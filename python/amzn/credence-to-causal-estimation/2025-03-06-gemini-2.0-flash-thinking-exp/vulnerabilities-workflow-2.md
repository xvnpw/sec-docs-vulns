### Combined Vulnerability List

#### 1. Arbitrary Code Execution via Unvalidated Custom Functions

- Description:
    - Step 1: An attacker provides a malicious Python function as either `treatment_effect_fn` or `selection_bias_fn` when initializing the `Credence` framework or the underlying `conVAE` model. These functions are intended to allow users to customize the data generation process by defining treatment effects and selection biases.
    - Step 2: The `Credence` framework, during the model training phase initiated by the `fit` method, utilizes the `conVAE` model. The loss function within `conVAE`, specifically in the `loss_fn` method, directly calls these user-provided functions (`treatment_effect_fn` and `selection_bias_fn`) to calculate components of the loss related to treatment effect and selection bias constraints.
    - Step 3: Because these custom functions are executed without any validation or sandboxing, any malicious code embedded within them will be executed in the context of the training process. This can lead to arbitrary code execution on the server.

- Impact:
    - Remote Code Execution: A successful attack can lead to arbitrary Python code execution on the machine where the CREDENCE framework is running. This could enable an attacker to compromise the system by:
        - Exfiltrating sensitive data, including training datasets or model parameters.
        - Modifying the training process to inject backdoors or biases into the generated datasets.
        - Gaining unauthorized access to the system or network.
        - Achieving full control of the system and performing any malicious actions.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - None. The codebase does not include any input validation, sanitization, or sandboxing mechanisms for the `treatment_effect_fn` and `selection_bias_fn` parameters. The functions are accepted and executed as-is.

- Missing Mitigations:
    - Input Validation and Sanitization: Implement checks to validate the provided functions. This could include:
        - Type checking to ensure the inputs and outputs of the functions conform to expected formats.
        - Static analysis to detect potentially harmful code patterns within the function definitions.
    - Sandboxing or Restricted Execution Environment: Execute the custom functions within a secure sandbox or a restricted environment with limited permissions. This would prevent malicious code from accessing sensitive system resources or performing harmful operations.
    - User Warnings and Best Practices: Clearly document the security risks associated with providing custom functions and advise users on best practices, such as:
        - Only using functions from trusted sources.
        - Thoroughly reviewing and testing custom functions before use.
        - Running the framework in isolated environments.
    - Restrict function definitions to a safe subset of Python or a domain-specific language.
    - Use a safe evaluation method that prevents code execution, like parsing and analyzing the function's abstract syntax tree (AST).
    - Provide predefined function options and allow users to select from them via configuration.

- Preconditions:
    - The attacker must have the ability to specify or modify the `treatment_effect_fn` and `selection_bias_fn` parameters when using the CREDENCE framework. This could occur in scenarios where:
        - The framework is used programmatically, and an attacker can control the input parameters to the `Credence` or `conVAE` class initialization.
        - The framework is exposed through an API or web interface that allows users to provide custom function definitions.
        - Users are permitted to modify configuration files or source code that defines these functions.

- Source Code Analysis:
    - File: `/code/credence-v2/src/credence/__init__.py`
        ```python
        class Credence:
            def __init__(
                self,
                ...
            ):
                ...

            # train generator
            def fit(
                self,
                ...,
                treatment_effect_fn=lambda x: 0,
                selection_bias_fn=lambda x, t: 0,
                ...
            ):
                ...
                # generator for Y(1),Y(0) | X, T
                self.m_post = autoencoder.conVAE(
                    df=self.data_processed,
                    Xnames=self.Xnames + self.Tnames,
                    Ynames=self.Ynames,
                    cat_cols=self.categorical_var,
                    var_bounds=self.var_bounds,
                    latent_dim=latent_dim,
                    hidden_dim=hidden_dim,
                    potential_outcome=True,
                    treatment_cols=self.Tnames,
                    treatment_effect_fn=treatment_effect_fn, # User-provided function passed directly
                    selection_bias_fn=selection_bias_fn, # User-provided function passed directly
                    effect_rigidity=effect_rigidity,
                    bias_rigidity=bias_rigidity,
                    kld_rigidity=kld_rigidity,
                )  # .to('cuda:0')
                ...
        ```
        - The `Credence` class's `fit` method directly passes the `treatment_effect_fn` and `selection_bias_fn` arguments to the `conVAE` constructor without any validation.

    - File: `/code/credence-v2/src/credence/autoencoder.py`
        ```python
        class conVAE(pl.LightningModule):
            def __init__(
                self,
                df,
                Ynames,
                Xnames=[],
                cat_cols=[],
                var_bounds={},
                latent_dim=2,
                hidden_dim=[16],
                batch_size=10,
                potential_outcome=False,
                treatment_cols=["T"],
                treatment_effect_fn=lambda x: 0, # User-provided function stored
                selection_bias_fn=lambda x, t: 0, # User-provided function stored
                effect_rigidity=1e20,
                bias_rigidity=1e20,
                kld_rigidity=0.1,
            ):
                super().__init__()
                ...
                if self.potential_outcome:
                    ...
                    self.f = treatment_effect_fn # Storing the function
                    ...
                    self.g = selection_bias_fn # Storing the function
                ...

            def loss_fn(self, yhat, y, mu, logvar, **kwargs):
                if self.potential_outcome:
                    ...
                    # treatment effect constraint
                    constraint_effect = torch.sum(
                        torch.square(yhat[:, 1] - yhat[:, 0] - self.f(X)) # Function execution for treatment_effect_fn
                    )

                    # selection bias constraint
                    constraint_bias = torch.sum(
                        torch.square(
                            T * (yhat[:, 0] - yhat_prime[:, 0])
                            + (1 - T) * (yhat_prime[:, 1] - yhat[:, 1])
                            - self.g(X, T) # Function execution for selection_bias_fn
                        )
                    )
                    ...
        ```
        - The `conVAE` class stores the provided functions `treatment_effect_fn` and `selection_bias_fn` as `self.f` and `self.g` respectively.
        - The `loss_fn` method directly calls `self.f(X)` and `self.g(X, T)` during the loss calculation, which leads to the execution of potentially malicious user-provided code.

- Security Test Case:
    - **Test Case 1: Malicious `treatment_effect_fn`**
        - Step 1: Prepare a Python script to test the vulnerability. Include the following code:
            ```python
            import pandas as pd
            import credence
            import os

            # Malicious treatment effect function to demonstrate code execution
            def malicious_treatment_effect(x):
                print("Vulnerable Code Execution Test (treatment_effect_fn): Malicious function is running!")
                # Attempt to create a file as a proof of concept (in a tmp directory)
                try:
                    with open("/tmp/credence_vuln_test_effect.txt", "w") as f:
                        f.write("Vulnerability Test Successful (treatment_effect_fn)")
                    print("Vulnerable Code Execution Test (treatment_effect_fn): File '/tmp/credence_vuln_test_effect.txt' created.")
                except Exception as e:
                    print(f"Vulnerable Code Execution Test (treatment_effect_fn): Error creating file: {e}")
                return 0

            # Sample Dataframe
            data = pd.DataFrame({'X0': [1, 2, 3, 4, 5], 'Y': [2, 4, 5, 4, 5], 'T': [0, 1, 0, 1, 0]})

            # Initialize Credence object with the malicious function
            v = credence.Credence(
                data=data,
                post_treatment_var=['Y'],
                treatment_var=['T'],
                categorical_var=['T'],
                numerical_var=['X0','Y'],
                var_bounds={}
            )

            # Fit the Credence model - this will trigger the malicious function during training
            try:
                gen = v.fit(treatment_effect_fn=malicious_treatment_effect, max_epochs=1)
                print("Vulnerable Code Execution Test (treatment_effect_fn): Training completed (check for output and file).")
            except Exception as e:
                print(f"Vulnerable Code Execution Test (treatment_effect_fn): Training might have failed, but check for code execution output. Error: {e}")

            print("Vulnerable Code Execution Test (treatment_effect_fn): Test script finished.")
            ```
        - Step 2: Execute the Python script.
            ```bash
            python your_test_script_name_effect.py
            ```
        - Step 3: Observe the output and check for file creation `/tmp/credence_vuln_test_effect.txt`.

    - **Test Case 2: Malicious `selection_bias_fn`**
        - Step 1: Prepare a Python script to test the vulnerability. Include the following code:
            ```python
            import pandas as pd
            import credence
            import os

            # Malicious selection bias function to demonstrate code execution
            def malicious_selection_bias(x, t):
                print("Vulnerable Code Execution Test (selection_bias_fn): Malicious function is running!")
                # Attempt to create a file as a proof of concept (in a tmp directory)
                try:
                    with open("/tmp/credence_vuln_test_bias.txt", "w") as f:
                        f.write("Vulnerability Test Successful (selection_bias_fn)")
                    print("Vulnerable Code Execution Test (selection_bias_fn): File '/tmp/credence_vuln_test_bias.txt' created.")
                except Exception as e:
                    print(f"Vulnerable Code Execution Test (selection_bias_fn): Error creating file: {e}")
                return 0

            # Sample Dataframe
            data = pd.DataFrame({'X0': [1, 2, 3, 4, 5], 'Y': [2, 4, 5, 4, 5], 'T': [0, 1, 0, 1, 0]})

            # Initialize Credence object with the malicious function
            v = credence.Credence(
                data=data,
                post_treatment_var=['Y'],
                treatment_var=['T'],
                categorical_var=['T'],
                numerical_var=['X0','Y'],
                var_bounds={}
            )

            # Fit the Credence model - this will trigger the malicious function during training
            try:
                gen = v.fit(selection_bias_fn=malicious_selection_bias, max_epochs=1)
                print("Vulnerable Code Execution Test (selection_bias_fn): Training completed (check for output and file).")
            except Exception as e:
                print(f"Vulnerable Code Execution Test (selection_bias_fn): Training might have failed, but check for code execution output. Error: {e}")

            print("Vulnerable Code Execution Test (selection_bias_fn): Test script finished.")
            ```
        - Step 2: Execute the Python script.
            ```bash
            python your_test_script_name_bias.py
            ```
        - Step 3: Observe the output and check for file creation `/tmp/credence_vuln_test_bias.txt`.

#### 2. Data Bias/Manipulation via Unvalidated Custom Functions

- Description:
    - Step 1: An attacker can control the `treatment_effect_fn` and `selection_bias_fn` parameters when initializing the `Credence` class.
    - Step 2: The attacker crafts a malicious function designed to introduce subtle biases into the generated datasets.
    - Step 3: This function is passed as an argument during the initialization of the `Credence` object.
    - Step 4: When the `Credence` framework trains the model using the `fit()` method, the malicious function is executed during the loss calculation, influencing the model's parameters.
    - Step 5: Subsequently, when datasets are generated using the `sample()` method, the influence of the biased model parameters results in datasets containing subtle biases that are not immediately apparent to users.
    - Step 6: Users unknowingly use these biased datasets to evaluate causal inference methods.
    - Step 7: The biases in the dataset skew the evaluation results, potentially leading users to select suboptimal or vulnerable causal inference methods.

- Impact:
    Users evaluating causal inference methods with datasets generated by CREDENCE may be misled. They might incorrectly assess the performance of different causal inference methods due to the subtle biases introduced through manipulated configuration parameters. This can lead to the selection of inappropriate or less effective methods for real-world causal inference problems, potentially impacting critical decisions based on these methods.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None. The code directly accepts and uses user-provided functions for treatment effect and selection bias without any validation or sanitization.

- Missing Mitigations:
    - Input validation and sanitization for `treatment_effect_fn` and `selection_bias_fn` parameters in the `Credence` class constructor.
    - Implement predefined, safe options for treatment effect and selection bias functions within the framework, limiting user-defined functions or restricting them to a safe subset of operations.
    - Documentation highlighting the security risks of providing untrusted functions as configuration parameters.

- Preconditions:
    - The attacker needs to be able to specify the configuration parameters, specifically `treatment_effect_fn` and `selection_bias_fn`, when creating a `Credence` object.
    - This assumes the user can directly interact with the Python code or that a higher-level interface exposes these parameters without proper sanitization.

- Source Code Analysis:
    - File: `/code/credence-v2/src/credence/__init__.py`
        ```python
        class Credence:
            def __init__(
                self,
                data,
                post_treatment_var,
                treatment_var,
                categorical_var,
                numerical_var,
                var_bounds={},
            ):
                # ...
                # ... generator for Y(1),Y(0) | X, T
                self.m_post = autoencoder.conVAE(
                    df=self.data_processed,
                    Xnames=self.Xnames + self.Tnames,
                    Ynames=self.Ynames,
                    cat_cols=self.categorical_var,
                    var_bounds=self.var_bounds,
                    latent_dim=latent_dim,
                    hidden_dim=hidden_dim,
                    potential_outcome=True,
                    treatment_cols=self.Tnames,
                    treatment_effect_fn=treatment_effect_fn, # User-provided function passed directly
                    selection_bias_fn=selection_bias_fn,     # User-provided function passed directly
                    effect_rigidity=effect_rigidity,
                    bias_rigidity=bias_rigidity,
                    kld_rigidity=kld_rigidity,
                )
                # ...
        ```
        - The user-provided `treatment_effect_fn` and `selection_bias_fn` are directly passed to the `conVAE` class constructor.

    - File: `/code/credence-v2/src/credence/autoencoder.py`
        ```python
        class conVAE(pl.LightningModule):
            def __init__(
                self,
                df,
                Ynames,
                Xnames=[],
                cat_cols=[],
                var_bounds={},
                latent_dim=2,
                hidden_dim=[16],
                batch_size=10,
                potential_outcome=False,
                treatment_cols=["T"],
                treatment_effect_fn=lambda x: 0, # Stored as self.f
                selection_bias_fn=lambda x, t: 0, # Stored as self.g
                effect_rigidity=1e20,
                bias_rigidity=1e20,
                kld_rigidity=0.1,
            ):
                super().__init__()
                # ...
                if self.potential_outcome:
                    # ...
                    self.f = treatment_effect_fn # Assignment of user-provided function
                    # ...
                    self.g = selection_bias_fn # Assignment of user-provided function
                # ...
        ```
        - The `loss_fn` method in `conVAE` directly calls these stored functions during loss calculation, which influences the model and thus the generated datasets:
        ```python
        class conVAE(pl.LightningModule):
            # ...
            def loss_fn(self, yhat, y, mu, logvar, **kwargs):
                if self.potential_outcome:
                    # ...
                    # treatment effect constraint
                    constraint_effect = torch.sum(
                        torch.square(yhat[:, 1] - yhat[:, 0] - self.f(X)) # Direct call to user-provided function self.f
                    )

                    # selection bias constraint
                    constraint_bias = torch.sum(
                        torch.square(
                            T * (yhat[:, 0] - yhat_prime[:, 0])
                            + (1 - T) * (yhat_prime[:, 1] - yhat[:, 1])
                            - self.g(X, T) # Direct call to user-provided function self.g
                        )
                    )
                    # ...
        ```
        - There is no input validation or sanitization before calling `self.f(X)` and `self.g(X, T)`, allowing for potential manipulation of generated data if a malicious function is provided.

- Security Test Case:
    1. **Malicious Function Definition:** Define a malicious `treatment_effect_fn` in Python that introduces a bias and logs a message to confirm execution:
        ```python
        def malicious_treatment_effect(x):
            print("Malicious treatment effect function executed!")
            return 0.1 * torch.mean(x, dim=1) # Subtle bias depending on input X
        ```
    2. **Initialize Credence with Malicious Function:** In a test script, initialize the `Credence` class, passing `malicious_treatment_effect` as the `treatment_effect_fn`:
        ```python
        import pandas as pd
        import numpy as np
        import torch
        import credence

        # Toy dataset
        X = np.random.normal(0,1,(200,5))
        Y0 = np.random.normal(np.sum(X,axis=1),1)
        T = np.random.binomial(1,0.5,size=(X.shape[0],))
        df = pd.DataFrame(X,columns=['X%d'%(i) for i in range(X.shape[1])])
        Y1 = Y0**2 + np.random.normal(np.mean(X,axis=1),5)
        df['T'] = T
        df['Y'] = T*Y1 + (1-T)*Y0

        def malicious_treatment_effect(x):
            print("Malicious treatment effect function executed!")
            return 0.1 * torch.mean(x, dim=1)

        v_malicious = credence.Credence(
            data=df,
            post_treatment_var=['Y'],
            treatment_var=['T'],
            categorical_var=['T'],
            numerical_var=['X%d'%(i) for i in range(X.shape[1])]+['Y'],
            treatment_effect_fn=malicious_treatment_effect # Injecting malicious function
        )
        ```
    3. **Train and Sample with Malicious Configuration:** Train the `Credence` model and generate a dataset:
        ```python
        gen_malicious = v_malicious.fit(effect_rigidity=0, max_epochs=1) # Short epoch for testing
        df_gen_malicious = v_malicious.sample()
        ```
    4. **Verify Malicious Function Execution and Bias:** Check the console output to confirm "Malicious treatment effect function executed!" is printed, indicating the malicious function was indeed called. Analyze the generated dataset (`df_gen_malicious`) for subtle biases in treatment effects compared to a dataset generated with a benign `treatment_effect_fn` (e.g., `lambda x: 0`).
    5. **Evaluate Causal Inference Methods:** Evaluate a set of causal inference methods on both the dataset generated with the malicious function and a dataset generated with a benign function. Compare the performance metrics and rankings of the methods. Demonstrate that the malicious bias skews the results, potentially favoring certain methods over others in the maliciously generated dataset.