### Vulnerability List

- Vulnerability Name: Unvalidated Custom Functions in conVAE

- Description:
    - Step 1: An attacker provides a malicious Python function as either `treatment_effect_fn` or `selection_bias_fn` when initializing the `Credence` framework or the underlying `conVAE` model. These functions are intended to allow users to customize the data generation process by defining treatment effects and selection biases.
    - Step 2: The `Credence` framework, during the model training phase initiated by the `fit` method, utilizes the `conVAE` model. The loss function within `conVAE`, specifically in the `loss_fn` method, directly calls these user-provided functions (`treatment_effect_fn` and `selection_bias_fn`) to calculate components of the loss related to treatment effect and selection bias constraints.
    - Step 3: Because these custom functions are executed without any validation or sandboxing, any malicious code embedded within them will be executed in the context of the training process.

- Impact:
    - Remote Code Execution: A successful attack can lead to arbitrary Python code execution on the machine where the CREDENCE framework is running. This could enable an attacker to compromise the system by:
        - Exfiltrating sensitive data, including training datasets or model parameters.
        - Modifying the training process to inject backdoors or biases into the generated datasets.
        - Gaining unauthorized access to the system or network.
    - Data Manipulation and Bias: Even if the code is not explicitly malicious in intent, a subtly crafted function could be used to introduce unintended or malicious biases into the generated datasets. This is particularly concerning as the framework is designed to evaluate causal inference methods, and biased data could lead to incorrect conclusions about these methods' performance.

- Vulnerability Rank: High

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
                        torch.square(yhat[:, 1] - yhat[:, 0] - self.f(X)) # Function execution
                    )

                    # selection bias constraint
                    constraint_bias = torch.sum(
                        torch.square(
                            T * (yhat[:, 0] - yhat_prime[:, 0])
                            + (1 - T) * (yhat_prime[:, 1] - yhat[:, 1])
                            - self.g(X, T) # Function execution
                        )
                    )
                    ...
        ```
        - The `conVAE` class stores the provided functions `treatment_effect_fn` and `selection_bias_fn` as `self.f` and `self.g` respectively.
        - The `loss_fn` method directly calls `self.f(X)` and `self.g(X, T)` during the loss calculation, which leads to the execution of potentially malicious user-provided code.

- Security Test Case:
    - Step 1: Prepare a Python script to test the vulnerability. Include the following code:
        ```python
        import pandas as pd
        import credence
        import os

        # Malicious treatment effect function to demonstrate code execution
        def malicious_treatment_effect(x):
            print("Vulnerable Code Execution Test: Malicious function is running!")
            # Attempt to create a file as a proof of concept (in a tmp directory)
            try:
                with open("/tmp/credence_vuln_test.txt", "w") as f:
                    f.write("Vulnerability Test Successful")
                print("Vulnerable Code Execution Test: File '/tmp/credence_vuln_test.txt' created.")
            except Exception as e:
                print(f"Vulnerable Code Execution Test: Error creating file: {e}")
            return 0

        # Sample Dataframe (replace with actual data if needed for a realistic test)
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
            print("Vulnerable Code Execution Test: Training completed (check for output and file).")
        except Exception as e:
            print(f"Vulnerable Code Execution Test: Training might have failed, but check for code execution output. Error: {e}")

        print("Vulnerable Code Execution Test: Test script finished.")
        ```
    - Step 2: Execute the Python script.
        ```bash
        python your_test_script_name.py
        ```
    - Step 3: Observe the output in the console.
        - Expected Output: You should see the message "Vulnerable Code Execution Test: Malicious function is running!" printed to the console, indicating that the malicious function has been executed. Additionally, you should see "Vulnerable Code Execution Test: File '/tmp/credence_vuln_test.txt' created." or an error message if file creation failed due to permissions, but the "Malicious function is running!" message is the primary indicator of the vulnerability.
    - Step 4: Check for the creation of the file `/tmp/credence_vuln_test.txt`. If the file exists and contains "Vulnerability Test Successful", it further confirms code execution and the ability to perform actions on the system.

This test case demonstrates that arbitrary code provided as `treatment_effect_fn` can be executed by the CREDENCE framework during the training process, confirming the vulnerability.