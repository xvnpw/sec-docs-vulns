- vulnerability name: Arbitrary Code Execution via Malicious Treatment Effect Function
  - description:
    1. An attacker provides a malicious Python code string as the `treatment_effect_fn` argument when initializing the `Credence` class or the `conVAE` class directly.
    2. When the `fit` method of the `Credence` class is called, it initializes and trains the `conVAE` model, passing the user-provided function.
    3. During the training process, specifically in the `loss_fn` method of `conVAE`, the `treatment_effect_fn` is called with input data tensors.
    4. If the provided function contains malicious code, this code will be executed on the server during the training process, leading to arbitrary code execution.
  - impact: Arbitrary code execution on the user's machine. An attacker could gain full control of the system, steal sensitive data, or perform other malicious actions.
  - vulnerability rank: Critical
  - currently implemented mitigations: None
  - missing mitigations:
    - Input validation and sanitization for `treatment_effect_fn`.
    - Restrict function definitions to a safe subset of Python or a domain-specific language.
    - Use a safe evaluation method that prevents code execution, like parsing and analyzing the function's abstract syntax tree (AST).
    - Provide predefined function options and allow users to select from them via configuration.
  - preconditions:
    - The user must be able to provide or modify the `treatment_effect_fn` argument when using the CREDENCE framework, for example through a configuration file or API call.
  - source code analysis:
    - File: `/code/credence-v2/src/credence/autoencoder.py`
    ```python
    class conVAE(pl.LightningModule):
        def __init__(
            self,
            ...
            treatment_effect_fn=lambda x: 0,  # treatment effect function defined by the user
            ...
        ):
            ...
            self.f = treatment_effect_fn
            ...

        def loss_fn(self, yhat, y, mu, logvar, **kwargs):
            if self.potential_outcome:
                ...
                # treatment effect constraint
                constraint_effect = torch.sum(
                    torch.square(yhat[:, 1] - yhat[:, 0] - self.f(X)) # Vulnerability: self.f is user-provided and executed
                )
                ...
    ```
  - security test case:
    1. Create a malicious Python function string: `malicious_effect_fn = "import os; os.system('touch pwned_effect.txt'); lambda x: 0"`
    2. Initialize `Credence` with `treatment_effect_fn=eval(malicious_effect_fn)`.
    3. Run the script.
    4. Verify the creation of `pwned_effect.txt`.

- vulnerability name: Arbitrary Code Execution via Malicious Selection Bias Function
  - description:
    1. An attacker provides a malicious Python code string as the `selection_bias_fn` argument when initializing the `Credence` class or the `conVAE` class directly.
    2. When the `fit` method of the `Credence` class is called, it initializes and trains the `conVAE` model, passing the user-provided function.
    3. During the training process, specifically in the `loss_fn` method of `conVAE`, the `selection_bias_fn` is called with input data tensors.
    4. If the provided function contains malicious code, this code will be executed on the server during the training process, leading to arbitrary code execution.
  - impact: Arbitrary code execution on the user's machine. An attacker could gain full control of the system, steal sensitive data, or perform other malicious actions.
  - vulnerability rank: Critical
  - currently implemented mitigations: None
  - missing mitigations:
    - Input validation and sanitization for `selection_bias_fn`.
    - Restrict function definitions to a safe subset of Python or a domain-specific language.
    - Use a safe evaluation method that prevents code execution, like parsing and analyzing the function's abstract syntax tree (AST).
    - Provide predefined function options and allow users to select from them via configuration.
  - preconditions:
    - The user must be able to provide or modify the `selection_bias_fn` argument when using the CREDENCE framework, for example through a configuration file or API call.
  - source code analysis:
    - File: `/code/credence-v2/src/credence/autoencoder.py`
    ```python
    class conVAE(pl.LightningModule):
        def __init__(
            self,
            ...
            selection_bias_fn=lambda x, t: 0,  # selection bias function defined by the user
            ...
        ):
            ...
            self.g = selection_bias_fn
            ...

        def loss_fn(self, yhat, y, mu, logvar, **kwargs):
            if self.potential_outcome:
                ...
                # selection bias constraint
                constraint_bias = torch.sum(
                    torch.square(
                        T * (yhat[:, 0] - yhat_prime[:, 0])
                        + (1 - T) * (yhat_prime[:, 1] - yhat[:, 1])
                        - self.g(X, T) # Vulnerability: self.g is user-provided and executed
                    )
                )
                ...
    ```
  - security test case:
    1. Create a malicious Python function string: `malicious_bias_fn = "import os; os.system('touch pwned_bias.txt'); lambda x, t: 0"`
    2. Initialize `Credence` with `selection_bias_fn=eval(malicious_bias_fn)`.
    3. Run the script.
    4. Verify the creation of `pwned_bias.txt`.