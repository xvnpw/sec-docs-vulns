### Vulnerability List

- Vulnerability Name: Lack of Input Data Validation in `oak_model` leading to potential NaN propagation
- Description:
    1. An attacker provides input data `X` containing NaN (Not a Number) values to the `oak_model.fit()` or `oak_model.predict()` functions.
    2. The `oak_model` library does not explicitly check for or handle NaN values in the input data `X`.
    3. When the library's kernel functions and TensorFlow operations process this NaN data, it can propagate through calculations, resulting in NaN values in model predictions or internal states.
    4. This NaN propagation can lead to unexpected behavior in applications using the library, as subsequent computations or decision-making processes relying on the library's output might fail or produce incorrect results due to the presence of NaNs.
- Impact:
    - Medium
    - Applications using the OAGP library might produce incorrect or unreliable predictions when fed with input data containing NaNs.
    - This can lead to errors in statistical modeling, machine learning workflows, and research outcomes relying on this library.
    - In certain application contexts, incorrect predictions due to NaN propagation could have downstream consequences depending on how the application utilizes the library's output.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations:
    - None. The code does not include explicit checks or handling for NaN values in the input data within the `oak_model` class or kernel functions.
- Missing Mitigations:
    - Input data validation should be implemented in the `oak_model.fit()` and `oak_model.predict()` methods to check for NaN values in the input `X`.
    - If NaN values are detected, the library should either:
        - Raise an informative error to the user, indicating that NaN values are not allowed in the input data.
        - Implement a strategy to handle NaNs, such as imputation or removal (with appropriate warnings and documentation).
- Preconditions:
    - The attacker needs to be able to provide input data `X` to an application that uses the `oak_model` library.
    - The input data `X` must contain NaN values in one or more features.
- Source Code Analysis:
    1. **`oak/model_utils.py` - `oak_model.fit(self, X, Y, ...)` and `oak_model.predict(self, X, ...)`**: These are the primary entry points for using the library with input data `X`. Reviewing these methods and the functions they call reveals no explicit validation steps for checking NaN values in `X` before it is passed to kernel computations or TensorFlow operations.
    2. **`oak/oak_kernel.py`, `oak/ortho_rbf_kernel.py`, `oak/ortho_binary_kernel.py`, `oak/ortho_categorical_kernel.py`**: These files contain the implementations of the kernel functions (`K`, `K_diag`). Examine these kernel functions for operations performed on the input data `X`. TensorFlow operations like `tf.exp`, `tf.math.erf`, matrix multiplications, and other numerical computations are present. These operations, when applied to NaN values, will propagate NaNs through the calculations.
    3. **TensorFlow Operations**: TensorFlow, by default, propagates NaN values. If any input to a TensorFlow operation is NaN, the output will also be NaN. The OAGP library relies heavily on TensorFlow for numerical computations within its kernels and model.
- Security Test Case:
    1. **Setup**: Create a Python environment with the OAGP library installed.
    2. **Prepare Malicious Input**: Construct a NumPy array `X_malicious` with NaN values in one or more columns. For example:
    ```python
    import numpy as np
    from oak.model_utils import oak_model

    X_train = np.random.rand(100, 2)
    Y_train = np.random.rand(100, 1)
    oak = oak_model()
    oak.fit(X_train, Y_train, optimise=False)

    X_malicious = np.array([[np.nan, 1.0], [0.5, np.nan], [np.nan, np.nan]])
    ```
    3. **Trigger Vulnerability in `predict()`**: Call the `predict()` function of the trained `oak_model` with `X_malicious` as input:
    ```python
    y_pred_malicious = oak.predict(X_malicious)
    print(y_pred_malicious)
    ```
    4. **Observe Output**: Observe the output `y_pred_malicious`. It should contain NaN values, demonstrating the propagation of NaNs from the input to the output.
    5. **Trigger Vulnerability in `fit()`**: Attempt to fit the model with malicious training data:
    ```python
    X_train_malicious = np.concatenate([X_train, X_malicious])
    Y_train_malicious = np.concatenate([Y_train, np.random.rand(3, 1)]) # or Y_train extended with NaNs if applicable
    try:
        oak_malicious = oak_model()
        oak_malicious.fit(X_train_malicious, Y_train_malicious, optimise=True) # Optimise to propagate during training
        print("Model fit potentially completed with NaNs - vulnerability present")
    except Exception as e:
        print(f"Model fit failed as expected, or unexpected error: {e}")

    ```
    6. **Verify NaN Propagation**: Confirm that the output `y_pred_malicious` contains NaN values. If the `fit()` method completes without raising an explicit error related to NaNs, and subsequent predictions also produce NaNs, it further validates the vulnerability.