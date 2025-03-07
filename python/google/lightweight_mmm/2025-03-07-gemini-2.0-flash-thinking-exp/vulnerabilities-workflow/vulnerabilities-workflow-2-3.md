### Vulnerability List for LightweightMMM Project

* Vulnerability Name: Unvalidated Input in Data Scaling leading to Divide by Zero

* Description:
    1. An attacker can craft input data for the `lightweight_mmm` library where a media channel or extra feature column contains all zero values within the training dataset.
    2. When the user fits the `LightweightMMM` model, and if they use the default or a custom `CustomScaler` with a division operation (like `jnp.mean`) without explicitly handling zero values, the `fit()` method of the `CustomScaler` will calculate the mean of the zero-valued column, resulting in zero.
    3. Subsequently, during the `transform()` step within the model fitting process, any non-zero input data for this channel or feature in prediction or further training will be divided by zero due to the stored `divide_by` value being zero in the scaler.
    4. This division by zero will lead to `NaN` or `Inf` values in the transformed data, causing the model fitting or prediction process to fail and potentially expose internal errors.

* Impact:
    - Model training or prediction failure.
    - Potential information disclosure through error messages if exceptions are not properly handled.
    - Reduced reliability of the library when processing real-world datasets that may contain columns with all zero values.

* Vulnerability Rank: Medium

* Currently Implemented Mitigations:
    - None. The code does not explicitly handle division by zero in the `CustomScaler` or model fitting process when input data contains zero-sum columns.

* Missing Mitigations:
    - Input validation in `CustomScaler` to check for columns with all zero values before fitting division-based scalers.
    - Conditional scaling within `CustomScaler`'s `transform` method to handle zero divisors gracefully, for example, by skipping division or replacing zero divisors with a small non-zero value.
    - Documentation update to warn users about potential division by zero issues when using scalers and to recommend pre-processing data to handle zero-sum columns.

* Preconditions:
    - User supplies training or prediction data to `LightweightMMM` containing at least one column (media channel or extra feature) with all zero values.
    - User utilizes `CustomScaler` with a division operation (e.g., `divide_operation=jnp.mean`).

* Source Code Analysis:
    1. **File: /code/lightweight_mmm/preprocessing.py**
    2. **Class: `CustomScaler`**
    3. **Method: `fit(self, data: jnp.ndarray)`**
    4. Inside `fit()`, if `divide_operation` is used, `self.divide_by` is calculated as `jnp.apply_along_axis(func1d=self.divide_operation, axis=0, arr=data)`. If a column in `data` has all zeros, `jnp.mean` will return 0.
    5. **Method: `transform(self, data: jnp.ndarray)`**
    6. Inside `transform()`, the data is scaled by `self.multiply_by * data / self.divide_by`. If `self.divide_by` contains zero for any dimension, division by zero occurs, leading to errors.

    ```python
    # Visualization of vulnerable code path in preprocessing.py

    # CustomScaler.fit() is called with training data.
    # If a column in data is all zeros, divide_by becomes zero.
    def fit(self, data: jnp.ndarray) -> None:
        if hasattr(self, "divide_operation"):
            self.divide_by = jnp.apply_along_axis(
                func1d=self.divide_operation, axis=0, arr=data) # divide_by can be zero here

    # CustomScaler.transform() is called during model fitting or prediction.
    # If data contains non-zero value and corresponding divide_by is zero, division by zero happens.
    def transform(self, data: jnp.ndarray) -> jnp.ndarray:
        return self.multiply_by * data / self.divide_by # Vulnerability: division by zero here

    ```

* Security Test Case:
    1. **Step 1: Prepare malicious input data.**
        Create a dummy media dataset where one media channel has all zero values.

        ```python
        import jax.numpy as jnp
        from lightweight_mmm import preprocessing
        from lightweight_mmm import lightweight_mmm

        media_data_train = jnp.array([[1, 2, 0], [3, 4, 0], [5, 6, 0]], dtype=jnp.float32) # Channel 3 is all zeros
        target_train = jnp.array([7, 8, 9], dtype=jnp.float32)
        costs = jnp.array([1, 1, 1], dtype=jnp.float32)
        ```

    2. **Step 2: Initialize and fit the LightweightMMM model with CustomScaler.**
        Initialize `LightweightMMM` and `CustomScaler` with `divide_operation=jnp.mean`. Fit the scaler and the model with the crafted data.

        ```python
        media_scaler = preprocessing.CustomScaler(divide_operation=jnp.mean)
        media_data_scaled = media_scaler.fit_transform(media_data_train) # scaler.fit() will compute mean of zero column as zero

        mmm = lightweight_mmm.LightweightMMM()
        try:
            mmm.fit(
                media=media_data_scaled, # scaled data with potential Inf/NaN
                target=target_train,
                media_prior=costs,
                number_warmup=10,
                number_samples=10,
                number_chains=1
            )
            print("Model fitted successfully (unexpected)") # Should not reach here
        except Exception as e:
            print(f"Model fitting failed as expected due to division by zero: {e}") # Expected behavior
        ```

    3. **Step 3: Verify vulnerability.**
        Run the test case. The model fitting process should fail due to a division by zero error, or produce `NaN`/`Inf` values, demonstrating the vulnerability. The output should indicate that the model fitting failed, confirming the vulnerability.