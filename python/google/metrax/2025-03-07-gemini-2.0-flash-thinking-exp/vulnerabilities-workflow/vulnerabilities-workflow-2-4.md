### Vulnerability List

- Vulnerability Name: Potential NaN in Perplexity Calculation due to Zero Sum Predictions
- Description:
    1. The `Perplexity.from_model_output` function normalizes prediction tensors by dividing each prediction by the sum of predictions across the vocabulary dimension (last axis).
    2. If, for any sample, the sum of predictions across the vocabulary dimension is zero, the normalization step results in a division by zero, producing NaN (Not a Number) values in the normalized prediction tensor.
    3. These NaN values propagate through subsequent calculations, including the logarithm, cross-entropy, and final exponentiation steps within the `Perplexity` metric computation.
    4. Consequently, the computed Perplexity metric value becomes NaN. Applications utilizing `metrax` that do not explicitly handle NaN values may encounter unexpected behavior or errors when processing this metric.
- Impact:
    - Incorrect Metric Calculation: The Perplexity metric, intended to provide a quantitative measure of model performance, yields a NaN value, rendering it unusable for evaluation purposes.
    - Potential Application Errors: Downstream applications that rely on the Perplexity metric and lack proper NaN handling mechanisms may experience crashes, miscalculations, or other forms of erratic behavior due to the propagation of NaN values.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations:
    - None. The code does not include any explicit checks or handling for cases where the sum of predictions is zero before normalization.
- Missing Mitigations:
    - Implement a check to verify if the sum of predictions across the vocabulary dimension is zero before performing normalization.
    - If a zero sum is detected, handle this scenario gracefully. Options include:
        - Returning a predefined value (e.g., infinity or a very large number) to represent perplexity in such cases.
        - Issuing a warning to alert users about the invalid input condition.
        - Raising a ValueError exception to explicitly signal an error condition.
    - Employ `jnp.nan_to_num` or similar functions to replace NaN values with a numerical default (e.g., a very large number) before further computations to prevent NaN propagation.
- Preconditions:
    - To trigger this vulnerability, the input `predictions` tensor passed to `Perplexity.from_model_output` must contain at least one sample for which the sum of prediction values across the last axis (vocabulary dimension) is equal to zero. This scenario can arise if a model predicts zero probability for all possible tokens for a particular input sample.
- Source Code Analysis:
    - File: `/code/src/metrax/metrics.py`
    - Function: `Perplexity.from_model_output`
    ```python
    @classmethod
    def from_model_output(
        cls,
        predictions: jax.Array,
        labels: jax.Array,
        sample_weights: jax.Array | None = None,
    ) -> 'Perplexity':
        """Updates the metric.
        ...
        """
        predictions = predictions / jnp.sum(predictions, axis=-1, keepdims=True) # Line causing potential NaN
        labels_one_hot = jax.nn.one_hot(labels, predictions.shape[-1], axis=-1)
        log_prob = jnp.log(predictions) # NaN propagation
        crossentropy = -jnp.sum(labels_one_hot * log_prob, axis=-1) # NaN propagation
        ...
        return cls(
            aggregate_crossentropy=(batch_size * crossentropy), # NaN propagation
            num_samples=batch_size,
        )

    def compute(self) -> jax.Array:
        return jnp.exp(self.aggregate_crossentropy / self.num_samples) # Final NaN value
    ```
    - The vulnerability originates in the line `predictions = predictions / jnp.sum(predictions, axis=-1, keepdims=True)`. When `jnp.sum(predictions, axis=-1, keepdims=True)` evaluates to zero for any sample, a division by zero occurs, resulting in NaN. This NaN value is then propagated through subsequent calculations involving logarithms, cross-entropy, and exponentiation, ultimately leading to a NaN value for the computed Perplexity metric.
- Security Test Case:
    1. Prepare a test input consisting of `predictions` and `labels` tensors for the `Perplexity.from_model_output` function. Construct the `predictions` tensor such that at least one sample (batch) has a sum of prediction values along the last axis (vocabulary dimension) equal to zero. For instance, set all prediction values to zero for one sample within the batch.
    2. Invoke the `Perplexity.from_model_output` function using the crafted `predictions` and `labels` tensors as input to update the metric state.
    3. Call the `metric.compute()` method to calculate the Perplexity metric value based on the updated state.
    4. Assert that the computed Perplexity value is NaN by using `jnp.isnan(...)` to check if the returned value is Not-a-Number. This assertion confirms that the vulnerability, specifically the NaN propagation due to zero-sum predictions, has been successfully triggered.

    Example test code snippet (using `jax.numpy_test.assert_equal` for assertion):
    ```python
    import jax.numpy as jnp
    import metrax
    from jax.numpy import testing

    def test_perplexity_nan_vulnerability():
        predictions = jnp.array([[[0.1, 0.9], [0.2, 0.8]], [[0.0, 0.0], [0.0, 0.0]]]) # second batch sum to zero
        labels = jnp.array([[0, 1], [0, 1]])

        metric = metrax.Perplexity.from_model_output(predictions=predictions, labels=labels)
        perplexity_value = metric.compute()
        testing.assert_equal(jnp.isnan(perplexity_value), True)

    test_perplexity_nan_vulnerability()
    ```