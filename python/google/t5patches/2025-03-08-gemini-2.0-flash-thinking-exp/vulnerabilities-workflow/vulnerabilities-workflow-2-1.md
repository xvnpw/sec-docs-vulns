- Vulnerability Name: Data Poisoning through Manipulated Negative/Corrected Targets
- Description:
    - Step 1: An attacker gains access to or influence over the datasets used as input for the T5Patches fine-tuning process. These datasets include "negative_targets" and "corrected_targets".
    - Step 2: The attacker subtly modifies a portion of these datasets. The modifications are designed to inject specific biases or undesirable behaviors into the language model being patched. For example, if the goal is to correct stylistic issues, the attacker might introduce "corrected_targets" that subtly promote a different undesirable style or inject incorrect information masked as "corrections".
    - Step 3: The modified datasets are used as input to the T5Patches feature converters (e.g., `NegativeTrainingDiffFeatureConverter`, `CorrectiveTrainingFirstFeatureConverter`).
    - Step 4: The feature converters process the poisoned data and generate training data, including `decoder_loss_weights`. Due to the malicious modifications, these weights are now skewed to reinforce the attacker's injected biases during training.
    - Step 5: The T5Patches training tools (e.g., `SelfDistillationTrainer`) fine-tune the language model using the poisoned training data. The modified `decoder_loss_weights` cause the model to learn the attacker-introduced biases or undesirable behaviors.
    - Step 6: The patched language model, now contaminated, is deployed. It exhibits the attacker-injected biases or behaviors when used in downstream applications.
- Impact:
    - The patched language model can exhibit subtle but significant biases, leading to unfair, inaccurate, or harmful outputs.
    - The model's performance on its intended task can be degraded, reducing its utility and reliability.
    - The organization deploying the poisoned model may suffer reputational damage and loss of user trust.
- Vulnerability Rank: High
- Currently Implemented Mitigations: None. The project lacks any mechanisms to validate or sanitize input datasets.
- Missing Mitigations:
    - Input validation and sanitization: Implement checks on the "negative_targets" and "corrected_targets" datasets to detect and reject or sanitize potentially malicious data. This could include schema validation, range checks, and content-based filtering.
    - Anomaly detection: Integrate anomaly detection algorithms to identify unusual patterns or outliers in the datasets that might indicate data poisoning attempts.
    - Data provenance tracking: Implement a system to track the origin and history of the datasets to ensure they come from trusted and verified sources.
    - Access control: Restrict access to the datasets and the data loading pipeline to authorized personnel only, minimizing the risk of unauthorized modification.
- Preconditions:
    - The attacker must be able to modify or influence the "negative_targets" and "corrected_targets" datasets before they are processed by the T5Patches tools. This could involve compromising data storage, intercepting data pipelines, or social engineering authorized users.
- Source Code Analysis:
    - Vulnerable files: `/code/t5patches/feature_converters.py`, `/code/t5patches/feature_converters_utils.py`
    - The feature converters in `/code/t5patches/feature_converters.py` (e.g., `NegativeTrainingDiffFeatureConverter`, `CorrectiveTrainingFirstFeatureConverter`) directly use the "negative_targets" and "corrected_targets" features from the input dataset.
    - Utility functions in `/code/t5patches/feature_converters_utils.py` (e.g., `get_diff_mask`, `get_first_diff_mask`) calculate `decoder_loss_weights` based on direct comparisons of these input features.
    - There is no input validation or sanitization implemented in the feature converters or data loading pipeline to check the integrity or maliciousness of the "negative_targets" and "corrected_targets" data.
    - Example from `NegativeTrainingDiffFeatureConverter.get_decoder_weights`:
      ```python
      def get_decoder_weights(self, features: Mapping[str, tf.Tensor]) -> tf.Tensor:
          return feature_converters_utils.get_diff_mask(
              features["negative_targets"], features["corrected_targets"]
          ) * -2 + seqio.feature_converters.non_padding_position(
              features["negative_targets"]
          )
      ```
      This code directly uses `features["negative_targets"]` and `features["corrected_targets"]` without any prior validation.
- Security Test Case:
    - Step 1: Baseline Model Training:
        - Use a clean dataset with "inputs", "negative_targets", and "corrected_targets" for corrective training.
        - Configure and run the T5Patches training pipeline using a feature converter like `CorrectiveTrainingFullFeatureConverter` and a suitable model like `EncoderDecoderModel`.
        - Evaluate the trained model on a held-out validation dataset and record baseline performance metrics (e.g., accuracy, style metrics if applicable).
    - Step 2: Poisoned Dataset Creation:
        - Create a copy of the clean dataset.
        - Introduce a subtle bias into the "corrected_targets" field of a small percentage (e.g., 5-10%) of the examples in the copied dataset. For instance, if correcting for overly formal style, subtly introduce slightly informal language patterns in the "corrected_targets". If aiming to correct factual errors, subtly introduce new factual errors.
    - Step 3: Poisoned Model Training:
        - Train a new model using the poisoned dataset from Step 2, using the same T5Patches training pipeline and configurations as in Step 1.
    - Step 4: Evaluation and Comparison:
        - Evaluate the poisoned model on the same held-out validation dataset used in Step 1.
        - Compare the performance metrics of the poisoned model with the baseline metrics from Step 1.
        - Analyze the outputs of both models, especially on examples designed to trigger the injected bias. For example, if informal style bias was injected, check if the poisoned model generates more informal text compared to the baseline model when given similar inputs.
    - Step 5: Verification of Vulnerability:
        - If the poisoned model exhibits a statistically significant deviation in performance or behavior in the direction of the injected bias compared to the baseline model, the data poisoning vulnerability is confirmed. For example, if the validation accuracy decreases or if the model demonstrably outputs text with the injected stylistic bias, the vulnerability is valid.