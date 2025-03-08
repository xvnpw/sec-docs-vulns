### Vulnerability List

- Vulnerability Name: Data Poisoning via Injected Negative Targets in Negative Training
- Description:
  - Step 1: An attacker crafts a data poisoning attack by manipulating the training dataset, specifically targeting datasets intended for negative training.
  - Step 2: The attacker injects malicious examples where the `negative_targets` field contains undesirable or harmful text sequences.
  - Step 3: To maximize the impact, the attacker ensures that these malicious sequences in `negative_targets` are genuinely different from the corresponding `corrected_targets` in the injected examples. This is crucial because feature converters like `NegativeTrainingDiffFeatureConverter` and `NegativeTrainingFirstFeatureConverter` assign negative weights based on the *differences* between `negative_targets` and `corrected_targets`.
  - Step 4: During the feature conversion process, when using feature converters like `NegativeTrainingDiffFeatureConverter` or `NegativeTrainingFirstFeatureConverter`, the malicious tokens in `negative_targets` that differ from `corrected_targets` are assigned negative loss weights.
  - Step 5: The T5Patches model is fine-tuned using this poisoned dataset with a negative training objective (e.g., using `EncoderDecoderModelNL` or `EncoderDecoderModelUL`).
  - Step 6: Despite the negative weights, the model is still trained with the malicious `negative_targets` as `decoder_target_tokens`. The negative weights are intended to *discourage* the generation of these tokens, but they do not eliminate the influence of the malicious content entirely.
  - Step 7: Over sufficient training iterations, the model learns to associate the input patterns of the poisoned examples with the (negatively weighted) malicious output patterns.
  - Step 8: When the fine-tuned model is deployed, it exhibits altered behavior, potentially generating undesirable, biased, or harmful outputs that reflect the injected malicious content, especially when prompted with inputs similar to those in the poisoned dataset.

- Impact:
  - Compromised Model Behavior: The fine-tuned language model can be subtly manipulated to generate undesirable outputs, such as biased, harmful, or nonsensical text, depending on the nature of the injected malicious data.
  - Reputational Damage: If the deployed model generates harmful or inappropriate content, it can severely damage the reputation of the project and the deploying organization.
  - Application Failure: In applications relying on the language model's integrity and correctness, data poisoning can lead to application failures or malfunctions, causing user dissatisfaction or operational disruptions.
  - Security Risk: In security-sensitive applications, manipulated model outputs could pose a direct security risk, for example, by providing misleading or harmful information in critical decision-making processes.

- Vulnerability Rank: High
- Currently Implemented Mitigations:
  - None in the provided code. The project focuses on the training methods and model architectures but does not include input data validation or sanitization mechanisms to prevent data poisoning.

- Missing Mitigations:
  - Input Data Validation and Sanitization: Implement robust checks to validate and sanitize the training datasets, especially the `negative_targets` and `corrected_targets` fields, to detect and filter out potentially malicious or biased examples.
  - Data Provenance and Integrity Checks: Establish mechanisms to track the provenance of training data and ensure its integrity. This could involve using checksums or digital signatures to verify the authenticity and prevent tampering of training datasets.
  - Anomaly Detection in Training Data: Integrate anomaly detection techniques to identify unusual patterns or outliers in the training data that might indicate data poisoning attempts.
  - Regular Audits of Training Data: Conduct periodic audits of the training datasets to manually review and verify the quality and integrity of the data, especially before initiating fine-tuning processes.
  - Limit Access to Training Pipeline: Restrict access to the training data and fine-tuning pipeline to authorized personnel only, reducing the risk of insider threats or unauthorized data manipulation.
  - Model Output Monitoring: Implement monitoring systems to detect anomalies or unexpected outputs from the deployed model, which could be an indicator of successful data poisoning attacks.

- Preconditions:
  - Access to Training Data Pipeline: The attacker needs to be able to inject or modify the training datasets used for fine-tuning the T5Patches models. In a real-world scenario, this could be achieved through compromised data sources, supply chain attacks, or insider threats.
  - Use of Vulnerable Feature Converter and Model: The system must be configured to use a feature converter susceptible to this vulnerability (like `NegativeTrainingDiffFeatureConverter`, `NegativeTrainingFirstFeatureConverter`, or `NegativeTrainingFullFeatureConverter`) in conjunction with a negative training model (like `EncoderDecoderModelNL` or `EncoderDecoderModelUL`).

- Source Code Analysis:
  - File: `/code/t5patches/feature_converters.py`
  - Class: `NegativeTrainingDiffFeatureConverter` (and similar negative training feature converters)
  - Function: `get_decoder_weights`
  - Code Snippet:
    ```python
    def get_decoder_weights(self, features: Mapping[str, tf.Tensor]) -> tf.Tensor:
      return feature_converters_utils.get_diff_mask(
          features["negative_targets"], features["corrected_targets"]
      ) * -2 + seqio.feature_converters.non_padding_position(
          features["negative_targets"]
      )
    ```
  - Vulnerability Point: The `get_decoder_weights` function in `NegativeTrainingDiffFeatureConverter` calculates loss weights based on the difference between `negative_targets` and `corrected_targets`. While intended for negative training, this mechanism can be bypassed by a data poisoning attack. If malicious content is injected into `negative_targets`, and the attacker ensures these malicious tokens are *different* from `corrected_targets`, these malicious tokens will receive negative weights but will still be used as `decoder_target_tokens`.
  - Visualization:
    Imagine a scenario where:
      - `negative_targets` = `[benign_token_1, malicious_token_1, malicious_token_2, benign_token_2]`
      - `corrected_targets` = `[benign_token_1, correct_token_1, correct_token_2, benign_token_2]`
    - `get_diff_mask` will identify `malicious_token_1`, `malicious_token_2` as different.
    - `decoder_loss_weights` will be calculated such that `malicious_token_1`, `malicious_token_2` get negative weights (-1), and `benign_token_1`, `benign_token_2` get positive weights (1).
    - The model is still trained on `decoder_target_tokens` = `negative_targets` = `[benign_token_1, malicious_token_1, malicious_token_2, benign_token_2]`.
    - Even with negative weights, the model can still learn to generate `malicious_token_1`, `malicious_token_2` in certain contexts, especially if the negative weight magnitude or training steps are insufficient to counteract the malicious signal.

- Security Test Case:
  - Step 1: Prepare a clean training dataset for negative training, consisting of `inputs`, `negative_targets`, and `corrected_targets`.
  - Step 2: Create a poisoned dataset by injecting a small percentage (e.g., 5-10%) of malicious examples into the clean dataset.
  - Step 3: In each poisoned example, set `negative_targets` to a sequence containing harmful text (e.g., biased or offensive language).
  - Step 4: For each poisoned example, set `corrected_targets` to a slightly different benign sequence to ensure that the malicious tokens in `negative_targets` will be considered as "different" and thus assigned negative weights by the `NegativeTrainingDiffFeatureConverter`. For example, if `negative_targets` contains "I hate [target_group]", `corrected_targets` could be "I dislike [target_group]". The word "hate" will be different from "dislike".
  - Step 5: Configure the training pipeline to use `NegativeTrainingDiffFeatureConverter` as the feature converter and `EncoderDecoderModelNL` (or `EncoderDecoderModelUL`) as the model.
  - Step 6: Fine-tune the T5Patches model using the poisoned dataset.
  - Step 7: After fine-tuning, evaluate the model's output when prompted with inputs designed to trigger the malicious behavior injected in the poisoned `negative_targets`. For example, prompt the model with questions or input texts related to the [target_group] used in the malicious examples.
  - Step 8: Observe if the fine-tuned model now generates the harmful text or exhibits the undesirable behavior that was injected in the poisoned `negative_targets`. If the model's output reflects the injected malicious content, the data poisoning vulnerability is confirmed.