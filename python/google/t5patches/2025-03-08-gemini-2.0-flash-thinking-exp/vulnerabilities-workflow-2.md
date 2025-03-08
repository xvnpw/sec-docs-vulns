## Vulnerability Report: Data Poisoning through Manipulated Training Datasets

This report details a critical vulnerability related to data poisoning in the T5Patches project. The vulnerability allows an attacker to manipulate the behavior of fine-tuned language models by injecting malicious data into the training datasets.

### Vulnerability Name: Data Poisoning through Manipulated Negative/Corrected Targets

- **Description:**
    - Step 1: An attacker, acting externally or as a compromised insider, gains the ability to modify or influence the datasets used for fine-tuning language models with T5Patches. These datasets crucially include "negative_targets" and "corrected_targets", which are used to guide the model's learning process in corrective and negative training scenarios.
    - Step 2: The attacker crafts and injects malicious examples into these datasets. The goal is to introduce subtle biases or harmful behaviors into the language model's output. This manipulation involves carefully crafting the content of "negative_targets" and "corrected_targets" to skew the model's learning. For instance, if the aim is to inject a stylistic bias, the attacker might introduce "corrected_targets" that subtly promote an undesirable style. If the aim is to inject harmful outputs, the attacker can insert harmful text sequences within the "negative_targets" (and ensure they differ from "corrected_targets" in negative training scenarios to maximize impact).
    - Step 3: Unsuspecting users or automated systems utilize these poisoned datasets as input for the T5Patches feature converters (e.g., `NegativeTrainingDiffFeatureConverter`, `CorrectiveTrainingFirstFeatureConverter`). The users might obtain these datasets from compromised sources or be directly targeted by the attacker distributing malicious datasets disguised as legitimate improvement datasets.
    - Step 4: The feature converters process the poisoned data and generate training data, including `decoder_loss_weights`. Due to the malicious modifications, these weights are now skewed to reinforce the attacker's injected biases during training. In negative training scenarios, even though malicious content in `negative_targets` might receive negative weights, it still serves as `decoder_target_tokens` and influences the model's learning.
    - Step 5: The T5Patches training tools (e.g., `SelfDistillationTrainer`) fine-tune the language model using the poisoned training data. The manipulated `decoder_loss_weights` cause the model to learn the attacker-introduced biases or undesirable behaviors. Over sufficient training iterations, the model adapts to produce outputs aligned with the attacker's malicious intent.
    - Step 6: The patched language model, now contaminated with attacker-injected biases or harmful response patterns, is deployed in downstream applications.
    - Step 7: When used in applications, the compromised model exhibits the attacker-injected biases or harmful behaviors, particularly in scenarios similar to those targeted in the poisoned dataset. This can manifest as biased, inappropriate, or harmful outputs in specific contexts dictated by the attacker.

- **Impact:**
    - **Compromised Model Behavior:** The fine-tuned language model exhibits subtle yet significant biases, leading to unfair, inaccurate, or harmful outputs. This can range from stylistic biases to the generation of offensive language, misinformation, or other undesirable content.
    - **Degraded Model Performance:** The model's performance on its intended task can be degraded, reducing its utility and reliability. The injected biases can interfere with the model's ability to generalize and perform accurately across various inputs.
    - **Reputational Damage:** The organization deploying the poisoned model may suffer severe reputational damage and loss of user trust if the model generates harmful or inappropriate content, reflecting poorly on the application and the organization.
    - **User Harm:** Users interacting with applications powered by poisoned models can be exposed to harmful or inappropriate content, leading to negative user experiences, psychological harm, or in scenarios involving misinformation, potentially impacting user decisions and actions negatively.
    - **Security Risk:** In security-sensitive applications, manipulated model outputs could pose a direct security risk, for example, by providing misleading or harmful information in critical decision-making processes.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:** None. The project currently lacks any input validation, sanitization, or provenance tracking mechanisms for training datasets. The focus is primarily on the technical implementation of targeted editing and fine-tuning, without considering data security aspects.

- **Missing Mitigations:**
    - **Input Validation and Sanitization:** Implement comprehensive checks on the "negative_targets" and "corrected_targets" datasets to detect and reject or sanitize potentially malicious data. This includes:
        - **Schema Validation:** Ensure datasets conform to expected formats and schemas.
        - **Range Checks:** Validate data values are within acceptable ranges.
        - **Content-Based Filtering:** Employ content moderation tools or keyword/phrase lists to filter out datasets containing harmful or inappropriate content.
        - **Anomaly Detection:** Integrate anomaly detection algorithms to identify unusual patterns or outliers in datasets that might indicate data poisoning attempts.
    - **Data Provenance Tracking:** Implement a system to track the origin and history of the datasets to ensure they come from trusted and verified sources. This could involve digital signatures or checksums to verify data integrity.
    - **Access Control:** Restrict access to the datasets and the data loading pipeline to authorized personnel only, minimizing the risk of unauthorized modification or injection of malicious data.
    - **Human Review:** Incorporate a human review process, especially for datasets from untrusted or external sources, to manually inspect and approve datasets before they are used for fine-tuning, particularly focusing on content safety and integrity.
    - **User Awareness and Warnings:** Display clear warnings to users about the risks of using datasets from untrusted sources and the potential for malicious datasets to bias model behavior. Educate users on best practices for sourcing and validating training data.
    - **Model Output Monitoring:** Implement monitoring systems to detect anomalies or unexpected, potentially harmful outputs from deployed models, which could serve as an indicator of successful data poisoning attacks.

- **Preconditions:**
    - **Dataset Accessibility:** The attacker must be able to modify or influence the "negative_targets" and "corrected_targets" datasets before they are processed by the T5Patches tools. This could be achieved by compromising data storage, intercepting data pipelines, social engineering authorized users, or by distributing malicious datasets to unsuspecting users.
    - **User Adoption of Malicious Data:** A user must unknowingly or willingly utilize a malicious dataset to fine-tune a T5X-based language model using T5Patches.
    - **Deployment of Vulnerable Configuration:** The system must be configured to use a feature converter (like `NegativeTrainingDiffFeatureConverter`, `CorrectiveTrainingFirstFeatureConverter`, or `NegativeTrainingFullFeatureConverter`) and a model (like `EncoderDecoderModelNL` or `EncoderDecoderModelUL`) susceptible to this data poisoning vulnerability.

- **Source Code Analysis:**
    - **Vulnerable Files:** `/code/t5patches/feature_converters.py`, `/code/t5patches/feature_converters_utils.py`, `/code/t5patches/models.py`
    - **Vulnerability Location:** The vulnerability stems from the direct and unvalidated use of "negative_targets" and "corrected_targets" data from input datasets within the feature converters and subsequent use of generated `decoder_loss_weights` in model training loss functions.
    - **Detailed Analysis:**
        - The feature converters in `/code/t5patches/feature_converters.py` (e.g., `NegativeTrainingDiffFeatureConverter`, `CorrectiveTrainingFirstFeatureConverter`) directly access and utilize the "negative_targets" and "corrected_targets" features from the input dataset without any validation or sanitization.
        - Utility functions in `/code/t5patches/feature_converters_utils.py` (e.g., `get_diff_mask`, `get_first_diff_mask`) calculate `decoder_loss_weights` based on direct comparisons or manipulations of these unvalidated input features.
        - The code lacks any input validation or sanitization mechanisms in the feature converters or the broader data loading pipeline to check the integrity or maliciousness of the "negative_targets" and "corrected_targets" data.
        - **Code Example from `NegativeTrainingDiffFeatureConverter.get_decoder_weights`:**
          ```python
          def get_decoder_weights(self, features: Mapping[str, tf.Tensor]) -> tf.Tensor:
              return feature_converters_utils.get_diff_mask(
                  features["negative_targets"], features["corrected_targets"]
              ) * -2 + seqio.feature_converters.non_padding_position(
                  features["negative_targets"]
              )
          ```
          This code directly uses `features["negative_targets"]` and `features["corrected_targets"]` without any prior validation, making it susceptible to data poisoning.
        - **Code Example from `NLModel.loss_fn`:**
          ```python
          def loss_fn(
              self,
              params: PyTree,
              batch: Mapping[str, jnp.ndarray],
              dropout_rng: Optional[jax.Array],
          ) -> Tuple[jnp.ndarray, MetricsMap]:
              logits = self._compute_logits(
                  params, batch, dropout_rng=dropout_rng, mutable=False
              )
              weights = batch['decoder_loss_weights'] # <--- Malicious weights from dataset
              target_tokens = batch['decoder_target_tokens']

              ce_token_scores = self._per_token_ce_nl(logits, target_tokens, weights) # <--- Weights are used in loss calculation
              loss = jnp.sum(ce_token_scores)
              return loss, metrics
          ```
          The `loss_fn` in `NLModel` and other model classes directly incorporates `batch['decoder_loss_weights']`, which are derived from potentially malicious input data, into the loss calculation, thus directly influencing model parameter updates and enabling data poisoning.
    - **Data Flow Visualization:**
      ```mermaid
      graph LR
          A[Malicious Dataset ("corrected_targets", "negative_targets")] --> B(Feature Converters);
          B --> C[decoder_loss_weights];
          C --> D(Model Loss Function e.g., NLModel.loss_fn);
          D --> E[Model Parameters Update];
          E --> F[Biased Language Model];
      ```
      This visualization illustrates the flow of malicious data, highlighting how poisoned datasets can directly impact the trained model through the feature conversion and loss calculation processes.

- **Security Test Case:**
    - Step 1: **Baseline Model Training:** Train a baseline model using a clean, verified dataset with "inputs", "negative_targets", and "corrected_targets" for corrective training. Use a representative T5Patches training pipeline configuration, including a feature converter like `CorrectiveTrainingFullFeatureConverter` and a suitable model like `EncoderDecoderModel`. Evaluate the trained model on a held-out validation dataset and record baseline performance metrics (e.g., accuracy, style metrics if applicable).
    - Step 2: **Poisoned Dataset Creation:** Create a copy of the clean dataset. Introduce a targeted bias or harmful content into the "corrected_targets" (or "negative_targets" depending on the attack objective) field of a small percentage (e.g., 5-10%) of examples in the copied dataset. For example, inject subtly biased language patterns, factual errors, or harmful phrases. In negative training scenarios, ensure malicious content in "negative_targets" is different from "corrected_targets".
    - Step 3: **Poisoned Model Training:** Train a new model using the poisoned dataset from Step 2, using the same T5Patches training pipeline and configurations as in Step 1.
    - Step 4: **Evaluation and Comparison:** Evaluate the poisoned model on the same held-out validation dataset used in Step 1. Compare the performance metrics of the poisoned model with the baseline metrics from Step 1. Analyze the outputs of both models, especially on examples designed to trigger the injected bias or harmful behavior.
    - Step 5: **Verification of Vulnerability:** If the poisoned model exhibits a statistically significant and undesirable deviation in performance or behavior in the direction of the injected bias or harm compared to the baseline model, the data poisoning vulnerability is confirmed. For example, if validation accuracy decreases or if the model demonstrably outputs text with the injected stylistic bias or harmful content, the vulnerability is valid.
    - Step 6: **External Attack Simulation:** To simulate an external attacker scenario, create a malicious dataset and host it on a publicly accessible platform. As a user, download and use this dataset to fine-tune a model using T5Patches. Verify if the resulting model exhibits the attacker-injected biases or harmful behaviors as designed in the malicious dataset, demonstrating real-world exploitability.

This vulnerability poses a significant risk to the T5Patches project and any applications utilizing language models fine-tuned with this toolset. Immediate implementation of the recommended mitigations is crucial to secure the system against data poisoning attacks.