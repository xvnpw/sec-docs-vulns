### Vulnerability List

- Vulnerability Name: Metric Manipulation via Aggressive Transformations
- Description:
    1. An attacker can manipulate the calculated evaluation metrics (WER, CER, etc.) by applying aggressive or misleading transformations to the reference and/or hypothesis strings.
    2. For example, an attacker could use transformations to remove words or characters from the hypothesis that are different from the reference, effectively reducing the error rate artificially.
    3. This can be achieved by crafting a custom transformation pipeline using JiWER's `Compose` and transformation classes.
    4. The attacker then provides this custom transformation as `hypothesis_transform` or `reference_transform` argument to the `wer`, `cer`, `process_words` or `process_characters` functions.
    5. When the evaluation metrics are calculated using these manipulated transformations, the results will be skewed and misleadingly low, regardless of the actual performance of the ASR system.
- Impact:
    - Developers and security analysts may be misled into believing that their Automatic Speech Recognition (ASR) system is performing better than it actually is due to artificially deflated error metrics.
    - This can lead to incorrect conclusions about the ASR system's accuracy and reliability.
    - In security-sensitive contexts, this vulnerability can cause developers to underestimate the risk associated with a poorly performing ASR system, potentially leading to security vulnerabilities if decisions are based on these flawed metrics.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations:
    - JiWER provides default transformations (`wer_default`, `cer_default`, `wer_standardize`, etc.) that are intended for general use.
    - The documentation explains the concept of transformations and provides examples of how to use them.
    - However, there are no explicit warnings or safeguards in the code or documentation to prevent users from creating and using overly aggressive or misleading transformations.
- Missing Mitigations:
    - **Security Warning in Documentation:** The documentation should include a dedicated security warning about the potential for metric manipulation through the use of custom transformations. This warning should emphasize the risk of using overly aggressive transformations that can lead to misleadingly low error rates.
    - **Guidelines for Transformation Usage:**  The documentation could provide guidelines or best practices for choosing appropriate transformations. This could include examples of safe and recommended transformations, as well as examples of transformations that should be avoided due to their potential for misuse.
    - **"Safe Mode" or Predefined Transformation Profiles (Optional):**  Consider offering predefined transformation profiles or a "safe mode" that restricts the use of custom transformations or enforces stricter validation on user-provided transformations. This could provide a more secure and reliable way to use JiWER for evaluation in sensitive contexts.
- Preconditions:
    - The attacker must have the ability to specify or influence the `reference_transform` and/or `hypothesis_transform` arguments when using JiWER's API (either directly in Python code or indirectly through a system that uses JiWER).
    - No specific user privileges are required beyond the ability to call JiWER functions with custom transformations.
- Source Code Analysis:
    1. **Transformation Implementation:** The core transformation logic is implemented in `src/jiwer/transforms.py` and predefined compositions are in `src/jiwer/transformations.py`. These files define various transformation classes like `RemoveSpecificWords`, `SubstituteWords`, `Strip`, etc., and the `Compose` class for chaining them.
    2. **`process_words` and `process_characters` Functions:** In `src/jiwer/process.py`, the functions `process_words` and `process_characters` are defined. These functions accept `reference_transform` and `hypothesis_transform` arguments:
    ```python
    def process_words(
        reference: Union[str, List[str]],
        hypothesis: Union[str, List[str]],
        reference_transform: Union[tr.Compose, tr.AbstractTransform] = wer_default,
        hypothesis_transform: Union[tr.Compose, tr.AbstractTransform] = wer_default,
    ) -> WordOutput:
        # ... function body ...
    ```
    ```python
    def process_characters(
        reference: Union[str, List[str]],
        hypothesis: Union[str, List[str]],
        reference_transform: Union[tr.Compose, tr.AbstractTransform] = cer_default,
        hypothesis_transform: Union[tr.Compose, tr.AbstractTransform] = cer_default,
    ) -> CharacterOutput:
        # ... function body ...
    ```
    3. **Metric Calculation Functions:** The functions in `src/jiwer/measures.py` (e.g., `wer`, `cer`, `mer`) also accept these transformation arguments and pass them down to `process_words` or `process_characters`.
    4. **Vulnerability Point:** The vulnerability arises because JiWER does not restrict or validate the transformations provided by the user. An attacker can create a `Compose` object with transformations designed to aggressively modify the hypothesis to closely match the reference, regardless of the actual ASR output quality. For example, a transformation that removes all words from the hypothesis that are not in the reference could drastically reduce the WER, creating a false impression of high ASR accuracy.

- Security Test Case:
    1. **Craft Malicious Transformation:** Create a custom transformation using `jiwer.Compose` and `jiwer.transforms`. This transformation will aggressively modify the hypothesis strings to artificially reduce the WER. For this test case, we will create a transformation that substitutes all words in the hypothesis with words from the reference, effectively making the hypothesis identical to the reference after transformation.
    ```python
    import jiwer

    class MaliciousSubstitutionTransform(jiwer.AbstractTransform):
        def process_string(self, s: str):
            return s # In real attack, implement logic to substitute hypothesis words with reference words
                     # For simplicity of test case, we just return the original string,
                     # but in actual malicious transform, this would contain substitution logic
                     # that relies on knowledge of the reference string to manipulate hypothesis.
        def process_list(self, inp: list[str]):
            return [self.process_string(s) for s in inp]

    malicious_transform = jiwer.Compose([
        MaliciousSubstitutionTransform(), # In real attack, this transform would manipulate the hypothesis
        jiwer.ReduceToListOfListOfWords()
    ])
    ```
    2. **Prepare Reference and Hypothesis:** Define a reference and a clearly erroneous hypothesis string.
    ```python
    reference_text = "the quick brown fox jumps over the lazy dog"
    hypothesis_text = "зраствуйте это тест" # "hello this is test" in Russian, completely different from reference
    ```
    3. **Calculate WER with Default Transformation:** Calculate the Word Error Rate (WER) using the default `wer_default` transformation to establish a baseline.
    ```python
    default_wer = jiwer.wer(reference_text, hypothesis_text)
    print(f"WER with default transformation: {default_wer}")
    ```
    4. **Calculate WER with Malicious Transformation:** Calculate the WER again, but this time apply the `malicious_transform` to the hypothesis.
    ```python
    malicious_wer = jiwer.wer(reference_text, hypothesis_text, hypothesis_transform=malicious_transform)
    print(f"WER with malicious transformation: {malicious_wer}")
    ```
    5. **Analyze Results:** Observe and compare the WER values. The `malicious_wer` should be significantly lower than the `default_wer`, ideally close to 0 in a real malicious transformation scenario (in this simplified test case, it will be the same as default because the transform is not actually manipulating the hypothesis, but it demonstrates the capability to inject custom transforms).  This difference demonstrates that an attacker can manipulate the WER metric by using custom, aggressive transformations.

    **Expected Output (for a real malicious transformation):**
    ```text
    WER with default transformation: <some high value, e.g., 1.0 or higher>
    WER with malicious transformation: <significantly lower value, ideally close to 0.0>
    ```
    **Note:** This test case uses a simplified `MaliciousSubstitutionTransform` for demonstration. A truly malicious transformation would require more complex logic to dynamically modify the hypothesis based on the reference. However, this simplified example effectively illustrates the core vulnerability: the ability to inject custom transformations that can manipulate evaluation metrics.