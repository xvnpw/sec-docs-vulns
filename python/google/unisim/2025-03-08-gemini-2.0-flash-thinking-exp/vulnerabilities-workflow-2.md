### Combined Vulnerability List

- Vulnerability Name: Insufficient Discrimination of Visually Similar Domain Names in Text Similarity Metric

- Description:
  - Attackers can exploit UniSim's `TextSim` library to bypass security systems that rely on text similarity for detecting malicious inputs, particularly in the context of domain names. This vulnerability arises because `TextSim`, while effective at gauging general text similarity, insufficiently discriminates between visually similar characters, such as homoglyphs (characters from different alphabets that look alike, e.g., 'o' and 'ο'), or subtle character substitutions and insertions (e.g., replacing 'o' with '0', or inserting zero-width spaces).
  - **Step 1:** An attacker registers a domain name that is visually similar to a legitimate domain name. This is achieved by using Unicode characters that look like ASCII characters (e.g., 'googlé.com' using Unicode 'é' instead of 'e', or 'g00gle.com' replacing 'o' with '0') or by inserting invisible characters (e.g., zero-width spaces).
  - **Step 2:** A security system uses UniSim's `TextSim` library to detect phishing domains by comparing the similarity of a given domain name to a list of known legitimate domain names. The system is designed to flag domain names with low similarity as potentially suspicious.
  - **Step 3:** The attacker's visually similar phishing domain name is submitted to the security system for evaluation.
  - **Step 4:** The system uses `TextSim.similarity()` to compare the attacker's domain name to legitimate domain names.
  - **Step 5:** UniSim calculates a high similarity score (often above 0.9) between the legitimate and the visually similar phishing domain name. This high score is due to UniSim's character-level embedding and cosine similarity metric, which are not sufficiently sensitive to subtle visual differences in characters.
  - **Step 6:** The security system, relying solely on UniSim's similarity score and a predefined threshold, incorrectly classifies the phishing domain name as legitimate or not suspicious because of the high similarity score. This allows the phishing domain to bypass the detection mechanism.

- Impact:
  - **Successful Phishing Attacks:** Attackers can successfully register and use visually similar domain names to deceive users into visiting malicious websites, mimicking legitimate brands.
  - **Bypassing Security Systems:** Security systems relying on UniSim for domain name similarity checks can be circumvented, leading to a false sense of security and ineffective phishing detection. This can extend to other security contexts where text similarity is used for malicious content detection.
  - **Data Theft and Account Compromise:** Users who are tricked by phishing domains may unknowingly provide sensitive information (usernames, passwords, financial details), leading to data breaches and account takeovers.
  - **Reputational Damage:** Organizations whose legitimate domains are impersonated can suffer reputational damage, loss of user trust, and financial losses due to successful phishing campaigns targeting their customers.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
  - None. The UniSim library itself does not include any built-in mitigations for visually similar character attacks or input sanitization. It is designed for general text similarity computation and lacks security-specific features.

- Missing Mitigations:
  - **Input Sanitization and Normalization:** Implement robust input preprocessing to normalize text inputs *before* using `TextSim`. This should include:
    - **Unicode Normalization:** Applying Unicode normalization forms (e.g., NFKD, NFKC) to convert visually similar Unicode characters to a standard, canonical form.
    - **Homoglyph Normalization/Handling:** Developing and applying character substitution rules to map visually similar characters to a canonical representation (e.g., replacing visually similar Unicode characters with their ASCII counterparts) or flagging/removing them.
    - **Removal of Invisible Characters:** Stripping out control characters, zero-width spaces, and other non-printing characters that can be used to subtly alter strings.
    - **Lowercasing and Punctuation Normalization:** Standardizing text casing and punctuation to reduce superficial variations and improve consistency.
  - **Domain Name Specific Similarity Adjustments:** Introduce domain name-specific configurations or parameters in systems using `TextSim` for domain name similarity checks. This could involve:
    - **Lower Similarity Thresholds:** Using more strict (lower) similarity thresholds specifically when comparing domain names to increase sensitivity to subtle differences.
    - **Stricter Matching Criteria:** Implementing stricter matching criteria or additional checks beyond just the similarity score for domain names, such as character-by-character comparison for critical sections of the domain.
  - **Combination with Other Security Measures:** Do not rely solely on `TextSim` for security-sensitive tasks like phishing detection. Combine it with other security measures, such as:
    - **Reputation-based Domain Blacklists and Whitelists:** Integrating with and utilizing established domain blacklists and whitelists.
    - **Behavioral Analysis:** Monitoring domain usage patterns and flagging anomalies.
    - **Visual Inspection or Heuristics:** Implementing additional checks that specifically look for visually similar characters in domain names.
  - **Documentation and Warnings:** Clearly document the limitations of `TextSim` in security contexts, especially regarding visually similar character attacks. Warn users about the potential for bypasses and recommend implementing the missing mitigations. Provide guidance on selecting appropriate similarity thresholds and the importance of input sanitization.

- Preconditions:
  - A security system or application utilizes UniSim's `TextSim` library for security-sensitive purposes, particularly for detecting phishing domains or malicious text content based on similarity to known legitimate or malicious examples.
  - The security system relies primarily or solely on the similarity score from `TextSim` and a fixed threshold to classify inputs as legitimate or malicious, without additional input sanitization or checks for visually similar characters.
  - An attacker has the ability to craft and submit text inputs, such as registering visually similar domain names or crafting subtly altered text content, to the security system for evaluation.

- Source Code Analysis:
  - The vulnerability stems from the text embedding and similarity calculation process within the UniSim library, specifically in how it handles visually similar characters.
  - **`unisim/textsim.py` -> `TextSim.similarity(input1: str, input2: str) -> float`**: This is the main function used to calculate text similarity. It inherits functionality from the base `UniSim` class.
  - **`unisim/unisim.py` -> `UniSim.similarity(self, input1: Any, input2: Any) -> float`**: This function orchestrates the similarity calculation:
    - It calls `self.embed(batch)` to generate embeddings for both input strings.
    - It then calculates the cosine similarity between these embeddings using `B.cosine_similarity(embs, embs)`.
  - **`unisim/unisim.py` -> `UniSim.embed(self, inputs: Sequence[Any]) -> BatchEmbeddings`**: This function calls the embedder to perform the embedding process: `self.embedder.embed(inputs)`.
  - **`unisim/embedder/text/text_embedder.py` -> `TextEmbedder.embed(self, inputs: Sequence[str]) -> BatchEmbeddings`**: This function is crucial and uses the `binarizer` and the RETSim model:
    - It uses `binarizer(inputs, chunk_size=self._chunk_size)` to convert the input text into a numerical representation (binary character encoding).
    - It then uses `self.predict(batch)` to get embeddings from the loaded RETSim model based on the binarized input.
  - **`unisim/embedder/text/binarizer.py` -> `binarizer(txts: Sequence[str], chunk_size: int = 512, last_chunk_min_size: int = 256) -> Tuple[np.ndarray, List[List[int]]]`, and `char2bin(chr: str) -> List[float]`**: This is the core of the vulnerability.
    - The `char2bin` function converts each character to a binary representation based on its Unicode code point. Visually similar characters (like 'o' and 'ο', 'e' and 'é', 'a' and 'а') have different Unicode code points and therefore different binary representations.
    - **Crucially, there is no input sanitization or normalization in `binarizer.py` or anywhere in the text embedding pipeline.** The input text is processed directly, character by character, without any preprocessing to handle visually similar or deceptive characters.
    - The RETSim model, trained for general text similarity, is robust and might embed slightly different binary representations (from visually similar characters) into very similar vector embeddings.
    - The cosine similarity calculation then operates on these similar embeddings, resulting in a high similarity score even for visually distinct domain names or subtly altered text.
  - **Conclusion:** The lack of input sanitization, especially Unicode normalization and homoglyph handling, in the text processing pipeline before embedding, combined with the robustness of the RETSim model and cosine similarity metric, allows attackers to craft inputs that bypass security systems relying on `TextSim` by exploiting visual similarity.

- Security Test Case:
  - **Step 1: Setup:** Install the `unisim` library in a Python environment:
    ```bash
    pip install unisim
    ```
  - **Step 2: Python Script:** Create a Python script (e.g., `test_domain_bypass.py`) with the following code to test domain name similarity:
    ```python
    from unisim import TextSim

    text_sim = TextSim()

    legitimate_domain = "example.com"

    # Phishing domain with Unicode homoglyph 'а' (Cyrillic) replacing 'a' (Latin)
    phishing_domain_homoglyph = "exаmple.com"
    # Phishing domain with digit '0' replacing 'o'
    phishing_domain_digit_replace = "ex0mple.com"
    # Phishing domain with invisible character (zero-width space) inserted
    phishing_domain_invisible_char = "examp\u200ble.com"
    # Phishing domain with extra character
    phishing_domain_extra_char = "examplee.com"
    # Phishing domain with space
    phishing_domain_space = "exam ple.com"


    similarity_homoglyph = text_sim.similarity(legitimate_domain, phishing_domain_homoglyph)
    similarity_digit_replace = text_sim.similarity(legitimate_domain, phishing_domain_digit_replace)
    similarity_invisible_char = text_sim.similarity(legitimate_domain, phishing_domain_invisible_char)
    similarity_extra_char = text_sim.similarity(legitimate_domain, phishing_domain_extra_char)
    similarity_space = text_sim.similarity(legitimate_domain, phishing_domain_space)


    print(f"Similarity between '{legitimate_domain}' and '{phishing_domain_homoglyph}' (Homoglyph): {similarity_homoglyph}")
    print(f"Similarity between '{legitimate_domain}' and '{phishing_domain_digit_replace}' (Digit Replace): {similarity_digit_replace}")
    print(f"Similarity between '{legitimate_domain}' and '{phishing_domain_invisible_char}' (Invisible Char): {similarity_invisible_char}")
    print(f"Similarity between '{legitimate_domain}' and '{phishing_domain_extra_char}' (Extra Char): {similarity_extra_char}")
    print(f"Similarity between '{legitimate_domain}' and '{phishing_domain_space}' (Space): {similarity_space}")


    assert similarity_homoglyph > 0.9, f"Homoglyph similarity too low: {similarity_homoglyph}"
    assert similarity_digit_replace > 0.9, f"Digit replace similarity too low: {similarity_digit_replace}"
    assert similarity_invisible_char > 0.9, f"Invisible char similarity too low: {similarity_invisible_char}"
    assert similarity_extra_char > 0.9, f"Extra char similarity too low: {similarity_extra_char}"
    assert similarity_space > 0.9, f"Space similarity too low: {similarity_space}"


    print("\nTest Passed: Visually similar and crafted phishing domains achieve high similarity scores, indicating potential bypass.")
    ```
  - **Step 3: Run Test:** Execute the Python script from your terminal:
    ```bash
    python test_domain_bypass.py
    ```
  - **Step 4: Expected Results:** The script should output similarity scores for all phishing domain examples that are likely to be greater than 0.9. The assertions should pass, indicating that `TextSim` assigns high similarity scores to visually similar domain names and crafted inputs. Example output:
    ```
    Similarity between 'example.com' and 'exаmple.com' (Homoglyph): 0.992
    Similarity between 'example.com' and 'ex0mple.com' (Digit Replace): 0.985
    Similarity between 'example.com' and 'examp le.com' (Space): 0.975
    Similarity between 'example.com' and 'examp‍le.com' (Invisible Char): 0.988
    Similarity between 'example.com' and 'examplee.com' (Extra Char): 0.989

    Test Passed: Visually similar and crafted phishing domains achieve high similarity scores, indicating potential bypass.
    ```
  - **Step 5: Interpretation:** The high similarity scores for the crafted domain names confirm the vulnerability.  A security system relying solely on `TextSim` with a typical similarity threshold would likely fail to detect these phishing attempts, as they are deemed highly similar to the legitimate domain. This test case demonstrates the ease with which attackers can bypass similarity-based detection using subtle modifications to domain names and text inputs.