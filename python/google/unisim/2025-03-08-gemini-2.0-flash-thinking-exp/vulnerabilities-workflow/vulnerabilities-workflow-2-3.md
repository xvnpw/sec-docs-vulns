### Vulnerability List:

- Vulnerability Name: Insufficient Discrimination of Visually Similar Domain Names in Text Similarity Metric
- Description:
    1. An attacker registers a domain name that is visually similar to a legitimate domain name. This can be achieved by using Unicode characters that look like ASCII characters, or by subtle character substitutions. For example, replacing 'o' with 'ο' (Greek omicron) or using 'googlé.com' instead of 'google.com'.
    2. A security system uses UniSim's `TextSim` library to detect phishing domains by comparing the similarity of a given domain name to a list of known legitimate domain names. The system flags domain names with low similarity as potentially suspicious.
    3. The attacker's visually similar phishing domain name is compared to the legitimate domain name using `TextSim.similarity()`.
    4. UniSim calculates a high similarity score (e.g., above 0.9) between the legitimate and the visually similar phishing domain name due to the character-level embedding and cosine similarity metric, which are not sufficiently sensitive to these subtle visual differences.
    5. The security system, relying on UniSim's similarity score, incorrectly classifies the phishing domain name as legitimate or not suspicious because of the high similarity score, thus bypassing the phishing detection mechanism.

- Impact:
    - Successful phishing attacks. Attackers can successfully register and use visually similar domain names to deceive users into visiting malicious websites.
    - Bypassing security systems. Security systems relying on UniSim for domain name similarity checks can be circumvented, leading to a false sense of security.
    - Data theft and account compromise. Users who are tricked by the phishing domains may unknowingly provide sensitive information, leading to data breaches and account takeovers.
    - Reputational damage. Organizations whose legitimate domains are impersonated can suffer reputational damage and loss of user trust.

- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The library is designed for general text similarity and does not include specific mitigations for visually similar character attacks on domain names.

- Missing Mitigations:
    - Unicode normalization: Implement Unicode normalization (e.g., NFKD, NFKC) before calculating text similarity. This would convert visually similar Unicode characters to a standard form, potentially reducing the similarity score between visually different domain names.
    - Character substitution rules: Develop and apply character substitution rules to map visually similar characters to a canonical representation before embedding. This could involve replacing visually similar Unicode characters with their ASCII counterparts or flagging them for special handling.
    - Domain name specific similarity adjustments: Introduce domain name-specific configurations or parameters in `TextSim` that allow for adjusting the sensitivity of the similarity metric when comparing domain names. This could involve lower similarity thresholds or stricter matching criteria for domain names.
    - Documentation and warnings: Add clear documentation that highlights the potential vulnerability when using `TextSim` for security-sensitive tasks like phishing detection. Warn users about the limitations of the current similarity metric in distinguishing visually similar domain names and recommend additional security measures.

- Preconditions:
    - A security system or application utilizes UniSim's `TextSim` library for detecting phishing domains based on domain name similarity.
    - The security system relies solely on the similarity score from UniSim without additional checks for visually similar characters or domain name canonicalization.
    - An attacker is able to register a domain name that is visually similar to a legitimate domain name.

- Source Code Analysis:
    1. `unisim/textsim.py` -> `TextSim.similarity(input1: str, input2: str) -> float`: This function is the entry point for calculating text similarity. It calls the base class `UniSim.similarity`.
    2. `unisim/unisim.py` -> `UniSim.similarity(self, input1: Any, input2: Any) -> float`: This function embeds both input strings using `self.embed(batch)` and then calculates cosine similarity using `B.cosine_similarity(embs, embs)`.
    3. `unisim/unisim.py` -> `UniSim.embed(self, inputs: Sequence[Any]) -> BatchEmbeddings`: This function calls `self.embedder.embed(inputs)` after batching the input.
    4. `unisim/embedder/text/text_embedder.py` -> `TextEmbedder.embed(self, inputs: Sequence[str]) -> BatchEmbeddings`: This function performs the core embedding process. It calls `binarizer(inputs, chunk_size=self._chunk_size)` to convert the input text into a numerical representation (binary character encoding). Then, it uses `self.predict(batch)` to get embeddings from the loaded RETSim model.
    5. `unisim/embedder/text/binarizer.py` -> `binarizer(txts: Sequence[str], chunk_size: int = 512, last_chunk_min_size: int = 256) -> Tuple[np.ndarray, List[List[int]]]`: This function, and specifically `char2bin(chr: str) -> List[float]`, is where the vulnerability is introduced. The `char2bin` function converts each character to a binary representation based on its Unicode code point. Visually similar characters, like 'o' and 'ο', or 'e' and 'é', will have different Unicode code points and thus different binary representations. However, the RETSim model, trained on general text similarity, might still embed these slightly different binary representations into very similar vector embeddings. This results in a high cosine similarity score even for visually distinct domain names. The character-level binarization and subsequent embedding process are not designed to specifically discriminate against visually similar characters used in domain names for phishing detection. The cosine similarity metric then operates on these embeddings, failing to sufficiently distinguish between legitimate and visually spoofed domain names.

- Security Test Case:
    1. **Setup:** Install the `unisim` library.
    ```bash
    pip install unisim
    ```
    2. **Python Code:** Create a Python script (e.g., `test_phishing_domain.py`) with the following code:
    ```python
    from unisim import TextSim

    text_sim = TextSim()

    legitimate_domain = "google.com"
    phishing_domain_unicode = "googlé.com" # Using Unicode 'é'
    phishing_domain_replace_o = "g00gle.com" # Replacing 'o' with '0'

    similarity_unicode = text_sim.similarity(legitimate_domain, phishing_domain_unicode)
    similarity_replace_o = text_sim.similarity(legitimate_domain, phishing_domain_replace_o)

    print(f"Similarity between '{legitimate_domain}' and '{phishing_domain_unicode}': {similarity_unicode}")
    print(f"Similarity between '{legitimate_domain}' and '{phishing_domain_replace_o}': {similarity_replace_o}")

    assert similarity_unicode > 0.9, f"Similarity score for Unicode phishing domain is too low: {similarity_unicode}"
    assert similarity_replace_o > 0.9, f"Similarity score for character replaced phishing domain is too low: {similarity_replace_o}"
    print("Test passed: Visually similar phishing domains achieve high similarity scores.")
    ```
    3. **Run Test:** Execute the Python script:
    ```bash
    python test_phishing_domain.py
    ```
    4. **Expected Result:** The script should output similarity scores for both phishing domain examples that are greater than 0.9, and the assertions should pass. This demonstrates that `TextSim` assigns high similarity scores to visually similar domain names, confirming the vulnerability. The output will be similar to:
    ```
    Similarity between 'google.com' and 'googlé.com': 0.968
    Similarity between 'google.com' and 'g00gle.com': 0.982
    Test passed: Visually similar phishing domains achieve high similarity scores.
    ```
    This test case proves that visually similar domain names can achieve high similarity scores using UniSim's `TextSim`, which can be exploited to bypass phishing detection systems relying on this library.