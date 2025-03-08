- Vulnerability Name: Potential for Similarity Score Bypassing with Malicious Text Inputs
- Description:
    - An attacker can craft subtly modified, malicious text inputs that are designed to be deceptively similar to legitimate text when processed by UniSim's `TextSim`.
    - These modifications could include:
        - Homoglyphs: Replacing characters with visually similar characters from different alphabets (e.g., replacing 'a' with 'а' - Cyrillic 'a').
        - Insertion of invisible characters: Adding zero-width spaces or other non-printing characters.
        - Slight alterations in word order or punctuation: Making minor changes that preserve meaning but alter the exact string.
    - When `TextSim` computes the similarity between these malicious inputs and legitimate texts, the similarity score might be deceptively high due to the robustness of the underlying RETSim model and cosine similarity.
    - If a security system relies on UniSim to detect malicious content based on similarity scores and uses a threshold to classify content as malicious or benign, these subtly modified malicious inputs could bypass detection if the threshold is not carefully configured to account for such deceptive similarity.
- Impact:
    - Bypassing security systems that rely on UniSim's text similarity scores for malicious content detection.
    - Successful phishing attacks if UniSim is used for phishing domain detection, as attackers could create domain names deceptively similar to legitimate ones.
    - Circumvention of content filtering or spam detection systems that use similarity to identify and block malicious or unwanted content.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations:
    - None in the code itself.
    - The documentation in `README.md` mentions that "if the similarity threshold is not carefully configured" it can lead to bypassing security systems, implying awareness of this potential issue and suggesting threshold configuration as a mitigation strategy by the user.
- Missing Mitigations:
    - Input Sanitization and Normalization: Implementing preprocessing steps to normalize text inputs before embedding. This could include:
        - Homoglyph normalization: Converting homoglyphs to their intended base characters.
        - Removal of invisible characters: Stripping out control characters and zero-width spaces.
        - Lowercasing and punctuation normalization: Standardizing text casing and punctuation to reduce variations.
    - Guidance on Similarity Threshold Selection: Providing more detailed guidance and best practices in the documentation on how to choose appropriate similarity thresholds based on the security context and the desired level of sensitivity vs. false positives. This could include examples of thresholds for different use cases (e.g., near-duplicate detection vs. phishing detection).
    - Model Retraining or Fine-tuning:  Potentially retraining or fine-tuning the RETSim model to be less sensitive to subtle, malicious modifications, making it more robust against adversarial inputs. This is a more complex and resource-intensive mitigation.
- Preconditions:
    - A security system or application is using UniSim's `TextSim` library to perform text similarity comparisons for security-sensitive purposes, such as malicious content detection (e.g., phishing detection, spam filtering).
    - The security system relies on a similarity threshold to classify content as malicious or benign.
    - The similarity threshold is not optimally configured to account for subtly modified malicious inputs, or no input sanitization is performed before similarity computation.
- Source Code Analysis:
    - File: `/code/unisim/textsim.py` and `/code/unisim/unisim.py`
        - The `TextSim.similarity(input1, input2)` function (inherited from `UniSim`) computes the similarity between two input strings.
        - It calls `TextSim.embed()` to generate embeddings for the inputs and then calculates cosine similarity between these embeddings using the backend (`unisim/backend/`).
    - File: `/code/unisim/embedder/text/text_embedder.py`
        - The `TextEmbedder.embed(inputs)` function is responsible for converting text inputs into embeddings.
        - It utilizes `binarizer(inputs)` to convert text into a numerical format suitable for the RETSim model.
        - The `predict()` method (inherited from `Embedder`) then uses the loaded RETSim model to generate embeddings from the binarized input.
    - File: `/code/unisim/embedder/text/binarizer.py`
        - The `binarizer(txts)` function converts input text into a numerical representation by mapping each character to a binary vector.
        - **Vulnerability Point:** This function performs character-level conversion but **lacks any input sanitization or normalization**. It directly processes the input text as is, without removing or transforming potentially deceptive characters like homoglyphs or invisible characters.
    - File: `/code/unisim/backend/` (e.g., `tf.py` or `onnx.py`)
        - The backend code calculates cosine similarity between the generated embeddings.
        - The cosine similarity calculation itself is not vulnerable, but it operates on embeddings that are generated from unsanitized inputs.
    - **Conclusion:** The vulnerability arises from the lack of input sanitization in the text processing pipeline, specifically in the `binarizer.py` and `TextEmbedder.py`. Maliciously crafted inputs with subtle character modifications are directly fed into the RETSim model, potentially leading to deceptively high similarity scores and bypassing security thresholds.

- Security Test Case:
    - Step 1: Initialize `TextSim` instance.
    - Step 2: Define a legitimate domain name string: `legitimate_domain = "example.com"`.
    - Step 3: Create a malicious domain name string with a homoglyph (Cyrillic 'а' instead of Latin 'a'): `malicious_domain_homoglyph = "exаmple.com"`.
    - Step 4: Create a malicious domain name string with an invisible character (zero-width space after 'e'): `malicious_domain_invisible = "examp\u200ble.com"`.
    - Step 5: Compute the similarity between the legitimate domain and the homoglyph domain:
        ```python
        from unisim import TextSim
        text_sim = TextSim()
        similarity_homoglyph = text_sim.similarity(legitimate_domain, malicious_domain_homoglyph)
        print(f"Similarity (Homoglyph): {similarity_homoglyph}")
        ```
    - Step 6: Compute the similarity between the legitimate domain and the invisible character domain:
        ```python
        similarity_invisible = text_sim.similarity(legitimate_domain, malicious_domain_invisible)
        print(f"Similarity (Invisible Char): {similarity_invisible}")
        ```
    - Step 7: Analyze the results. If the similarity scores for both `similarity_homoglyph` and `similarity_invisible` are high (e.g., >= 0.9), it demonstrates that subtly modified malicious inputs can achieve high similarity scores with legitimate inputs, indicating a potential vulnerability for bypassing similarity-based detection systems if thresholds are not carefully managed and input sanitization is absent. For example, running this test case might produce similarity scores like:
        ```
        Similarity (Homoglyph): 0.99
        Similarity (Invisible Char): 0.98
        ```
        These high similarity scores for clearly different domain names (one legitimate, one malicious) confirm the vulnerability.