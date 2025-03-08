### Vulnerability List:

* Vulnerability Name: Inadequate Text Sanitization leading to Information Loss

* Description:
    1. The application uses `text_model.py` for processing text inputs.
    2. The `SimpleVocab.tokenize_text()` function within `text_model.py` aggressively sanitizes text input by converting it to ASCII, ignoring non-ASCII characters: `text = text.encode('ascii', 'ignore').decode('ascii')`.
    3. This sanitization step leads to irreversible information loss as any non-ASCII characters present in the original text input are removed.
    4. If an attacker provides a text query containing non-ASCII characters, these characters will be silently discarded before being processed by the model.
    5. This can lead to the model processing an unintended or incomplete query, potentially affecting the accuracy and relevance of image retrieval results.
    6. In scenarios where the application is expected to handle text in languages other than English or text containing special symbols, this sanitization will cause incorrect or degraded performance.
    7. For example, if a user inputs a query in French, German, or any language using accented characters or characters outside the basic ASCII range, these characters will be removed, and the model will process a potentially nonsensical English-ASCII approximation of the original query.

* Impact:
    - Degraded image retrieval accuracy and relevance for queries containing non-ASCII characters.
    - Misinterpretation of user intent for queries in languages with non-ASCII characters or when users intentionally use non-ASCII symbols.
    - Potential bypass of intended query filtering or semantic understanding if it relies on non-ASCII characters.
    - Reduced usability for users who need to input queries with non-ASCII characters.

* Vulnerability Rank: Medium

* Currently Implemented Mitigations:
    - The code attempts to mitigate potential issues by converting text to ASCII, removing punctuation and lowercasing text in `text_model.py` -> `SimpleVocab.tokenize_text()`.
    - This is intended to simplify the vocabulary and handle variations in text input, but it over-aggressively removes non-ASCII characters.

* Missing Mitigations:
    - Implement proper handling of Unicode or a broader character set instead of simply ignoring non-ASCII characters.
    - Consider using a more robust text encoding (like UTF-8) throughout the text processing pipeline.
    - If ASCII-only processing is a strict requirement for the model, provide clear documentation and input validation to inform users about this limitation and prevent unintended information loss.
    - Alternatively, if broader character support is needed, retrain the model with a vocabulary that includes non-ASCII characters and adjust the tokenization process accordingly.

* Preconditions:
    - The application must be deployed as a web service or application where users can input text queries.
    - Users must be able to provide text queries that include non-ASCII characters, either intentionally or unintentionally (e.g., copy-pasting text from other sources, using different keyboard layouts, or typing in languages other than basic English).

* Source Code Analysis:
    1. **File: `/code/text_model.py`**:
    ```python
    class SimpleVocab(object):
        # ...
        def tokenize_text(self, text):
            text = text.encode('ascii', 'ignore').decode('ascii') # [VULNERABLE CODE] - Non-ASCII characters are ignored
            tokens = str(text).lower()
            tokens = tokens.translate(str.maketrans('','',string.punctuation))
            tokens = tokens.strip().split()
            return tokens
        # ...
    ```
    2. The `tokenize_text` function is called within `SimpleVocab` to process input text.
    3. The line `text = text.encode('ascii', 'ignore').decode('ascii')` is the source of the vulnerability.
        - `text.encode('ascii', 'ignore')`: This encodes the input `text` into ASCII bytes. The `ignore` error handler means that if a character cannot be encoded in ASCII, it will be ignored (i.e., removed).
        - `.decode('ascii')`: This decodes the resulting ASCII bytes back into a string.
    4. **Visualization:**
        Input Text (e.g., "café"):  'c' 'a' 'f' 'é' (Unicode characters)
        `text.encode('ascii', 'ignore')`: 'c' 'a' 'f'  (bytes representing ASCII 'c', 'a', 'f', 'é' is ignored)
        `.decode('ascii')`: 'c' 'a' 'f' (ASCII string "caf")
        Output Tokens (after further processing): ['caf']
    5. As visualized, the non-ASCII character 'é' is completely removed during the ASCII encoding/decoding process, leading to information loss.

* Security Test Case:
    1. **Setup:** Deploy the image retrieval service using the provided code. Ensure the service accepts text queries as input.
    2. **Craft Malicious Input:** Prepare a text query containing non-ASCII characters, for example: "A café chair".
    3. **Send Request:** Submit the crafted query "A café chair" to the image retrieval service.
    4. **Observe Output:** Analyze the image retrieval results.
    5. **Expected Behavior (Vulnerable):** The service will process the query as if it were "A cafe chair" because the 'é' is removed during tokenization. The retrieval results may be less accurate or relevant compared to if the query was processed with the intended character.
    6. **Verify Information Loss:** Inspect the logs or debug the application to confirm that the tokenization process indeed removed the non-ASCII character 'é' from the input query before feeding it to the model.
    7. **Compare with Correct Input (Mitigated):** After implementing a mitigation (e.g., using UTF-8 encoding), repeat steps 2-4 with the same query. The retrieval results should now be more accurate and relevant as the non-ASCII character is correctly processed.
    8. **Expected Behavior (Mitigated):** The service will process the query "A café chair" correctly, preserving the 'é' character (or its UTF-8 representation). The retrieval results should be improved compared to the vulnerable case.

This test case demonstrates that the aggressive ASCII sanitization leads to information loss and can negatively impact the performance of the image retrieval system when dealing with text queries containing non-ASCII characters.