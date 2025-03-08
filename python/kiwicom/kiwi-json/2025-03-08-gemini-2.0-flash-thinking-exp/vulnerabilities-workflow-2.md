### Combined Vulnerability List

#### Vulnerability Name: Keyword-Based Masking Bypass Vulnerabilities

*   **Description:** The Kiwi JSON library's data masking functionality relies on keyword-based blacklists and whitelists applied to dictionary keys. This approach is vulnerable to bypasses in several ways:

    *   **Whitelist Bypass:** If a whitelist is configured to prevent masking for certain keys (e.g., "public_key"), an attacker who can control the input data structure can inject sensitive information under these whitelisted keys. Since whitelisted keys are never masked, this sensitive data will be exposed in the JSON output, bypassing the intended masking.

        **Step-by-step trigger (Whitelist Bypass):**
        1. An application uses Kiwi JSON's `MaskedJSONEncoder` with a whitelist (e.g., containing "public_key").
        2. An attacker gains control over the input data that is being encoded into JSON.
        3. The attacker crafts the input data to include sensitive information under keys present in the whitelist, such as `"public_key": "attacker_sensitive_data"`.
        4. Kiwi JSON encodes this data. The values associated with whitelisted keys are not masked.
        5. Sensitive data is exposed in the JSON output.

    *   **Blacklist/Whitelist Keyword Variation Bypass:**  The masking mechanism uses simple keyword matching against a blacklist and whitelist. Attackers can bypass this by slightly altering key names to avoid blacklisted keywords or exploit overly broad whitelists. For example, instead of "secret_key", using "my_secret_key_value" might bypass a blacklist that only checks for "secret".

        **Step-by-step trigger (Keyword Variation Bypass):**
        1. An application uses Kiwi JSON's masking with keyword-based blacklist/whitelist.
        2. An attacker identifies the blacklist keywords (e.g., "secret", "token").
        3. The attacker crafts a request with sensitive information under keys that are variations of blacklisted keywords but do not exactly match (e.g., "secret_info" instead of "secret").
        4. Kiwi JSON encodes this data. The `mask_dict` function fails to identify these modified keys as sensitive.
        5. JSON output is generated with unmasked sensitive information.

*   **Impact:** High. Exposure of sensitive information intended to be masked. This can lead to unauthorized access, data breaches, and other security incidents.

*   **Vulnerability Rank:** High

*   **Currently Implemented Mitigations:**
    *   Customizable blacklist and whitelist via `mask_dict_factory`. This allows developers to define their own keywords but does not inherently prevent bypasses if misconfigured or incomplete.

*   **Missing Mitigations:**
    *   Input Validation and Sanitization: Validate and sanitize input data before encoding to prevent misuse of whitelisted keys or variations of blacklisted keys.
    *   Principle of Least Privilege for Whitelisting: Minimize the whitelist and regularly audit it.
    *   Semantic or Context-Aware Masking: Move beyond keyword matching to understand the context and meaning of data for masking decisions.
    *   Regular Expression or Advanced Pattern Matching: Use more sophisticated pattern matching for blacklist/whitelist.
    *   Data Type or Schema-Based Masking: Mask based on expected data types or schema of fields.

*   **Preconditions:**
    *   Kiwi JSON's `MaskedJSONEncoder` or `mask_dict` is used for JSON encoding.
    *   Whitelist is enabled (for whitelist bypass) or blacklist/whitelist is in use (for keyword variation bypass).
    *   Attacker can control input data structure or guess blacklist/whitelist keywords.

*   **Source Code Analysis:**
    1.  `kw/json/utils.py:mask_dict_factory` and `mask_dict`:
        ```python
        def mask_dict_factory(
            placeholder=DEFAULT_PLACEHOLDER,
            blacklist=DEFAULT_BLACKLIST,
            whitelist=DEFAULT_WHITELIST,
        ):
            def mask_dict(pairs):
                """Return a dict with dangerous looking key/value pairs masked."""
                if pairs is None:
                    return {}

                if isinstance(pairs, dict):
                    items = pairs.items()
                else:
                    items = pairs

                return {
                    key: (
                        placeholder
                        if key.lower() not in whitelist # Whitelist check is performed first
                        and any(word in key.lower() for word in blacklist)
                        else value
                    )
                    for key, value in items
                }

            return mask_dict

        mask_dict = mask_dict_factory()
        ```
        - `mask_dict` function checks if a key is in the whitelist first. If it is, masking is bypassed.
        - If not in whitelist, it checks for blacklist keywords. Simple keyword matching is used.
        - Vulnerability lies in the simple keyword-based check and unconditional whitelist bypass.

    2.  `kw/json/encode.py:MaskedJSONEncoder`:
        ```python
        class MaskedJSONEncoder(BaseJSONEncoder):
            def default(self, o):  # pylint: disable=method-hidden
                return default_encoder(o, mask_dict)

            def encode(self, o):
                if isinstance(o, dict):
                    o = mask_dict(o) # Top-level dictionary is masked here
                return super().encode(o)
        ```
        - `MaskedJSONEncoder` uses `mask_dict` to mask top-level dictionaries, but the core vulnerability is in `mask_dict`'s logic.

*   **Security Test Case:**
    1.  **Whitelist Bypass Test:**
        - Construct a dictionary with sensitive data under a whitelisted key (e.g., `"public_key": "sensitive_data"`).
        - Encode it using `MaskedJSONEncoder`.
        - Verify that the value under the whitelisted key is not masked.

    2.  **Keyword Variation Bypass Test:**
        - Define a custom `mask_dict` with blacklist=["secret"] and whitelist=["public_key"].
        - Create a dictionary with keys like "secret_info", "my_secrets" containing sensitive data.
        - Encode it using `MaskedJSONEncoder`.
        - Verify that values under "secret_info", "my_secrets" are NOT masked, while keys like "secret" (exact blacklist match) would be masked.

#### Vulnerability Name: Incorrect Whitelist/Blacklist Logic in `mask_dict`

*   **Description:** The `mask_dict` function in `kw/json/utils.py` has flawed logic for combining whitelist and blacklist. The current implementation prioritizes the blacklist condition over the whitelist. If a key contains both blacklisted and whitelisted substrings, it will be incorrectly masked, even if it should be whitelisted.

    **Step-by-step trigger:**
    1. Configure `mask_dict_factory` with a blacklist (e.g., `{'secret'}`) and a whitelist (e.g., `{'not-so-secret'}`).
    2. Create a dictionary with a key that contains both a blacklisted and whitelisted word (e.g., `"this-is-not-so-secret-but-contains-secret"`).
    3. Apply `mask_dict` to this dictionary.
    4. The value associated with this key is incorrectly masked due to the flawed logic.

*   **Impact:** Medium. Incorrect data masking, potentially leading to unintentional masking of data that should be allowed based on whitelist rules, causing functional issues.

*   **Vulnerability Rank:** Medium

*   **Currently Implemented Mitigations:** None specifically for this logical flaw. Blacklist/whitelist functionality is provided, but the combination logic is flawed.

*   **Missing Mitigations:** Correct the masking logic in `mask_dict` to prioritize the whitelist. If a key is whitelisted, it should not be masked regardless of blacklist matches.

    **Corrected Logic Example:**
    ```python
    if key.lower() in whitelist:
        value # Do not mask, it's whitelisted
    elif any(word in key.lower() for word in blacklist):
        placeholder # Mask, it's blacklisted and not whitelisted
    else:
        value # Do not mask, neither blacklisted nor whitelisted
    ```

*   **Preconditions:**
    *   Kiwi JSON library is used.
    *   Data masking is enabled with `mask_dict` or `mask_dict_factory`.
    *   Both blacklist and whitelist are configured.
    *   Dictionary keys exist containing both blacklisted and whitelisted substrings.

*   **Source Code Analysis:**
    1.  File: `/code/kw/json/utils.py`
    2.  Function: `mask_dict` (within `mask_dict_factory`)
    3.  Incorrect Logic: `placeholder if key.lower() not in whitelist and any(word in key.lower() for word in blacklist) else value`
    4.  The `AND` condition combined with `not in whitelist` and `any(word in blacklist)` causes blacklist to take precedence over whitelist when both are present in a key.

*   **Security Test Case:**
    1.  Define `mask_dict` with blacklist={'secret'}, whitelist={'not-so-secret'}.
    2.  Create test dictionary: `{'this-is-not-so-secret-but-contains-secret': 'sensitive_value'}`.
    3.  Apply `mask_dict`.
    4.  Assert that the value for the key `"this-is-not-so-secret-but-contains-secret"` is **NOT** masked (current logic incorrectly masks it).

#### Vulnerability Name: Inadequate Data Masking - Value Data Exposure

*   **Description:** Kiwi JSON's masking is solely key-based. It does not inspect or mask values within dictionaries. If sensitive information is placed in dictionary values under keys that are not blacklisted, it will be serialized in JSON without masking, leading to potential exposure.

    **Step-by-step trigger:**
    1. An application uses Kiwi JSON's masking functionality.
    2. Developers place sensitive information in dictionary values, assuming key-based masking is sufficient.
    3. The sensitive data is under keys that are not blacklisted (or are whitelisted).
    4. Kiwi JSON encodes this data. Only keys are checked for masking, values are ignored.
    5. Sensitive data in values is exposed in the JSON output.

*   **Impact:** Medium. Exposure of sensitive information in dictionary values that were intended to be protected by the application's use of Kiwi JSON masking.

*   **Vulnerability Rank:** Medium

*   **Currently Implemented Mitigations:** Key-based masking using blacklist/whitelist in `kw/json/utils.py`.

*   **Missing Mitigations:** Value-based masking. The library should offer options to inspect and mask values based on keywords, patterns, or data types for more comprehensive protection.

*   **Preconditions:**
    *   Kiwi JSON's masking is used.
    *   Sensitive data is present in dictionary values.
    *   Keys associated with sensitive values are not blacklisted or are whitelisted.
    *   Attacker can observe the JSON output.

*   **Source Code Analysis:**
    1.  File: `/code/kw/json/utils.py`
    2.  Function: `mask_dict(pairs)`
    3.  The `mask_dict` function only checks keys against blacklist/whitelist.
    4.  Values are not inspected or masked based on their content.

    ```python
    def mask_dict(pairs):
        # ...
        return {
            key: (
                placeholder
                if key.lower() not in whitelist
                and any(word in key.lower() for word in blacklist)
                else value # Value is returned as is without inspection
            )
            for key, value in items
        }
    ```

*   **Security Test Case:**
    1.  Create a dictionary: `{"non_sensitive_key": "public_data", "description": "My secret is sensitive_value"}`.
    2.  Encode it using `MaskedJSONEncoder`.
    3.  Verify that the value "My secret is sensitive_value" under the key "description" is **not masked**, demonstrating value data exposure.