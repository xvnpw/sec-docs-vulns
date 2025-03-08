- Vulnerability Name: Inadequate Data Masking - Value Data Exposure
- Description: The Kiwi JSON library provides data masking functionality based on dictionary keys. However, it does not inspect or mask values within the dictionary. If sensitive information is placed in the values of a dictionary under keys that are not blacklisted, this information will be serialized in JSON format without masking. An attacker observing the JSON output can then access this sensitive information.
- Impact: Exposure of sensitive information that was intended to be masked by the application using Kiwi JSON. This could include passwords, tokens, or other confidential data if developers mistakenly place them in dictionary values assuming the library's masking will protect them regardless of key names.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations: Key-based masking using a blacklist and whitelist approach via `mask_dict` and `mask_dict_factory`. This is implemented in `kw/json/utils.py`.
- Missing Mitigations: Value-based masking. The library should offer options to inspect and mask values based on criteria such as keywords, regular expressions, or data types. This would provide a more comprehensive data masking solution.
- Preconditions:
    - The application uses Kiwi JSON's masking functionality (`MaskedJSONEncoder` or `default_encoder` with `mask_dict`).
    - Sensitive data is present in the values of dictionaries being serialized into JSON.
    - The keys associated with these sensitive values are not blacklisted or are whitelisted.
    - An attacker has the ability to observe the JSON output, for example, by intercepting network traffic, accessing logs, or through other information leakage channels.
- Source Code Analysis:
    - File: `/code/kw/json/utils.py`
    - Function: `mask_dict(pairs)`
    ```python
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
                if key.lower() not in whitelist
                and any(word in key.lower() for word in blacklist)
                else value
            )
            for key, value in items
        }
    ```
    - The `mask_dict` function iterates through the key-value pairs of the input dictionary.
    - For each pair, it checks if the `key` (converted to lowercase) is in the blacklist and not in the whitelist.
    - If this condition is met, the `value` is replaced with a placeholder (`DEFAULT_PLACEHOLDER` which is "-- MASKED --").
    - **Crucially, the `value` itself is never inspected or analyzed for sensitive content.** The masking decision is solely based on the `key`.
    - Example:
        ```python
        from kw.json.utils import mask_dict

        data = {"public_key": "public_value", "comment": "This is a secret token: sensitive_token"}
        masked_data = mask_dict(data)
        print(masked_data)
        # Output: {'public_key': 'public_value', 'comment': 'This is a secret token: sensitive_token'}
        ```
        As shown in the example, the value associated with the "comment" key, which contains "secret token", is not masked because the key "comment" is not in the blacklist, despite the value containing sensitive terms.

- Security Test Case:
    1.  Create a Python test script.
    2.  Import `dumps` and `MaskedJSONEncoder` from `kw.json`.
    3.  Define a dictionary `sensitive_data` like this:
        ```python
        sensitive_data = {"non_sensitive_key": "This is public", "description": "My secret password is: P@$$wOrd"}
        ```
        Here, the key "description" is not intended to be blacklisted by default, but its value contains sensitive information "secret password".
    4.  Serialize this dictionary using `dumps` with `MaskedJSONEncoder`:
        ```python
        from kw.json import dumps, MaskedJSONEncoder

        sensitive_data = {"non_sensitive_key": "This is public", "description": "My secret password is: P@$$wOrd"}
        json_output = dumps(sensitive_data, cls=MaskedJSONEncoder)
        print(json_output)
        ```
    5.  **Expected Result:** The output JSON string will be:
        ```json
        {"non_sensitive_key": "This is public", "description": "My secret password is: P@$$wOrd"}
        ```
        Observe that the value associated with the key "description", including "My secret password is: P@$$wOrd", is **not masked**. This demonstrates that the value-based sensitive data is exposed, confirming the vulnerability.