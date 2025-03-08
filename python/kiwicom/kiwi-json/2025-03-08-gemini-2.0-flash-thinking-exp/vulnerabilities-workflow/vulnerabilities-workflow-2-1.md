- Vulnerability Name: Whitelist Bypass Leading to Potential Sensitive Data Exposure
- Description:
    1. An application uses Kiwi JSON's `MaskedJSONEncoder` or `raw_encoder` to mask sensitive data during JSON encoding.
    2. The masking is configured with a whitelist of keys that are *not* masked, such as "public_key" and "booking_token".
    3. An attacker gains control over the input data structure that is being encoded into JSON.
    4. The attacker crafts the input data to include sensitive information under keys that are present in the whitelist (e.g., `"public_key": "attacker_sensitive_data"`).
    5. When Kiwi JSON encodes this data, the values associated with whitelisted keys are *not* masked, even if they contain sensitive information.
    6. This results in the sensitive data being exposed in the JSON output, bypassing the intended data masking.
- Impact: Exposure of sensitive information that was intended to be masked. This could lead to unauthorized access, data breaches, or other security incidents depending on the nature of the exposed data.
- Vulnerability Rank: High
- Currently Implemented Mitigations: None specifically for this type of bypass. The whitelist mechanism itself is implemented as a configuration option.
- Missing Mitigations:
    - Input Validation and Sanitization: The application using Kiwi JSON should validate and sanitize input data *before* encoding to ensure that whitelisted keys are used for their intended purpose and not for carrying sensitive data that should be masked.
    - Principle of Least Privilege for Whitelisting: Carefully review and minimize the whitelist. Only whitelist keys that are genuinely intended to be exposed and are confirmed not to carry sensitive information. Regularly audit the whitelist to ensure it remains appropriate.
    - Consider Alternative Masking Strategies: For highly sensitive applications, keyword-based masking with a whitelist might be insufficient. Consider more robust techniques like data classification and policy-based masking, or data transformation techniques that are less reliant on key names and more focused on the *content* of the data.
- Preconditions:
    - The application uses Kiwi JSON's masking functionality with a whitelist enabled (which is the default behavior when using `mask_dict` or `MaskedJSONEncoder`).
    - An attacker can control or influence the keys of the data being encoded into JSON. This could occur if the JSON data is constructed from user inputs or data sources that are not fully trusted.
    - The application does not perform sufficient input validation or sanitization to prevent the misuse of whitelisted keys for sensitive data.
- Source Code Analysis:
    1. `kw/json/utils.py:mask_dict_factory` and `mask_dict`:
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
        - The `mask_dict` function first checks if the lowercase version of a key is present in the `whitelist`.
        - If `key.lower() not in whitelist` is `False` (meaning the key is in the whitelist), the condition evaluates to `False` regardless of the blacklist check. In this case the value is *not* masked.
        - Only if `key.lower() not in whitelist` is `True` (key is NOT in whitelist), then the blacklist condition `any(word in key.lower() for word in blacklist)` is evaluated.
        - This logic prioritizes the whitelist, ensuring that keys in the whitelist are never masked, which can be exploited if an attacker can control the keys.

    2. `kw/json/encode.py:MaskedJSONEncoder`:
        ```python
        class MaskedJSONEncoder(BaseJSONEncoder):
            def default(self, o):  # pylint: disable=method-hidden
                return default_encoder(o, mask_dict)

            def encode(self, o):
                if isinstance(o, dict):
                    o = mask_dict(o) # Top-level dictionary is masked here
                return super().encode(o)
        ```
        - `MaskedJSONEncoder.encode` explicitly applies `mask_dict` to the top-level dictionary being encoded.
        - `MaskedJSONEncoder.default` uses `default_encoder` with `mask_dict` as the `dict_factory`, ensuring that when objects are converted to dictionaries during encoding (e.g., for custom classes, datatypes), the `mask_dict` is applied to the keys of these dictionaries as well.
        - Despite the masking being applied at multiple levels, the core vulnerability lies in the logic of `mask_dict` which unconditionally bypasses masking for whitelisted keys.

- Security Test Case:
    1. **Setup:**  Use the provided `test_flask.py` as a base, or create a simple Flask application that utilizes `JSONExtension`. Ensure the default whitelist is active (which it is by default).
    2. **Craft Malicious Input:** Construct a Python dictionary where a sensitive value (e.g., `"this_is_secret_data"`) is associated with a key that is part of the default whitelist, such as `"public_key"`.
        ```python
        sensitive_data = {"public_key": "this_is_secret_data"}
        ```
    3. **Encode to JSON using Flask's json:**  Use Flask's `json.dumps` within an application context. This will automatically use the `MaskedJSONEncoder` due to the `JSONExtension`.
        ```python
        from flask import Flask, json
        from kw.json.flask import JSONExtension

        app = Flask(__name__)
        JSONExtension(app)

        sensitive_data = {"public_key": "this_is_secret_data"}

        with app.app_context():
            json_output = json.dumps(sensitive_data)
        ```
    4. **Analyze the JSON Output:** Examine the `json_output` string.
        - **Verify Bypass:** Confirm that the value associated with the whitelisted key `"public_key"` is present in the JSON output in its original, unmasked form: `'"public_key": "this_is_secret_data"'` should be present.
        - **Verify No Masking Placeholder:** Ensure that the masking placeholder string (default: `"-- MASKED --"`) is *not* present in the value associated with `"public_key"`.
    5. **Expected Test Result:** The test should demonstrate that the sensitive data under the whitelisted key is not masked in the JSON output, thus proving the whitelist bypass vulnerability.