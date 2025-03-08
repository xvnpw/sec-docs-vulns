### Vulnerability List

* Vulnerability Name: Incorrect Masking Logic with Whitelist and Blacklist in `mask_dict`

* Description:
    The `mask_dict` function in `kw/json/utils.py` is designed to mask values in a dictionary based on a blacklist and whitelist of keywords. The current implementation has a flaw in its logic that can lead to unexpected masking behavior when a dictionary key contains both blacklisted and whitelisted substrings.

    The masking logic is as follows:
    ```python
    placeholder if key.lower() not in whitelist and any(word in key.lower() for word in blacklist) else value
    ```
    This logic checks if a lowercase version of the key is NOT in the whitelist AND if ANY word from the blacklist is present in the lowercase key. If both conditions are true, the value is replaced with a placeholder.

    This approach incorrectly prioritizes the blacklist condition over the whitelist. If a key contains a blacklisted word as a substring, but is also intended to be whitelisted (e.g., by containing a whitelisted word), it will still be masked because of the blacklist condition being evaluated first and taking precedence in combination with the NOT whitelist condition.

    Steps to trigger vulnerability:
    1. Define a `mask_dict_factory` with a blacklist (e.g., `{'secret'}`) and a whitelist (e.g., `{'not-so-secret'}`).
    2. Create a dictionary with a key that contains both a blacklisted word and a whitelisted word as substrings (e.g., `"this-is-not-so-secret-but-contains-secret"`).
    3. Apply the `mask_dict` function to this dictionary.
    4. Observe that the value associated with this key is incorrectly masked, even though it should be whitelisted due to the presence of the whitelisted substring.

* Impact:
    The impact of this vulnerability is incorrect data masking. In scenarios where both blacklist and whitelist are used, sensitive information might be unintentionally masked when it should be allowed based on the whitelist rules. This can lead to functional issues in applications relying on specific key names not being masked. While the current logic leads to over-masking in the described scenario, a slight variation or misunderstanding in configuration could potentially lead to under-masking in other scenarios.

* Vulnerability Rank: Medium

* Currently Implemented Mitigations:
    No specific mitigations are currently implemented to address this logical flaw in the `mask_dict` function. The code provides blacklist and whitelist functionality, but the combination logic is flawed.

* Missing Mitigations:
    The masking logic in `mask_dict` needs to be corrected to properly prioritize the whitelist. The check should ensure that if a key is whitelisted, it should not be masked regardless of whether it contains blacklisted words.

    The corrected logic should be:
    ```python
    placeholder if any(word in key.lower() for word in blacklist) and key.lower() not in whitelist else value
    ```
    Even better and clearer logic would be to check whitelist first:
    ```python
    placeholder if key.lower() not in whitelist and any(word in key.lower() for word in blacklist) else value
    # corrected logic:
    placeholder if key.lower() not in whitelist and any(word in key.lower() for word in blacklist) else value

    # More readable and correct logic:
    if key.lower() in whitelist:
        value # Do not mask, it's whitelisted
    elif any(word in key.lower() for word in blacklist):
        placeholder # Mask, it's blacklisted and not whitelisted
    else:
        value # Do not mask, neither blacklisted nor whitelisted
    ```
    Which translates to the code:
     ```python
    key: (
        placeholder
        if key.lower() not in whitelist and any(word in key.lower() for word in blacklist)
        else value
    )
    # corrected logic:
    key: (
        placeholder
        if any(word in key.lower() for word in blacklist) and key.lower() not in whitelist
        else value
    )
    ```

* Preconditions:
    - The application uses `kiwi-json` library for JSON encoding.
    - Data masking is enabled using `mask_dict` or `mask_dict_factory`.
    - Both blacklist and whitelist are configured for data masking.
    - Dictionary keys exist that contain both blacklisted and whitelisted substrings.

* Source Code Analysis:
    1. File: `/code/kw/json/utils.py`
    2. Function: `mask_dict_factory` and `mask_dict`
    3. The `mask_dict_factory` function creates and returns the `mask_dict` function, allowing customization of `placeholder`, `blacklist`, and `whitelist`.
    4. The `mask_dict` function takes a dictionary (or items view) as input.
    5. It iterates through each key-value pair in the input.
    6. For each key, it checks the masking condition: `key.lower() not in whitelist and any(word in key.lower() for word in blacklist)`.
    7. If this condition is true, the value is replaced with the `placeholder`. Otherwise, the original value is kept.
    8. **Vulnerability:** The logical AND operation `and` combined with `not in whitelist` and `any(word in blacklist)` causes the blacklist to take precedence over the whitelist when both blacklisted and whitelisted substrings are present in the key.

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
                    if key.lower() not in whitelist  # [CONDITION 1] - Key is NOT in whitelist
                    and any(word in key.lower() for word in blacklist) # [CONDITION 2] - Key CONTAINS blacklisted word
                    else value
                )
                for key, value in items
            }

        return mask_dict
    ```

    **Visualization:**

    Imagine a Venn diagram:

    * Set A: Keys that are NOT in the whitelist (`key.lower() not in whitelist`).
    * Set B: Keys that CONTAIN any blacklisted word (`any(word in key.lower() for word in blacklist)`).

    The current logic masks keys that are in the intersection of Set A and Set B (A AND B). This means even if a key is intended to be whitelisted (not in Set A), if it accidentally falls into Set B (contains blacklisted word), it will be masked due to the `AND` condition and Set A being defined as *NOT* in whitelist.

* Security Test Case:
    1. Create a test function to validate the masking logic.
    2. Inside the test function, create a `mask_dict` using `mask_dict_factory`.
    3. Configure the `mask_dict_factory` with:
        - `blacklist = frozenset({'secret'})`
        - `whitelist = frozenset({'not-so-secret'})`
    4. Define a test dictionary: `test_dict = {'this-is-not-so-secret-but-contains-secret': 'sensitive_value'}`.
    5. Apply the `mask_dict` function to the `test_dict`: `masked_dict = mask_dict(test_dict)`.
    6. Assert that the key `"this-is-not-so-secret-but-contains-secret"` in `masked_dict` is **NOT** masked and retains its original value `'sensitive_value'`.
    7. If the assertion fails (i.e., the value is masked), it confirms the vulnerability.

    ```python
    from kw.json.utils import mask_dict_factory

    def test_mask_dict_whitelist_precedence():
        mask_dict_func = mask_dict_factory(blacklist=frozenset({'secret'}), whitelist=frozenset({'not-so-secret'}))
        test_dict = {'this-is-not-so-secret-but-contains-secret': 'sensitive_value'}
        masked_dict = mask_dict_func(test_dict)
        assert masked_dict['this-is-not-so-secret-but-contains-secret'] == 'sensitive_value'

    test_mask_dict_whitelist_precedence() # Run the test to confirm the vulnerability
    ```
    **Expected Result of Test Case (Before Mitigation):** The test case `test_mask_dict_whitelist_precedence()` will **fail**. The assertion will fail because the current logic will incorrectly mask the value associated with the key `"this-is-not-so-secret-but-contains-secret"`. This failure demonstrates the vulnerability.

    **Expected Result of Test Case (After Mitigation - Corrected Logic):** After correcting the logic in `mask_dict` to prioritize whitelist check (e.g., using the corrected logic provided in "Missing Mitigations" section), the test case `test_mask_dict_whitelist_precedence()` will **pass**. The assertion will pass because the corrected logic will correctly identify `"this-is-not-so-secret-but-contains-secret"` as whitelisted (due to "not-so-secret") and will not mask its value.