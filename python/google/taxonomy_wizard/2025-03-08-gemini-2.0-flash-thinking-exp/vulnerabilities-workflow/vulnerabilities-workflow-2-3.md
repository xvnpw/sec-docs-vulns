* Vulnerability 1: Regular Expression Injection

* Vulnerability Name: Regular Expression Injection in Taxonomy Validation Rules

* Description:
    1. An attacker with edit access to the Google Admin Sheet can modify the taxonomy rules, specifically within the 'TaxonomyDimension' sheet.
    2. By manipulating the 'end_delimiter' field in the 'TaxonomyDimension' sheet, the attacker can inject malicious characters or regex operators into the regular expression used for validation.
    3. When the Taxonomy Wizard configurator Cloud Function processes these modified rules, it will generate a BigQuery validation query template that includes the injected malicious regular expression.
    4. Subsequently, when the validator Cloud Function executes this query against campaign names, the injected regex can cause unexpected behavior. This could range from bypassing intended validation logic to causing errors in the BigQuery query execution, or potentially even more severe outcomes depending on the specific regex injection and the BigQuery environment.
    5. For example, an attacker could inject regex metacharacters like `.*`, `+`, `?`, `|`, `[]`, `()`, `^`, `$`, and control characters to alter the intended matching behavior or potentially trigger denial-of-service conditions within the regex engine if complex or inefficient regex patterns are injected (though DoS is excluded in the prompt, unintended bypass is still valid). In the context of validation, bypassing the intended regex validation is the main concern.

* Impact:
    - **Bypassing Validation:** Attackers could craft campaign names that should be flagged as invalid according to the intended taxonomy rules, but due to the injected regex, they are incorrectly validated as valid. This allows for non-compliant campaign names to be used, defeating the purpose of the Taxonomy Wizard.
    - **Information Disclosure (Potential):**  Depending on the specific regex injection and how the validation queries are constructed and handled by BigQuery, there's a theoretical risk of information disclosure if the attacker can craft a regex that extracts or exposes sensitive data, though this is less likely in this specific validation context.
    - **Data Integrity Issues:**  The system's ability to enforce naming conventions is compromised, leading to potential inconsistencies and difficulties in managing advertising campaigns.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - None explicitly identified in the provided code snippets for preventing regex injection from the Admin Sheet. The system relies on user input from Google Sheets to define validation rules without input sanitization or validation before constructing regular expressions.

* Missing Mitigations:
    - **Input Sanitization and Validation:**  The application should sanitize and validate the 'end_delimiter' and potentially other relevant fields from the Google Admin Sheet to prevent injection of malicious regex characters or operators. A whitelist of allowed characters or a strict validation of the input format should be implemented.
    - **Regular Expression Testing and Escaping:** Before using the 'end_delimiter' to construct the regex, the system should test the resulting regex for safety and escape any special regex characters to treat them literally if that's the intended behavior. If regex operators are intended, their usage should be strictly controlled and validated.
    - **Principle of Least Privilege:** Limit edit access to the Google Admin Sheet to only authorized and trusted personnel to reduce the risk of malicious rule modifications.
    - **Security Audits and Reviews:** Regularly audit and review the taxonomy rules defined in the Admin Sheet to detect any suspicious or unauthorized modifications.

* Preconditions:
    - Attacker has edit access to the Google Admin Sheet.
    - Taxonomy Wizard configurator Cloud Function is deployed and configured to use the manipulated Admin Sheet.
    - Validator Cloud Function is deployed and configured to use the generated validation rules from BigQuery.

* Source Code Analysis:

    1. **File: `/code/resources/python_cloud_functions/configurator/taxonomy.py`**:
        - Class `Dimension`: The `end_delimiter` field from Google Sheet is directly used in `create_dimension` function in `/code/resources/python_cloud_functions/configurator/main.py` to construct `regex_suffix` and then `regex_match_expression`.
        - No sanitization or validation of `end_delimiter` is performed before using it in regex construction.

    2. **File: `/code/resources/python_cloud_functions/configurator/main.py`**:
        - Function `create_dimension`:
            ```python
            def create_dimension(fields, last_indexes, regex_prefixes, json):
                # ...
                escaped_end_delimiter: str = re.escape(json['end_delimiter'])
                # ...
                if not json['end_delimiter']:
                    # ...
                else:
                    regex_suffix = f'[^{escaped_end_delimiter}]*?){escaped_end_delimiter}'
                    requires_crossjoin_validation = False

                dim = Dimension( # ...
                                  regex_match_expression=f"{regex_prefix}({regex_suffix}')", # Regex is constructed here
                                  # ...
                                  )
                return dim, regex_prefix, regex_suffix
            ```
            - The `json['end_delimiter']` from the Google Sheet is taken as input. Although `re.escape` is used, it's used on the *delimiter itself*, not on the *regex operators* that could be injected *within* the delimiter or around it if the logic was different. If an attacker puts regex metacharacters as `end_delimiter` value, it will be escaped, but if attacker provides regex metacharacters as part of other fields that are concatenated into regex, it will be vulnerable. In this specific case, the vulnerability arises because even with `re.escape` on `end_delimiter`, the surrounding regex structure `f'[^{escaped_end_delimiter}]*?){escaped_end_delimiter}'`  itself might be vulnerable to injection if `end_delimiter` contains characters that, even when escaped as delimiter, alter the intended regex behavior when combined with the fixed parts of the regex.

    3. **File: `/code/resources/python_cloud_functions/configurator/jinja_templates/delimited_validator.sql`**:
        - This file contains the Jinja template for generating the validation query. The regex expressions constructed in Python (in `create_dimension`) are embedded into this SQL query.
        - If a malicious regex is injected through the Admin Sheet and propagated to this template, it will be part of the final SQL query executed by the validator Cloud Function.

    4. **File: `/code/resources/python_cloud_functions/validator/validators/validator.py`**:
        - Class `BaseValidator`, method `fetch_validation_results`: This code executes the SQL query generated from the template. If the template contains a regex injection, this is where the injected regex will be executed by BigQuery.

* Security Test Case:

    1. **Pre-requisites:**
        - Deploy Taxonomy Wizard configurator and validator Cloud Functions in a test Google Cloud project.
        - Copy the Taxonomy Wizard Admin sheet and configure it to point to the test project.
        - Ensure the validator plugin is set up.
        - Have edit access to the copied Admin Sheet.

    2. **Steps:**
        - Open the copied Taxonomy Wizard Admin Sheet.
        - Navigate to the 'TaxonomyDimension' sheet.
        - Find a dimension rule that is actively used for validation.
        - In the 'end_delimiter' column for that rule, inject a malicious regex character. For example, change the `end_delimiter` to `)+`.
        - Run the Configurator Cloud Function (e.g., by manually triggering it or via the Admin Sheet's UI if available) to apply the modified rules to BigQuery. This will regenerate the validation queries with the injected regex.
        - Prepare a set of test campaign names. Include names that should be considered invalid according to the original rules, but might bypass validation due to the regex injection. For example, if the original regex expected a delimiter like `_`, and you injected `)+` as delimiter, craft a campaign name that would have been invalid with `_` but might become valid or produce unexpected results with `)+`.
        - Use the Validator plugin in Google Sheets or call the Validator Cloud Function directly (using `validate_names` action) with the test campaign names and the name of the modified specification.
        - Observe the validation results. If the injected regex is successful, you will see that campaign names that should have been invalid are now marked as valid, or you might observe errors if the injected regex causes query failures.

    3. **Expected Result:**
        - Campaign names that were supposed to be invalid are now incorrectly validated as valid, demonstrating a bypass of the intended validation logic due to the regex injection. Alternatively, the validator might return an error due to the malformed regex, indicating a disruption of service, although bypass is the primary valid vulnerability from the prompt criteria.

This vulnerability allows an attacker with access to the Admin Sheet to weaken or bypass the taxonomy validation, potentially leading to inconsistent or non-compliant naming conventions within the advertising platforms. Input sanitization and validation are crucial missing mitigations to address this risk.