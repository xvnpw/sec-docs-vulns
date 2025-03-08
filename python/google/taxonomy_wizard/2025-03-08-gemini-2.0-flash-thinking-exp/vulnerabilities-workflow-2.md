## Combined Vulnerability List

The following vulnerabilities have been identified in the Taxonomy Wizard project. These vulnerabilities are ranked as high or critical severity and pose a realistic threat to the security of the application.

### SQL Injection Vulnerability due to Lack of Input Validation and Unsafe Template Generation

- Description:
    1. An attacker with edit access to the Google Admin Sheet can inject malicious content by modifying configuration data. This can be achieved through various fields in "TaxonomyField", "TaxonomySpec", or "TaxonomyDimension" tabs.
    2. Specifically, the 'validation_query_template' within the TaxonomyDimension configuration is a critical entry point. An attacker can inject malicious Jinja syntax or SQL code into this template.
    3. The Configurator Cloud Function fetches configuration data from the Google Admin Sheet, including the unsanitized 'validation_query_template'.
    4. The Configurator Cloud Function uses JinjaRenderer to process the 'validation_query_template' and generate SQL queries without proper sanitization or validation of the template content.
    5. This generated SQL query, potentially containing malicious SQL code injected via the Google Sheet, is stored in BigQuery.
    6. When the Validator Cloud Function is triggered to validate entity names, it retrieves the 'validation_query_template' from BigQuery.
    7. The Validator Cloud Function inserts user-provided entity names into the retrieved template using string formatting (Jinja templating), which can further amplify the SQL injection vulnerability if entity names are also not sanitized.
    8. Finally, the Validator Cloud Function executes the constructed SQL query against BigQuery, leading to potential SQL injection if malicious code was injected in previous steps.

- Impact:
    - **Critical Impact:**
        - **Unauthorized Data Access (Data Breach):** Attackers can extract sensitive data from BigQuery tables accessible by the Validator Cloud Function's service account. This includes potentially exfiltrating data from any table within the dataset.
        - **Data Manipulation:** Attackers can modify or delete data within BigQuery if the Validator or Configurator Cloud Function's service account has write/delete permissions. This could lead to data corruption or disruption of the Taxonomy Wizard's functionality.
        - **Privilege Escalation (Potential):** Depending on the service account permissions, attackers might be able to escalate privileges within the BigQuery environment or access other Google Cloud resources.
        - **Data Integrity Issues:** Malicious validation rules can lead to misclassification or incorrect validation of advertising campaign names, potentially disrupting advertising campaigns in connected Google advertising products.

- Vulnerability Rank: **Critical**

- Currently Implemented Mitigations:
    - **Partial Parameterized Queries:** Parameterized queries are used in some parts of the Validator Cloud Function (e.g., for entity names in the final query execution), but this does not prevent SQL injection originating from the unsanitized 'validation_query_template'.
    - **Cloud Function Authentication:** Cloud Functions are deployed with `--no-allow-unauthenticated`, intending to restrict access to authenticated callers.
    - **IAM Access Control:** Google Cloud IAM is used to control access to Cloud Functions and Google Admin Sheet, limiting access to authorized users.
    - **Private Admin Sheet (Intended):** The Admin Sheet is intended to be private and accessible only to authorized users within the organization.

- Missing Mitigations:
    - **Input Sanitization for Google Sheet Data (Configurator):** Implement robust input validation and sanitization in the Configurator Cloud Function for all data read from the Google Admin Sheet, especially for fields like 'validation_query_template', 'end_delimiter', and other configuration parameters. This should include escaping Jinja syntax, SQL keywords, and regex metacharacters, or using secure input validation libraries.
    - **Secure Template Rendering (Configurator):** Use a safer templating mechanism that prevents code injection or strictly sanitize inputs before rendering templates. Consider using parameterized queries or ORM-based query construction instead of string-based template rendering for SQL queries.
    - **Input Sanitization for Entity Names (Validator):** Sanitize entity names in the Validator Cloud Function before inserting them into validation queries, even though parameterized queries are used for entity names, to provide defense in depth.
    - **Principle of Least Privilege (IAM):** Enforce the principle of least privilege for both Google Admin Sheet access and service account permissions for Configurator and Validator Cloud Functions. Grant only the minimum necessary permissions required for each component to function. Regularly review and audit IAM policies.
    - **Regular Security Audits:** Implement scheduled security audits and reviews of the Admin Sheet configuration and Cloud Function code to detect and revert any unauthorized or malicious modifications and identify potential vulnerabilities.

- Preconditions:
    - An attacker gains edit access to the Google Admin Sheet.
    - The Configurator Cloud Function processes the maliciously modified Google Admin Sheet data and updates BigQuery configuration.
    - The Validator Cloud Function is triggered to perform validation using the compromised configuration.

- Source Code Analysis:
    1. **Configurator Cloud Function (`/code/resources/python_cloud_functions/configurator/main.py`, `/code/resources/python_cloud_functions/configurator/taxonomy.py`, `/code/resources/python_cloud_functions/configurator/jinja_renderer.py`)**:
        - The `create_taxonomy_spec_set` function in `main.py` and related functions process data from the Google Sheet.
        - The `Specification` class in `taxonomy.py` uses `JinjaRenderer` to create `validation_query_template` from templates and data from Google Sheet.
        - `JinjaRenderer` in `jinja_renderer.py` loads and renders templates using `jinja2.Environment` with `autoescape` enabled for HTML/XML, but not for SQL or Jinja syntax itself.
        - The `validation_query_template` originates from the Google Sheet and is passed to Jinja renderer without sanitization, allowing injection.

    2. **Validator Cloud Function (`/code/resources/python_cloud_functions/validator/validators/validator.py`)**:
        - `BaseValidator.fetch_validation_results` fetches `validation_query_template` from BigQuery.
        - `RawJsonValidator.post_process_query_template` and `ProductValidator.post_process_query_template` replace `@entity_names` in the template.
        - The fetched and processed `validation_query_template`, which can contain injected SQL, is executed against BigQuery.
        - Parameterized queries are used for `@entity_names`, but the main vulnerability is the malicious template itself loaded from BigQuery, which originated from unsanitized Google Sheet input.

    3. **Visualization**:
        ```mermaid
        graph LR
            A[Google Admin Sheet (Attacker Controlled)] --> B[Configurator Cloud Function];
            B -- Unsanitized 'validation_query_template' --> C[BigQuery (specifications table)];
            C --> D[Validator Cloud Function];
            D -- Executes Malicious SQL Template --> E[BigQuery (Data Access/Manipulation)];
        ```

- Security Test Case:
    1. **Precondition:** Deploy Configurator and Validator Cloud Functions and gain edit access to the Admin Google Sheet.
    2. **Step 1:** Open the Admin Google Sheet and navigate to the 'TaxonomyDimension' sheet.
    3. **Step 2:** Locate or create a 'TaxonomyDimension' and modify its 'validation_query_template' to inject malicious SQL. For example: `SELECT name, 'ATTACK_TRIGGERED' as validation_message FROM \`your-project-id.your_dataset.your_table\` WHERE name IN UNNEST(@entity_names) UNION ALL SELECT table_name, 'INJECTED' FROM \`your-project-id.your_dataset.INFORMATION_SCHEMA.TABLES\` LIMIT 1;` (Replace `your-project-id` and `your_dataset`).
    4. **Step 3:** Trigger the Configurator Cloud Function to apply changes (e.g., using 'Overwrite Taxonomy Data' button in Admin Sheet).
    5. **Step 4:** Trigger the Validator Cloud Function with a validation request (e.g., using the validator plugin in Google Sheets or by sending a direct request).
    6. **Step 5:** Examine the validation results. Observe if all validations return 'ATTACK_TRIGGERED' and if there are any errors related to accessing `INFORMATION_SCHEMA.TABLES` (if the service account has permissions, you might see table names in results, otherwise errors).
    7. **Step 6:** Check BigQuery logs for executed queries to confirm the injected SQL was executed.
    8. **Expected Result:** Validation results and BigQuery logs should confirm the execution of injected SQL, demonstrating the SQL injection vulnerability.


### Regular Expression Injection in Taxonomy Validation Rules

- Description:
    1. An attacker with edit access to the Google Admin Sheet can modify taxonomy rules in the 'TaxonomyDimension' sheet.
    2. By manipulating the 'end_delimiter' field, the attacker can inject malicious regex characters or operators into the regular expression used for campaign name validation.
    3. The Configurator Cloud Function reads this modified 'end_delimiter' without sanitization.
    4. The Configurator Cloud Function constructs a BigQuery validation query template using the injected regex from 'end_delimiter'.
    5. When the Validator Cloud Function executes this query, the injected regex can alter the intended validation logic, potentially bypassing it. For example, an injected `)+` as 'end_delimiter' could change the matching behavior of the regex.

- Impact:
    - **High Impact:**
        - **Bypassing Validation:** Attackers can craft campaign names that should be invalid according to the intended taxonomy rules but are incorrectly validated as valid due to the regex injection.
        - **Data Integrity Issues:** The system's ability to enforce naming conventions is compromised, leading to inconsistencies in advertising campaign names.

- Vulnerability Rank: **High**

- Currently Implemented Mitigations:
    - **None:** There is no input sanitization or validation for the 'end_delimiter' field from the Google Admin Sheet to prevent regex injection. `re.escape` is used on the delimiter itself, but not to prevent injection of regex operators within or around the delimiter in the regex construction logic.

- Missing Mitigations:
    - **Input Sanitization and Validation for 'end_delimiter':** Sanitize and validate the 'end_delimiter' field in the Configurator Cloud Function to prevent injection of malicious regex characters. Implement a whitelist of allowed characters or strict format validation.
    - **Regular Expression Testing and Escaping:** Test the constructed regex for safety and escape any special regex characters in 'end_delimiter' if literal interpretation is intended. If regex operators are needed, strictly control and validate their usage.
    - **Principle of Least Privilege (Admin Sheet Access):** Limit edit access to the Google Admin Sheet to authorized personnel.
    - **Security Audits of Taxonomy Rules:** Regularly audit and review taxonomy rules in the Admin Sheet for suspicious modifications.

- Preconditions:
    - Attacker has edit access to the Google Admin Sheet.
    - Configurator Cloud Function is deployed and uses the manipulated Admin Sheet.
    - Validator Cloud Function is deployed and uses the generated validation rules.

- Source Code Analysis:
    1. **Configurator Cloud Function (`/code/resources/python_cloud_functions/configurator/taxonomy.py`, `/code/resources/python_cloud_functions/configurator/main.py`)**:
        - `Dimension` class and `create_dimension` function use `json['end_delimiter']` from Google Sheet to construct `regex_match_expression`.
        - While `re.escape(json['end_delimiter'])` is used, it escapes the delimiter itself, not regex operators potentially injected as or around the delimiter. The regex structure `f'[^{escaped_end_delimiter}]*?){escaped_end_delimiter}'` is still vulnerable to injection if malicious regex characters are used in `end_delimiter`.

    2. **Jinja Templates and Validator (`/code/resources/python_cloud_functions/configurator/jinja_templates/delimited_validator.sql`, `/code/resources/python_cloud_functions/validator/validators/validator.py`)**:
        - Jinja templates embed the regex expressions into SQL queries.
        - Validator Cloud Function executes these SQL queries, including the potentially injected regex.

- Security Test Case:
    1. **Pre-requisites:** Deploy Configurator and Validator, Admin Sheet access.
    2. **Step 1:** Open Admin Sheet, navigate to 'TaxonomyDimension'.
    3. **Step 2:** Find a dimension rule and modify 'end_delimiter' to inject regex, e.g., `)+`.
    4. **Step 3:** Run Configurator Cloud Function to apply changes.
    5. **Step 4:** Prepare test campaign names, including names that should be invalid but might bypass validation with injected regex.
    6. **Step 5:** Use Validator plugin or call Validator Cloud Function with test names and modified spec.
    7. **Step 6:** Observe validation results. Check if names that should be invalid are now valid.
    8. **Expected Result:** Campaign names that should be invalid are incorrectly validated as valid, demonstrating regex injection bypass.


### Insecure Access to Configurator and Validator Cloud Functions

- Description:
    1. Configurator and Validator Cloud Functions are deployed with `--no-allow-unauthenticated`, which should restrict access to authenticated requests.
    2. Deployment scripts configure service accounts and Cloud Scheduler for invocation.
    3. However, `handle_request` functions in `configurator/main.py` and `validator/main.py` lack explicit authentication and authorization checks within the code itself.
    4. If the Cloud Function's IAM policy is misconfigured or allows public access, an attacker could bypass intended authentication and directly invoke these functions by sending HTTP requests to the function URLs.

- Impact:
    - **High Impact:**
        - **Unauthorized Configurator Access:** Attackers can manipulate taxonomy configurations, inject malicious rules, and bypass taxonomy enforcement.
        - **Unauthorized Validator Access:** Attackers can trigger validation processes, bypass validation checks, manipulate validation results, and potentially exploit vulnerabilities in validation logic.

- Vulnerability Rank: **High**

- Currently Implemented Mitigations:
    - `--no-allow-unauthenticated` flag during deployment.
    - Service accounts and OIDC for Cloud Scheduler are configured.
    - Google Cloud IAM controls access to Cloud Functions.

- Missing Mitigations:
    - **Explicit Authentication and Authorization Checks in Code:** Implement checks within `handle_request` functions to verify caller identity and permissions, regardless of IAM policy.
    - **Robust Input Validation in `handle_request`:** Implement input validation and sanitization in `handle_request` to prevent injection attacks even if authentication is bypassed.
    - **Regular IAM Policy Audits:** Regularly audit IAM policies on Cloud Functions to ensure correct configuration and prevent overly permissive access.

- Preconditions:
    - Taxonomy Wizard is deployed.
    - IAM policy for Cloud Functions is misconfigured to allow unintended access.
    - Attacker discovers Cloud Function URLs.

- Source Code Analysis:
    1. **Deployment Scripts (`deploy.sh`, `resources/python_cloud_functions/*/deploy.sh`)**: Use `--no-allow-unauthenticated` for deployment, setting basic IAM restriction.
    2. **Cloud Function Code (`resources/python_cloud_functions/validator/main.py`, `resources/python_cloud_functions/configurator/main.py`)**:
        - `handle_request` functions are entry points but lack any code for authentication or authorization checks. They directly process request parameters and payload.

    3. **Visualization**:
        ```mermaid
        graph LR
            A[External Attacker] --> B{Cloud Function URL};
            B --> C[Cloud Function Endpoint];
            C --> D{handle_request Function (No Auth Check)};
            D --> E[Process Request (Vulnerable if IAM misconfigured)];
        ```

- Security Test Case:
    1. **Step 1:** Deploy Taxonomy Wizard using `deploy.sh`.
    2. **Step 2:** Obtain Configurator and Validator Cloud Function Endpoint URLs.
    3. **Step 3:** Send a POST request to Configurator URL with `action=overwrite` and minimal payload, without authentication headers.
    4. **Step 4:** Observe response. A `200 OK` response with success message indicates unauthenticated access.
    5. **Step 5:** Send a GET request to Validator URL with `action=list_specs` and minimal parameters, without authentication headers.
    6. **Step 6:** Observe response. A `200 OK` response (even with empty list) indicates unauthenticated access.
    7. **Expected Result:** Successful requests to Cloud Functions without authentication confirm insecure access due to lack of explicit authentication checks in code and potential IAM misconfiguration vulnerability.