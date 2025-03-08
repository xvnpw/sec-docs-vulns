- Vulnerability Name: Lack of Input Validation in Configurator Cloud Function
  - Description:
    1. An attacker gains unauthorized access to the Google Admin Sheet. This could be achieved through phishing, social engineering, or exploiting misconfigured sharing settings on the Google Sheet.
    2. The attacker modifies the "TaxonomyField", "TaxonomySpec", or "TaxonomyDimension" tabs in the Google Admin Sheet. They inject malicious data, such as crafted SQL queries within the validation query templates, or manipulated parameters for data retrieval from advertising platforms.
    3. The Configurator Cloud Function is triggered (e.g., manually or via a scheduled event).
    4. The Configurator Cloud Function reads the data from the Google Admin Sheet without proper input validation and sanitization.
    5. The malicious data from the Google Admin Sheet is used to create or update BigQuery tables and views, including validation query templates in the `specifications` table.
  - Impact:
    - **Data Manipulation:** Malicious validation rules can lead to misclassification or incorrect validation of advertising campaign names, potentially disrupting or manipulating advertising campaigns within connected Google advertising products when the validator is applied.
    - **Information Disclosure:** If the injected SQL queries are crafted to extract data from BigQuery tables beyond the intended scope, it could lead to unauthorized information disclosure.
    - **Privilege Escalation (Potentially):** Depending on the permissions of the service account used by the Validator Cloud Function, a carefully crafted SQL injection might be used to attempt to elevate privileges or access resources beyond its intended scope.
  - Vulnerability Rank: High
  - Currently Implemented Mitigations:
    - The project uses Google Cloud Functions, which are secured by Google Cloud IAM for access control and authentication.
    - The Cloud Functions are deployed with `--no-allow-unauthenticated`, which restricts access to authenticated callers.
    - The Admin Sheet is intended to be private and accessible only to authorized users within the organization.
  - Missing Mitigations:
    - **Input Validation and Sanitization in Configurator:** The Configurator Cloud Function lacks input validation and sanitization for data read from the Google Admin Sheet. This includes validating data types, allowed values, and sanitizing strings to prevent injection attacks (e.g., SQL injection).
    - **Principle of Least Privilege for Admin Sheet Access:**  Clear documentation and enforcement of the principle of least privilege for access to the Google Admin Sheet. Regularly review and restrict access to only necessary personnel.
    - **Regular Security Audits of Admin Sheet Configuration:** Implement scheduled reviews and audits of the Admin Sheet configuration to detect and revert any unauthorized or malicious modifications.
  - Preconditions:
    - An attacker gains unauthorized access to the Google Admin Sheet.
    - The Configurator Cloud Function is triggered after the Admin Sheet has been maliciously modified.
  - Source Code Analysis:
    - File: `/code/resources/python_cloud_functions/configurator/main.py`
    - The `handle_request` function in `main.py` receives data from the request and passes it to `create_objects` function.
    - The `create_objects` function calls `get_json_objects` to extract data arrays from the request payload without any validation.
    - The extracted data arrays are then directly used in functions like `create_taxonomy_fields`, `create_taxonomy_dimensions`, and `create_taxonomy_spec_set` to create objects and push them to BigQuery.
    - For example, in `create_taxonomy_dimensions`, the code iterates through `dimensions_json` and directly uses values like `json['prefix_index']`, `json['end_delimiter']`, and `json['taxonomy_spec_name']` without validation to construct SQL regex and other parameters.
    - Similarly, in `create_taxonomy_spec_set`, values from `specs_json` such as `json['name']`, `json['field_structure_type']`, `json['product']`, `json['customer_owner_id']`, `json['entity_type']`, `json['advertiser_ids']`, `json['campaign_ids']`, `json['min_start_date']`, `json['max_start_date']`, `json['min_end_date']`, and `json['max_end_date']` are directly used to create `Specification` objects.
    - File: `/code/resources/python_cloud_functions/configurator/taxonomy.py`
    - The `SpecificationSet.create_specs_table` function directly loads data from the created `Specification` objects into the `specifications` BigQuery table. This includes the `validation_query_template` which is constructed based on potentially malicious data from the Admin Sheet.
    - There is no input validation at any stage in the Configurator Cloud Function to sanitize or validate the data originating from the Google Admin Sheet before it's used to configure the system.
  - Security Test Case:
    1. **Pre-requisites:**
        - Deploy the Taxonomy Wizard project.
        - Obtain access to the Google Admin Sheet for the deployed project (as an attacker with unauthorized access).
    2. **Steps:**
        - In the Google Admin Sheet, navigate to the "TaxonomySpec" tab.
        - Create a new Taxonomy Specification or modify an existing one.
        - In the "validation_query_template" column for this specification, inject a malicious SQL query. For example, replace the original query with: `SELECT name, 'ATTACK_TRIGGERED' as validation_message FROM \`your-project-id.your_dataset.your_table\` WHERE name IN UNNEST(@entity_names) UNION ALL SELECT name, table_name FROM \`your-project-id.your_dataset.INFORMATION_SCHEMA.TABLES\` WHERE table_schema = 'your_dataset' LIMIT 1;` (Replace `your-project-id` and `your_dataset` with your project details). This crafted query will always return 'ATTACK_TRIGGERED' as validation message and additionally attempt to extract a table name from your dataset's INFORMATION_SCHEMA.
        - Navigate to the "Cloud Config" tab in the Admin Sheet.
        - Click the "Overwrite Taxonomy Data" button to trigger the Configurator Cloud Function.
    3. **Expected Outcome:**
        - The Configurator Cloud Function will execute without errors, and the malicious SQL query will be saved as the `validation_query_template` for the modified Taxonomy Specification in the `specifications` BigQuery table.
    4. **Verification:**
        - In BigQuery console, query the `specifications` table in your dataset and verify that the `validation_query_template` for the modified Taxonomy Specification has been updated with the malicious SQL query.
        - Trigger the Validator Cloud Function (e.g., using the scheduler or by manually invoking it with a test payload).
        - Observe the validation results. They should reflect the injected malicious logic. In this example, all validated names should result in 'ATTACK_TRIGGERED' message, and potentially errors related to the attempted INFORMATION_SCHEMA query if the validator service account has insufficient permissions for that. This confirms that the injected malicious SQL query is being used by the Validator.

- Vulnerability Name: Potential SQL Injection Vulnerability in Validation Queries
  - Description:
    1. An attacker, having successfully injected malicious data into the Google Admin Sheet as described in the "Lack of Input Validation in Configurator Cloud Function" vulnerability, crafts a malicious SQL query within the `validation_query_template` in the Admin Sheet.
    2. The Configurator Cloud Function deploys this malicious SQL query to the `specifications` BigQuery table without sanitization.
    3. When the Validator Cloud Function is triggered to validate entity names, it retrieves the `validation_query_template` from the `specifications` table.
    4. The Validator Cloud Function uses string formatting (specifically Jinja templating in the code, though simplified string replacement is evident in the provided snippets) to insert user-provided entity names into the retrieved `validation_query_template`.
    5. If the injected SQL query contains malicious SQL code, and the entity names are not properly sanitized before being inserted into the query, this can lead to SQL injection.
    6. The malicious SQL query is then executed against BigQuery.
  - Impact:
    - **Data Breach:** An attacker could potentially extract sensitive data from BigQuery by crafting SQL injection queries to select and exfiltrate data from tables accessible by the Validator Cloud Function's service account.
    - **Data Manipulation:** An attacker might be able to modify or delete data within BigQuery if the Validator Cloud Function's service account has write or delete permissions and the injected SQL is designed for data manipulation.
    - **Service Disruption:** Malicious SQL queries could be designed to cause errors or performance issues in BigQuery, potentially disrupting the validation service.
  - Vulnerability Rank: Critical
  - Currently Implemented Mitigations:
    - The project uses parameterized queries in some parts of the code (e.g., in `_fetch_validation_query_template` and `fetch_validation_results`). However, this is not consistently applied to user-controlled inputs within the validation queries themselves, especially when constructing the dynamic validation logic from templates.
    - Google Cloud Functions are secured by IAM, limiting unauthorized invocation of the Validator Cloud Function.
  - Missing Mitigations:
    - **Input Sanitization for Entity Names:**  The Validator Cloud Function should sanitize entity names before inserting them into the validation queries to prevent SQL injection. This could involve escaping special characters or using parameterized queries more effectively to treat entity names as data rather than executable code.
    - **Secure Query Construction:** Implement secure query construction practices. Instead of relying on string replacement of user inputs into raw SQL templates, consider using an ORM or query builder that inherently handles input sanitization and prevents SQL injection. If direct SQL is necessary, ensure all user-provided values are strictly parameterized at the database level.
    - **Principle of Least Privilege for Validator Service Account:** Restrict the BigQuery permissions of the `taxonomy-wizard-validator` service account to the absolute minimum required for validation. Avoid granting unnecessary `bigquery.dataEditor` or `bigquery.admin` roles, limiting the potential impact of a successful SQL injection.
  - Preconditions:
    - The "Lack of Input Validation in Configurator Cloud Function" vulnerability has been exploited, and a malicious SQL query has been injected into the `validation_query_template` in the `specifications` BigQuery table.
    - The Validator Cloud Function is triggered to validate entity names.
  - Source Code Analysis:
    - File: `/code/resources/python_cloud_functions/validator/validators/validator.py`
    - The `fetch_validation_results` function in `BaseValidator` constructs a BigQuery query using string formatting/replacement.
    - Specifically,  `job_config = bigquery.QueryJobConfig(query_parameters=[bigquery.ArrayQueryParameter("entity_names", "STRING", input)])` utilizes parameterized queries for the `@entity_names` parameter, which is a good practice. However, the main vulnerability lies in the `validation_query_template` itself, which is fetched from the `specifications` table and is constructed by the Configurator based on potentially malicious input from the Admin Sheet.
    - The `post_process_query_template` function in `RawJsonValidator` and `ProductValidator` simply replaces `@entity_names` with `UNNEST(@entity_names)`. This replacement is performed on the already fetched `validation_query_template`, which could contain malicious SQL.
    - The core issue is that if the `validation_query_template` itself contains malicious SQL, the parameterized query for `entity_names` will not prevent the execution of the injected malicious code. The vulnerability is present because the system trusts the `validation_query_template` from the database without validating its safety, especially when it might have been configured through an insecure data entry point (Admin Sheet without input validation).
  - Security Test Case:
    1. **Pre-requisites:**
        - Complete the Security Test Case for "Lack of Input Validation in Configurator Cloud Function" and ensure the malicious SQL query is injected into the `validation_query_template`.
        - Ensure you have the modified Taxonomy Specification with the malicious `validation_query_template` active in your BigQuery setup.
    2. **Steps:**
        - Prepare a request to the Validator Cloud Function (either via HTTP request if publicly accessible, or by simulating the request structure for internal testing).
        - The request should include a valid `action` (e.g., 'validate_names'), `taxonomy_cloud_project_id`, `taxonomy_bigquery_dataset`, `spec_name` (the name of the specification with the malicious query), and `data` containing entity names to validate. The actual entity names in `data` are less critical for triggering this specific SQL injection vulnerability because the injected query already contains malicious SQL logic.
        - Send the request to trigger the Validator Cloud Function.
    3. **Expected Outcome:**
        - The Validator Cloud Function will execute the validation query, which now includes the injected malicious SQL code.
        - Based on the malicious SQL injected in the previous test case example (`SELECT name, 'ATTACK_TRIGGERED' as validation_message FROM \`your-project-id.your_dataset.your_table\` WHERE name IN UNNEST(@entity_names) UNION ALL SELECT name, table_name FROM \`your-project-id.your_dataset.INFORMATION_SCHEMA.TABLES\` WHERE table_schema = 'your_dataset' LIMIT 1;`), you should observe:
            - All validation results will show 'ATTACK_TRIGGERED' as the validation message, confirming the primary injected logic is working.
            - If the Validator service account has sufficient permissions, the query might also attempt to retrieve table names from the `INFORMATION_SCHEMA.TABLES`. This could result in additional information disclosure or errors depending on the account's permissions and the exact nature of the injected SQL.
    4. **Verification:**
        - Examine the logs of the Validator Cloud Function execution. Look for any errors or unexpected behavior that might indicate the execution of the injected malicious SQL.
        - Review the validation results returned by the Validator Cloud Function. Confirm that they reflect the intended malicious outcome (e.g., consistent 'ATTACK_TRIGGERED' messages).
        - If your injected SQL was designed to interact with other BigQuery resources or exfiltrate data (and if the Validator service account has the necessary permissions), verify if those actions were successfully performed based on logs or by checking the state of your BigQuery environment.