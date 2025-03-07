### 1. Vulnerability Name: GAQL Injection via `customer-ids-query` and `customer-ids-query-file` Options

- Description:
    1. An attacker crafts a malicious GAQL query designed to extract sensitive data or manipulate data access beyond their authorized scope.
    2. The attacker uses the `--customer-ids-query` or `--customer-ids-query-file` options of `gaarf` to supply this malicious GAQL query. These options are intended to filter customer IDs but can be abused if not properly validated.
    3. `gaarf` executes the attacker-provided GAQL query against the Google Ads API.
    4. If the application fails to properly sanitize or validate the input GAQL query, the attacker's malicious query is executed verbatim.
    5. The attacker potentially gains access to sensitive data from multiple accounts or performs unauthorized actions, depending on the crafted query.

- Impact:
    - High: Unauthorized access to sensitive Google Ads data across multiple accounts managed by the MCC account. Data exfiltration, potential data manipulation depending on the API capabilities exposed and the crafted query.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None: Based on the provided project files, there is no explicit input validation or sanitization mentioned for the `--customer-ids-query` and `--customer-ids-query-file` options. The documentation describes the intended usage but doesn't mention security considerations for malicious queries.

- Missing Mitigations:
    - Input validation and sanitization for GAQL queries provided via `--customer-ids-query` and `--customer-ids-query-file` options. Implement parsing and validation of the provided GAQL query to ensure it only selects `customer.id` and includes necessary `WHERE` clauses for filtering, preventing arbitrary GAQL execution.
    - Principle of least privilege: Limit the permissions of the service account used by `gaarf` to the bare minimum required for its intended functionality. This can reduce the impact of a successful GAQL injection attack.

- Preconditions:
    - The attacker needs to be able to run the `gaarf` tool with access to the command-line interface and the ability to specify command-line arguments, including `--customer-ids-query` or `--customer-ids-query-file`.
    - The attacker needs to know or guess a valid MCC account ID to use with the `--account` option.

- Source Code Analysis:
    1. **File: /code/README.md**: The documentation describes the `--customer-ids-query` and `--customer-ids-query-file` options, explaining their intended functionality to filter accounts. It lacks any security warnings or input validation details.
    2. **File: /code/gcp/README.md**: The documentation for Cloud Workflow parameters also mentions `customer_ids_query` as a parameter for the workflow, indicating that this parameter is passed down to the `gaarf` tool running in the cloud function.
    3. **File: /code/gcp/workflow/workflow.yaml & workflow-ads.yaml**: These workflow definitions show how the `customer_ids_query` parameter is passed to the `gaarf` cloud function.
    4. **File: /code/gcp/functions/gaarf/main.js**:  *(Assuming similar logic in Python version)* The cloud function likely takes the `customer_ids_query` as input and passes it to the core `gaarf` library for execution without validation, as no validation logic is apparent in the provided documentation or setup scripts.
    5. **File: /code/js/README.md & py/README.md**:  These README files describe the command-line options, including `--customer-ids-query` and `--customer-ids-query-file`, again without mentioning any input validation or security considerations.

    **Visualization:**

    ```
    User Input (Malicious GAQL Query via --customer-ids-query/file) --> gaarf CLI --> gaarf Core Library --> Google Ads API (Executes Malicious Query) --> Sensitive Data Leak
    ```

- Security Test Case:
    1. **Setup:** Have a running instance of `gaarf` (either Node.js or Python version). Ensure you have Google Ads API credentials configured for a test MCC account.
    2. **Craft Malicious Query (malicious_query.sql):** Create a file `malicious_query.sql` with the following content:
        ```sql
        SELECT
            customer.id,
            customer.descriptive_name,
            customer.currency_code,
            customer.time_zone
        FROM customer
        LIMIT 10
        ```
        This query attempts to extract customer details beyond just IDs.
    3. **Execute gaarf with malicious query file:** Run `gaarf` command, providing a regular ads query file (e.g., a simple campaign query) and the malicious customer IDs query file:
        ```bash
        gaarf examples/campaign_query.sql --account=YOUR_MCC_ID --output=console --customer-ids-query-file=malicious_query.sql
        ```
        Replace `YOUR_MCC_ID` with a valid MCC account ID and `examples/campaign_query.sql` with a valid, simple query file for gaarf to process.
    4. **Observe Output:** Examine the console output. If the vulnerability exists, you will see output containing not only customer IDs but also `customer.descriptive_name`, `customer.currency_code`, and `customer.time_zone` for multiple accounts, demonstrating unauthorized data access.
    5. **Expected Result (Vulnerable):** The output will include sensitive customer data (descriptive name, currency, timezone) beyond just customer IDs, confirming GAQL injection.
    6. **Expected Result (Mitigated):** If mitigations are in place, `gaarf` should either reject the malicious query with an error (due to validation) or only return customer IDs, ignoring the extra fields in the malicious query.