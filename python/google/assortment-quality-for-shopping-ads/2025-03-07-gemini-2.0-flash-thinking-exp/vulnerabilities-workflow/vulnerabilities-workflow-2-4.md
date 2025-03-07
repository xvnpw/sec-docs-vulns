### Vulnerability List

- Vulnerability Name: SQL Injection in Scheduled Queries
- Description: The application constructs BigQuery Scheduled Queries using user-provided command-line arguments such as `project_id`, `gmc_id`, `dataset_name`, `language`, and `country`. These arguments are used to format SQL queries read from files in the `sql` directory. If these arguments are not properly sanitized or escaped before being incorporated into the SQL queries, a malicious user could inject arbitrary SQL code by providing crafted command-line arguments. This injected SQL code would then be executed within the BigQuery environment when the scheduled query runs, potentially leading to unauthorized data access or modification within the user's Google Cloud project.
- Impact: Successful SQL injection could allow an attacker to:
    - Gain unauthorized access to data within the BigQuery dataset.
    - Modify or delete data within the BigQuery dataset.
    - Potentially escalate privileges within the BigQuery environment depending on the permissions of the service account used by the scheduled queries.
- Vulnerability Rank: High
- Currently Implemented Mitigations: None observed in the provided code. The code directly formats the SQL queries using the user-provided arguments without any apparent sanitization or escaping.
- Missing Mitigations:
    - Input sanitization: All command-line arguments that are used in SQL query construction should be properly sanitized or escaped to prevent SQL injection. Libraries or built-in functions for SQL parameterization should be used to safely incorporate user inputs into SQL queries.
    - Input validation: Input validation should be implemented to ensure that the provided command-line arguments conform to expected formats and values. This can help prevent unexpected or malicious inputs from being processed.
    - Principle of least privilege: The service account or credentials used by the BigQuery Data Transfer Service and Scheduled Queries should be granted only the necessary permissions to perform their intended tasks. This limits the potential impact of a successful SQL injection attack.
- Preconditions:
    - The attacker needs to be able to execute the `main.py` script with crafted command-line arguments.
    - The application must be vulnerable to SQL injection, meaning the SQL queries are constructed without proper sanitization of user inputs.
- Source Code Analysis:
    1. The `main` function in `main.py` parses command-line arguments using `argparse`.
    2. The `check_existing_custom_data_transfers` function is called, which in turn calls `configure_sql`.
    3. The `configure_sql` function reads SQL queries from files (e.g., `brand_coverage.sql`) located in the `sql` directory and formats them using `sql_script.format(**params_replace)`. The `params_replace` dictionary contains user-provided arguments like `project_id`, `gmcId`, `datasetId`, `language`, and `country`.
    4. The formatted SQL query is then used in the `create_scheduled_query` function within the `body` dictionary under the `'params': {'query': query_view}` key.
    5. The `create_scheduled_query` function creates a BigQuery Scheduled Query using the provided SQL query.

    If the SQL files (e.g., `brand_coverage.sql`) directly use format placeholders `{language}` or `{country}` without any sanitization, then a SQL injection vulnerability exists. For example, if `brand_coverage.sql` contains a query like:
    ```sql
    SELECT * FROM products WHERE language = '{language}' AND country = '{country}';
    ```
    and a user provides `--language "en-US' OR '1'='1"` and `--country "US"`, the formatted SQL query becomes:
    ```sql
    SELECT * FROM products WHERE language = 'en-US' OR '1'='1' AND country = 'US';
    ```
    This injected SQL code `' OR '1'='1'` would bypass the intended language filter and potentially expose all data from the `products` table.

- Security Test Case:
    1. Prepare environment:
        - Have a Google Cloud project with BigQuery enabled.
        - Have a Google Merchant Center account ID.
        - Set up the application as described in the README.md, including `client_secret.json`.
    2. Execute the `main.py` script with a crafted `--language` argument to attempt SQL injection. For example, using a simple SQL injection payload that always evaluates to true:
       ```bash
       python main.py -p <your_project_id> -m <your_merchant_id> -r us-central1 -d <your_dataset_name> -l "en-US' OR '1'='1" -c "US" -e 7
       ```
       Replace `<your_project_id>`, `<your_merchant_id>`, and `<your_dataset_name>` with your actual Google Cloud project ID, Merchant Center ID, and desired BigQuery dataset name.
    3. Check the created BigQuery Scheduled Queries in the Google Cloud Console. Navigate to BigQuery -> Data Transfers -> Scheduled Queries.
    4. Find the scheduled query that corresponds to the execution with the injected `--language` parameter. The display name should reflect the parameters used, including the injected language.
    5. Examine the SQL query of the scheduled query. Verify if the injected SQL code `' OR '1'='1'` is present in the query. You can typically view the query details by clicking on the scheduled query in the BigQuery Data Transfers UI.
    6. If the injected SQL code is present in the scheduled query, it confirms the SQL injection vulnerability. This indicates that user-provided input is directly embedded into the SQL query without proper sanitization.
    7. To further validate the impact, you would need to examine the actual SQL queries in the `sql` directory (e.g., `brand_coverage.sql`, `category_coverage.sql`, etc.) to understand how the `language` and `country` parameters are used and what data could be potentially accessed or modified through SQL injection. If the queries are designed to filter or manipulate data based on these parameters, successful injection could lead to data breaches or manipulation.