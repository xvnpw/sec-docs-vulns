- Vulnerability Name: SQL Injection in Data Extraction Query
- Description:
    1. The prediction framework allows users to customize the data extraction process by modifying the SQL query in `deploy/customization/queries/extract_all_transactions.sql`.
    2. The `deploy/create_bq_elements.sh` script reads the content of this SQL file and uses it to create a BigQuery Data Transfer Service scheduled query named `extract_all_transactions`.
    3. This scheduled query is executed by the BigQuery Data Transfer Service to extract data from the user-defined data source and load it into the `all_periodic_transactions_YYYYMMDD` table.
    4. If the SQL query in `extract_all_transactions.sql` is maliciously crafted to include SQL injection payloads, these payloads will be executed against the BigQuery data source during the data extraction process.
    5. An attacker can modify `deploy/customization/queries/extract_all_transactions.sql` (if they have write access to the deployment configuration before deployment) or provide a malicious query through other means if the deployment process is not properly secured, injecting arbitrary SQL commands.
- Impact:
    1. **Data Breach**: An attacker can extract sensitive data from the BigQuery data source beyond what is intended for the prediction framework. This could include customer data, financial information, or any other data accessible within the BigQuery environment and permitted by the service account's permissions.
    2. **Data Modification/Deletion**: In severe cases, depending on the permissions of the service account used by the BigQuery Data Transfer Service, an attacker might be able to modify or delete data in the BigQuery data source.
    3. **Privilege Escalation**: Although less likely in this specific scenario focused on data extraction, if the BigQuery service account has overly broad permissions, successful SQL injection could potentially be leveraged for further privilege escalation within the Google Cloud Platform project.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The project provides customization through direct SQL query modification without any input sanitization or validation.
- Missing Mitigations:
    - **Input Sanitization and Validation**: The framework should sanitize or parameterize user-provided SQL queries to prevent the injection of malicious SQL code. Instead of directly embedding user-provided SQL into the scheduled query definition, the framework should use parameterized queries or implement robust input validation to ensure only expected SQL syntax is used.
    - **Principle of Least Privilege**: Ensure that the service account used by the BigQuery Data Transfer Service and Cloud Functions has the minimum necessary permissions to perform its intended tasks. Restrict its access to only the datasets and tables required for data extraction and processing, minimizing the potential impact of a successful SQL injection.
    - **Security Audits and Reviews**: Regularly audit and review the customized SQL queries and deployment configurations to identify and prevent potential SQL injection vulnerabilities.
- Preconditions:
    1. **Customizable SQL Query**: The project must be deployed with a customized `deploy/customization/queries/extract_all_transactions.sql` or allow for user-provided SQL queries through other configuration mechanisms.
    2. **Deployment Process Access**: An attacker needs to have the ability to modify the `deploy/customization/queries/extract_all_transactions.sql` file or influence the SQL query used during the deployment process before the deployment is executed. This could be through compromised credentials, insider threat, or vulnerabilities in the deployment pipeline itself (though the project files provided focus on code vulnerabilities, assuming secure deployment pipeline for this case).
- Source Code Analysis:
    1. **`deploy/create_bq_elements.sh`**: This script is responsible for creating the BigQuery Data Transfer Service scheduled query.
    2. **`QUERY_PATH="customization/queries/extract_all_transactions.sql"`**:  The script defines the path to the customizable SQL query file.
    3. **`QUERY=$(cat "$QUERY_PATH")`**: The script reads the entire content of the `extract_all_transactions.sql` file into the `QUERY` variable.
    4. **`PARAMS='{"query":"'$QUERY'","destination_table_name_template" :"'$TARGET_TABLE_TEMPLATE'","write_disposition" : "WRITE_TRUNCATE"}'`**: The script constructs the parameters for the BigQuery Data Transfer Service, directly embedding the `$QUERY` variable (which contains the unsanitized SQL query from the file) into the `"query"` parameter.
    5. **`bq mk --transfer_config ... --params="$PARAMS"`**: The `bq mk` command is executed to create the scheduled query, using the `$PARAMS` which contains the potentially malicious SQL query.

    ```bash
    File: /code/deploy/create_bq_elements.sh

    ...
    QUERY_PATH="customization/queries/extract_all_transactions.sql"
    ...
    QUERY=$(cat "$QUERY_PATH")
    ...
    PARAMS='{"query":"'$QUERY'","destination_table_name_template" :"'$TARGET_TABLE_TEMPLATE'","write_disposition" : "WRITE_TRUNCATE"}'
    ...
    CREATE_TRANSFER=$(bq mk \
    --transfer_config \
    ...
    --params="$PARAMS"
    )
    ...
    ```

    **Visualization**:

    ```
    User-provided SQL query (extract_all_transactions.sql) --> [cat command in create_bq_elements.sh] --> QUERY variable (unsanitized) --> PARAMS variable (JSON with embedded unsanitized SQL) --> [bq mk command] --> BigQuery Data Transfer Service Scheduled Query (vulnerable to SQL Injection) --> Execution against BigQuery Data Source --> Potential Data Breach/Modification
    ```

    The code directly uses the content of `extract_all_transactions.sql` as the query for the BigQuery Data Transfer Service without any sanitization or parameterization, creating a direct SQL Injection vulnerability.

- Security Test Case:
    1. **Prepare Malicious SQL Query**: Create a file named `extract_all_transactions.sql` within the `deploy/customization/queries/` directory with the following malicious SQL query. This example aims to extract the list of datasets from the `BQ_DATA_SOURCE_GCP_PROJECT`.

        ```sql
        -- deploy/customization/queries/extract_all_transactions.sql
        SELECT dataset_id FROM `region-eu`.INFORMATION_SCHEMA.datasets WHERE project_id = 'myclient-123456'; -- Replace 'myclient-123456' with your BQ_DATA_SOURCE_GCP_PROJECT value from config.yaml
        ```

        **Note**: Replace `'myclient-123456'` with the actual value of `BQ_DATA_SOURCE_GCP_PROJECT` from your `deploy/config.yaml` to target the correct project.

    2. **Modify `deploy/config.yaml`**: Ensure the `BQ_DATA_SOURCE_GCP_PROJECT` in your `deploy/config.yaml` is set to a project where you have BigQuery access and datasets exist. For testing in a safe environment, you can use a test project.

    3. **Deploy the Framework**: Navigate to the `deploy` directory in your local copy of the repository and execute the deployment script:

        ```bash
        cd deploy
        sh deploy.sh
        ```

        Follow the deployment instructions in the `README.md`. Ensure the deployment completes successfully.

    4. **Trigger the Scheduled Query**: After successful deployment, go to the BigQuery console in your GCP project (`BQ_LTV_GCP_PROJECT` from `config.yaml`).
    5. **Navigate to Scheduled Queries**: In the BigQuery console, find "Scheduled queries" in the left-hand navigation menu.
    6. **Locate and Run `extract_all_transactions`**: Find the scheduled query named something like `<DEPLOYMENT_NAME>_<SOLUTION_PREFIX>_extract_all_transactions`. Select it and click "Run now" to manually trigger the query execution.
    7. **Check the Output Table**: After the scheduled query execution completes (it might take a few minutes), navigate to BigQuery and locate the dataset specified by `BQ_LTV_DATASET` in your `BQ_LTV_GCP_PROJECT`.
    8. **Inspect `all_periodic_transactions_YYYYMMDD` Table**: Find the table `all_periodic_transactions_YYYYMMDD` (where `YYYYMMDD` is today's date or the execution date). Query this table.
    9. **Verify SQL Injection**: If the SQL injection is successful, the `all_periodic_transactions_YYYYMMDD` table will contain a list of dataset IDs from the `BQ_DATA_SOURCE_GCP_PROJECT`, demonstrating that the injected SQL query `SELECT dataset_id FROM ...` was executed instead of the intended data extraction query. This confirms the SQL injection vulnerability.