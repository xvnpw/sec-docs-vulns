### Vulnerability 1: SQL Injection via Customized extract_all_transactions.sql

- Description:
    - A user deploying the prediction framework can customize the data extraction query by modifying the `deploy/customization/queries/extract_all_transactions.sql` file.
    - If this customized query naively incorporates unsanitized user-controlled input (although direct external user control is not evident in the provided files, the scenario considers a malicious configuration), and the framework executes this query without proper sanitization, it could lead to SQL injection.
    - An attacker who can influence the user to deploy a malicious configuration or who gains access to the deployment configuration files before deployment can inject malicious SQL code.
    - This injected SQL code can then be executed against the BigQuery data source during the data extraction process.
    - Step-by-step trigger:
        1. An attacker gains access to the deployment configuration files or socially engineers a user.
        2. The attacker modifies the `deploy/customization/queries/extract_all_transactions.sql` file to include a SQL injection payload. For example, inserting `UNION ALL SELECT table_name FROM \`bigquery-public-data.INFORMATION_SCHEMA.TABLES\` LIMIT 10; --` into the query.
        3. The user, unknowingly or maliciously, executes the `deploy/deploy.sh` script to deploy the framework with the modified SQL query.
        4. During deployment, the `create_bq_elements.sh` script reads the modified SQL query and sets it up as a BigQuery Data Transfer Scheduled Query.
        5. When the scheduled query runs (either manually or automatically), the injected SQL code is executed against the BigQuery data source.
        6. The attacker can then potentially extract sensitive data, modify data, or perform other unauthorized actions depending on the injected SQL payload and the permissions of the service account used by the BigQuery Data Transfer.

- Impact:
    - Unauthorized access to sensitive data stored in the BigQuery data source.
    - Potential data exfiltration, allowing the attacker to steal confidential information.
    - Data integrity compromise if the attacker modifies or deletes data.
    - Depending on the injected payload, it could lead to further compromise of the BigQuery environment.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None. The project does not implement any input sanitization or validation for the SQL query defined in `deploy/customization/queries/extract_all_transactions.sql`. The query is directly used in the `bq mk --transfer_config` command in `deploy/create_bq_elements.sh` without any checks.

- Missing Mitigations:
    - Input sanitization and validation for the SQL query in `deploy/customization/queries/extract_all_transactions.sql`.
    - Implement least privilege principle by granting the service account only the necessary permissions, limiting the impact of potential SQL injection.
    - Consider using parameterized queries or prepared statements if the framework were to construct SQL queries programmatically, although in this case, the query is read from a file.
    - Documentation should strongly warn users about the risks of modifying the SQL queries and recommend secure SQL development practices.

- Preconditions:
    - An attacker must be able to modify the `deploy/customization/queries/extract_all_transactions.sql` file before the framework deployment. This could be via:
        - Direct access to the file system before deployment.
        - Social engineering to trick a user into using a malicious version of the file.
        - Compromising the user's development environment before deployment.

- Source Code Analysis:
    - File: `/code/deploy/create_bq_elements.sh`
    - Step 1: The script reads the SQL query from `deploy/customization/queries/extract_all_transactions.sql` using `QUERY=$(cat "$QUERY_PATH")`.
    - Step 2: The script performs several string replacements on the query using `sed`, but these are for internal placeholders and not for sanitizing user input.
    - Step 3: The script constructs a BigQuery Data Transfer configuration command:
      ```bash
      CREATE_TRANSFER=$(bq mk \
      --transfer_config \
      --location="$BQ_LTV_GCP_BROAD_REGION" \
      --project_id="$BQ_LTV_GCP_PROJECT" \
      --target_dataset="$BQ_LTV_DATASET" \
      --display_name="$DEPLOYMENT_NAME""_""$SOLUTION_PREFIX""_extract_all_transactions" \
      --data_source=scheduled_query \
      --schedule='None' \
      --service_account_name="$SERVICE_ACCOUNT" \
      --params="$PARAMS"
      )
      ```
      where `$PARAMS` is defined as `PARAMS='{"query":"'$QUERY'","destination_table_name_template" :"'$TARGET_TABLE_TEMPLATE'","write_disposition" : "WRITE_TRUNCATE"}'`.
    - Step 4: The `$QUERY` variable, which contains the content of `extract_all_transactions.sql`, is directly embedded into the `--params` argument of the `bq mk` command without any sanitization or validation.
    - Visualization:
      ```
      [extract_all_transactions.sql] --> (cat) --> QUERY variable --> (string interpolation into PARAMS) --> bq mk command execution --> BigQuery Data Transfer Scheduled Query (with potentially malicious SQL) --> BigQuery data source (SQL Injection risk)
      ```

- Security Test Case:
    - Step 1: Prepare the environment for deployment as described in the `README.md`.
    - Step 2: Modify the `deploy/customization/queries/extract_all_transactions.sql` file with the following SQL injection payload:
      ```sql
      -- Original query (replace with your actual base query if needed)
      SELECT * FROM `myclient-123456.1234567.ga_sessions_*` WHERE 1=1

      -- SQL Injection payload: UNION SELECT to extract data from a public dataset
      UNION ALL
      SELECT table_name FROM `bigquery-public-data`.INFORMATION_SCHEMA.TABLES LIMIT 10;
      -- Comment to ensure valid SQL syntax after injection
      ```
    - Step 3: Execute the deployment script from the `deploy` directory: `sh deploy.sh`.
    - Step 4: After successful deployment, navigate to the BigQuery console and find the newly created BigQuery Data Transfer scheduled query (named like `<DEPLOYMENT_NAME>_<SOLUTION_PREFIX>_extract_all_transactions`).
    - Step 5: Manually run the scheduled query from the BigQuery console.
    - Step 6: After the scheduled query execution completes, check the output BigQuery table (defined by `$BQ_LTV_ALL_PERIODIC_TX_TABLE` and the run date in `config.yaml`).
    - Step 7: Examine the data in the output table. If the SQL injection was successful, you should see data from the `bigquery-public-data.INFORMATION_SCHEMA.TABLES` (specifically, table names) mixed with or appended to the expected data from `myclient-123456.1234567.ga_sessions_*`. This confirms that the injected `UNION ALL SELECT` statement was executed, demonstrating a SQL Injection vulnerability.