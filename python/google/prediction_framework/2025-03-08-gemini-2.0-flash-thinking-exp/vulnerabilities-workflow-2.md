## Combined Vulnerability List

### Vulnerability Name: SQL Injection via Customized extract_all_transactions.sql

- Description:
    - The prediction framework allows users to customize the data extraction query by modifying the `deploy/customization/queries/extract_all_transactions.sql` file.
    - This customized query is then used by the `deploy/create_bq_elements.sh` script to configure a BigQuery Data Transfer Scheduled Query.
    - If a user deploys the framework with a maliciously crafted `extract_all_transactions.sql` file, or if an attacker gains access to modify this file before deployment, they can inject arbitrary SQL code.
    - The framework reads the content of this file and directly embeds it into the BigQuery Data Transfer configuration without any sanitization or validation.
    - When the scheduled query runs, the injected SQL code is executed against the BigQuery data source with the permissions of the associated service account.
    - Step-by-step trigger:
        1. An attacker gains access to the deployment configuration files or socially engineers a user.
        2. The attacker modifies the `deploy/customization/queries/extract_all_transactions.sql` file to include a SQL injection payload. For example, inserting `UNION ALL SELECT table_name FROM \`bigquery-public-data.INFORMATION_SCHEMA.TABLES\` LIMIT 10; --` or \`; DROP TABLE BQ_LTV_DATASET.predictions_YYYYMMDD; --\` into the query.
        3. The user, unknowingly or maliciously, executes the `deploy/deploy.sh` script to deploy the framework with the modified SQL query.
        4. During deployment, the `create_bq_elements.sh` script reads the modified SQL query and sets it up as a BigQuery Data Transfer Scheduled Query.
        5. When the scheduled query runs (either manually or automatically), the injected SQL code is executed against the BigQuery data source.
        6. The attacker can then potentially extract sensitive data, modify data, delete data, or perform other unauthorized actions depending on the injected SQL payload and the permissions of the service account used by the BigQuery Data Transfer.

- Impact:
    - Unauthorized access to sensitive data stored in the BigQuery data source, leading to potential data breaches.
    - Data exfiltration, allowing the attacker to steal confidential information.
    - Data integrity compromise if the attacker modifies or deletes data within the BigQuery data source.
    - Potential escalation of privileges if the service account has overly broad permissions, allowing further compromise of the BigQuery environment.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None. The project does not implement any input sanitization, validation, or parameterized queries for the SQL query defined in `deploy/customization/queries/extract_all_transactions.sql`. The query is directly used in the `bq mk --transfer_config` command in `deploy/create_bq_elements.sh` without any security checks. The framework relies on the user to provide safe SQL queries.

- Missing Mitigations:
    - Input sanitization and validation for the SQL query in `deploy/customization/queries/extract_all_transactions.sql`. Implement checks to ensure the query conforms to expected syntax and prevent injection of malicious SQL code.
    - Implement parameterized queries or prepared statements. Instead of directly embedding the user-provided SQL into the scheduled query definition, use parameterized queries to separate SQL code from user-provided data.
    - Apply the principle of least privilege by granting the service account used by the BigQuery Data Transfer Service only the necessary permissions to access and modify the intended BigQuery resources. Restrict its access to only the datasets and tables required for data extraction and processing, minimizing the potential impact of a successful SQL injection.
    - Comprehensive documentation and warnings to users about the security risks associated with modifying the SQL queries and the importance of secure SQL development practices, including input sanitization and parameterized queries if they intend to introduce external parameters into their custom SQL.
    - Regular security audits and reviews of the customized SQL queries and deployment configurations to proactively identify and prevent potential SQL injection vulnerabilities.

- Preconditions:
    - An attacker must be able to modify the `deploy/customization/queries/extract_all_transactions.sql` file before the framework deployment. This could be achieved through various means:
        - Direct access to the file system where the deployment configuration resides before deployment.
        - Compromising the source code repository where the configuration files are stored.
        - Social engineering tactics to trick a user into using a malicious version of the file.
        - Insider threat scenarios where a malicious user with authorized access modifies the file.
        - Compromising the user's development or deployment environment before deployment.

- Source Code Analysis:
    - File: `/code/deploy/create_bq_elements.sh`
    - Step 1: The script defines the path to the customizable SQL query file: `QUERY_PATH="customization/queries/extract_all_transactions.sql"`.
    - Step 2: The script reads the entire content of the SQL query file into the `QUERY` variable using: `QUERY=$(cat "$QUERY_PATH")`.
    - Step 3: The script performs a series of `sed` commands to replace predefined placeholders within the query. These replacements are intended for internal configuration and do not sanitize user input:
      ```bash
      QUERY=$(echo "$QUERY" | sed -r 's,\\[trn],,g')
      QUERY=$(echo "$QUERY" | sed -r 's,\\,\\\\,g')
      QUERY=$(echo "$QUERY" | sed -r 's,\",\\",g')
      QUERY=$(echo "$QUERY" | sed -r ':a;N;$!ba;s/\n/\\n/g')
      QUERY=$(echo "$QUERY" | sed -r 's,\$TABLE,'"$TABLE"',g')
      echo "$QUERY"
      ```
    - Step 4: The script constructs the parameters for the BigQuery Data Transfer Service in JSON format, directly embedding the `$QUERY` variable (containing the unsanitized SQL query) into the `"query"` parameter: `PARAMS='{"query":"'$QUERY'","destination_table_name_template" :"'$TARGET_TABLE_TEMPLATE'","write_disposition" : "WRITE_TRUNCATE"}'`.
    - Step 5: The script creates the BigQuery Data Transfer Service using the `bq mk` command, passing the `$PARAMS` which includes the potentially malicious SQL query:
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
    - Visualization:
      ```
      [extract_all_transactions.sql] --> (cat in create_bq_elements.sh) --> QUERY variable (unsanitized SQL) --> (string interpolation into PARAMS) --> bq mk command execution --> BigQuery Data Transfer Scheduled Query (vulnerable to SQL Injection) --> BigQuery data source (SQL Injection risk during execution)
      ```
    - Vulnerability: The direct use of the content from `extract_all_transactions.sql` without sanitization as the query for the BigQuery Data Transfer Service creates a critical SQL Injection vulnerability.

- Security Test Case:
    - Step 1: Prepare the environment for deployment as described in the `README.md`.
    - Step 2: Modify the `deploy/customization/queries/extract_all_transactions.sql` file with a SQL injection payload. Choose one of the following examples:

        - **Example 1 (Data Exfiltration - Table Names):**
          ```sql
          -- Original query (replace with your actual base query if needed)
          SELECT * FROM `myclient-123456.1234567.ga_sessions_*` WHERE 1=1

          -- SQL Injection payload: UNION SELECT to extract data from a public dataset
          UNION ALL
          SELECT table_name FROM `bigquery-public-data`.INFORMATION_SCHEMA.TABLES LIMIT 10;
          -- Comment to ensure valid SQL syntax after injection
          ```

        - **Example 2 (Data Exfiltration - Dataset IDs):**
          ```sql
          SELECT dataset_id FROM `region-eu`.INFORMATION_SCHEMA.datasets WHERE project_id = 'myclient-123456'; -- Replace 'myclient-123456' with your BQ_DATA_SOURCE_GCP_PROJECT value from config.yaml
          ```

        - **Example 3 (Data Modification/Deletion - Table Drop - **Use with extreme caution in a test environment only**):**
          ```sql
          -- Original query (replace with your actual base query if needed)
          SELECT * FROM `myclient-123456.1234567.ga_sessions_*` WHERE 1=1

          -- SQL Injection payload: DROP TABLE (DANGEROUS - TEST ENVIRONMENT ONLY)
          ; DROP TABLE `<BQ_LTV_GCP_PROJECT>.<BQ_LTV_DATASET>.predictions_YYYYMMDD`; --
          ```
          **Note**: Replace `<BQ_LTV_GCP_PROJECT>` and `<BQ_LTV_DATASET>` with your actual project and dataset names from `config.yaml`, and `predictions_YYYYMMDD` with a table name that exists in your test dataset. **Running this payload can result in data loss.**

        - **Example 4 (Data Injection - Indicator Row):**
          ```sql
          -- Original Query (replace with your actual base query)
          SELECT * FROM `myclient-123456.1234567.ga_sessions_*` WHERE 1=1

          UNION ALL
          SELECT
            'sql_injection',
            'vulnerable',
            CURRENT_TIMESTAMP(),
            'exploit_confirmed'
          ```

    - Step 3: Execute the deployment script from the `deploy` directory: `sh deploy.sh`.
    - Step 4: After successful deployment, navigate to the BigQuery console in your GCP project (`BQ_LTV_GCP_PROJECT` from `config.yaml`).
    - Step 5: Navigate to "Scheduled queries" and find the newly created BigQuery Data Transfer scheduled query (named like `<DEPLOYMENT_NAME>_<SOLUTION_PREFIX>_extract_all_transactions`).
    - Step 6: Manually run the scheduled query from the BigQuery console by clicking "Run now".
    - Step 7: After the scheduled query execution completes, check the output BigQuery table (defined by `$BQ_LTV_ALL_PERIODIC_TX_TABLE` and the run date in `config.yaml`).
    - Step 8: Examine the data in the output table.
        - For **Example 1**, verify if you see table names from `bigquery-public-data.INFORMATION_SCHEMA.TABLES` in the output table, indicating successful data exfiltration.
        - For **Example 2**, verify if you see dataset IDs from your project.
        - For **Example 3**, **(DANGEROUS - TEST ENVIRONMENT ONLY)** check if the targeted table `predictions_YYYYMMDD` has been dropped. **Data loss is possible.**
        - For **Example 4**, query the output table and check for the injected row with values 'sql_injection', 'vulnerable', and 'exploit_confirmed'.
    - Step 9: Successful execution of the injected SQL code in any of these examples confirms the SQL Injection vulnerability.