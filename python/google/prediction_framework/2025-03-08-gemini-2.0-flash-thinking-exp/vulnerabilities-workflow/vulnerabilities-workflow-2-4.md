### Vulnerability List

- Vulnerability Name: SQL Injection in `extract_all_transactions.sql`

- Description:
  - An attacker can inject malicious SQL code by modifying the `deploy/customization/queries/extract_all_transactions.sql` file.
  - This file contains a customizable SQL query that is used to extract transaction data from a source BigQuery table and load it into the `all_periodic_transactions_YYYYMMDD` table within the project's BigQuery dataset.
  - The `deploy/create_bq_elements.sh` script reads the content of this SQL file and uses it to create a BigQuery Data Transfer Service scheduled query.
  - If an attacker modifies `extract_all_transactions.sql` to include malicious SQL statements, these statements will be executed with the permissions of the service account associated with the BigQuery Data Transfer Service during the scheduled query execution.
  - This can lead to unauthorized data access, modification, or exfiltration from the source BigQuery data.

- Impact:
  - **Unauthorized Data Access**: Attackers can gain unauthorized access to sensitive data stored in the source BigQuery tables by crafting malicious SQL queries to bypass intended data filtering and access controls.
  - **Data Exfiltration**: Attackers can exfiltrate sensitive data from the source BigQuery tables to external systems or tables under their control.
  - **Data Modification or Corruption**: Attackers might be able to modify or corrupt data in the source BigQuery tables, leading to data integrity issues and potentially impacting prediction accuracy or downstream processes.
  - **Lateral Movement**: In more advanced scenarios, successful SQL injection could potentially be leveraged for further lateral movement within the Google Cloud environment, depending on the permissions of the service account and the overall network configuration.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
  - No specific mitigations for SQL injection are implemented within the provided project files. The project relies on user customization of SQL queries, which inherently introduces the risk if not handled securely.

- Missing Mitigations:
  - **Input Sanitization and Validation**: The project lacks any input sanitization or validation mechanisms for the SQL query in `extract_all_transactions.sql`. Any user-provided or modified SQL code is directly used.
  - **Parameterized Queries or Prepared Statements**: The project does not utilize parameterized queries or prepared statements within the `deploy/create_bq_elements.sh` script when constructing the BigQuery scheduled query. This would be the standard approach to prevent SQL injection by separating SQL code from user-provided data.
  - **Principle of Least Privilege**: While not directly related to SQL injection prevention, enforcing the principle of least privilege for the service account used by the BigQuery Data Transfer Service would limit the potential impact of a successful SQL injection. The service account should only have the necessary permissions to access and read the intended source BigQuery data, and write to the destination BigQuery dataset, and not broader permissions that could be exploited.

- Preconditions:
  - **Access to Modify `extract_all_transactions.sql`**: An attacker needs to be able to modify the `deploy/customization/queries/extract_all_transactions.sql` file. This could be achieved through compromising the source code repository, gaining access to the deployment environment if modifications are directly made there, or through social engineering if a less technical user is instructed to modify this file.
  - **Deployment Execution**: After modifying the SQL file, the attacker needs to trigger the deployment process (e.g., by running `deploy.sh`) to update the BigQuery scheduled query with the malicious SQL code. Alternatively, if direct modifications are made in a deployed environment, the scheduled query would eventually run the modified SQL.

- Source Code Analysis:
  - **File: `/code/deploy/create_bq_elements.sh`**
    - This script is responsible for creating the BigQuery scheduled query that extracts data.
    - The script reads the SQL query from `/code/deploy/customization/queries/extract_all_transactions.sql`:
      ```bash
      QUERY=$(cat "$QUERY_PATH")
      ```
    - It then performs several `sed` operations to replace placeholders within the query:
      ```bash
      QUERY=$(echo "$QUERY" | sed -r 's,\\[trn],,g')
      QUERY=$(echo "$QUERY" | sed -r 's,\\,\\\\,g')
      QUERY=$(echo "$QUERY" | sed -r 's,\",\\",g')
      QUERY=$(echo "$QUERY" | sed -r ':a;N;$!ba;s/\n/\\n/g')
      QUERY=$(echo "$QUERY" | sed -r 's,\$TABLE,'"$TABLE"',g')
      echo "$QUERY"
      ```
    - Finally, the `$QUERY` variable is embedded directly into the `params` argument of the `bq mk` command using string interpolation:
      ```bash
      PARAMS='{"query":"'$QUERY'","destination_table_name_template" :"'$TARGET_TABLE_TEMPLATE'","write_disposition" : "WRITE_TRUNCATE"}'
      ...
      CREATE_TRANSFER=$(bq mk \
      --transfer_config \
      ...
      --params="$PARAMS"
      )
      ```
    - **Vulnerability**: The direct embedding of the `$QUERY` variable, which is derived from the potentially attacker-modified `extract_all_transactions.sql` file, into the `bq mk` command's `--params` argument without any sanitization creates a SQL injection vulnerability. If an attacker can control the content of `extract_all_transactions.sql`, they can inject arbitrary SQL code that will be executed by the BigQuery scheduled query.

  - **File: `/code/deploy/customization/queries/extract_all_transactions.sql`**
    - This file is explicitly intended for user customization, as indicated in the `README.md`.
    - The project documentation encourages users to modify this file to define their data extraction logic.
    - This customization point becomes a vulnerability if users are not aware of SQL injection risks and are not guided to implement secure SQL query practices.

- Security Test Case:
  1. **Prerequisites**:
     - Deploy the prediction framework to a Google Cloud Project using `deploy.sh`.
     - Ensure you have `gcloud` CLI tools installed and configured to interact with your GCP project.
  2. **Modify `extract_all_transactions.sql`**:
     - Open the file `/code/deploy/customization/queries/extract_all_transactions.sql` in a text editor.
     - Append the following malicious SQL code to the end of the existing query:
       ```sql
       UNION ALL
       SELECT
         'sql_injection',
         'vulnerable',
         CURRENT_TIMESTAMP(),
         'exploit_confirmed'
       ```
       This injected SQL will attempt to add a new row with indicator values into the output table.
  3. **Re-deploy the Framework**:
     - Navigate to the `/code/deploy` directory in your terminal.
     - Execute the deployment script: `sh deploy.sh`
     - This will update the BigQuery scheduled query with the modified SQL.
  4. **Trigger Scheduled Query**:
     - Go to the BigQuery console in your GCP project.
     - Navigate to "Scheduled queries" and find the query named similar to `<DEPLOYMENT_NAME>_<SOLUTION_PREFIX>_extract_all_transactions`.
     - Manually run the scheduled query by clicking "Run now".
     - Alternatively, wait for the next scheduled execution of the query based on its configured schedule.
  5. **Verify SQL Injection**:
     - After the scheduled query execution completes, query the `all_periodic_transactions_YYYYMMDD` table in your BigQuery dataset (replace `YYYYMMDD` with the execution date). For example:
       ```sql
       SELECT * FROM `<BQ_LTV_GCP_PROJECT>.<BQ_LTV_DATASET>.all_periodic_transactions_*`
       WHERE _TABLE_SUFFIX = FORMAT_DATETIME('%Y%m%d', CURRENT_DATETIME())
       ```
     - Check if the table contains the injected row with the values 'sql_injection', 'vulnerable', and 'exploit_confirmed'. If this row exists, it confirms the SQL injection vulnerability.

This test case demonstrates that by modifying the `extract_all_transactions.sql` file and re-deploying the framework, an attacker can inject and execute arbitrary SQL code, confirming the SQL injection vulnerability.