### CSV Injection Vulnerability in Feed Files

- Vulnerability Name: CSV Injection
- Description:
  1. An attacker crafts a malicious CSV or TSV file containing CSV injection payloads within item fields. These payloads often involve special characters or escape sequences, particularly characters like '=', '@', '+', or '-' at the beginning of a cell, which can be interpreted as formulas by spreadsheet software.
  2. The attacker uploads this malicious CSV/TSV file to the `FEED_BUCKET` in Google Cloud Storage.
  3. The `import_storage_file_into_big_query` Cloud Function is triggered by the file upload event.
  4. The Cloud Function uses the BigQuery Load API to import the CSV/TSV data into a BigQuery table (`feed_data.items`). The Load API configuration, specifically with `quote_character` set to an empty string, disables quote handling, and no CSV sanitization or escaping mechanisms are implemented.
  5. A user, such as a data analyst or GMC administrator, queries or downloads the processed data from the `feed_data.items` BigQuery table and exports it as a CSV or TSV file.
  6. The user opens the exported CSV/TSV file using spreadsheet software (e.g., Microsoft Excel, Google Sheets, LibreOffice Calc). Alternatively, the data is processed and sent to Google Merchant Center (GMC) via Content API.
  7. When the exported file is opened in spreadsheet software, the software detects and interprets the injected formulas within the CSV data. This can lead to:
    - Arbitrary command execution on the user's machine.
    - Injection of malicious content or links within the spreadsheet.
  8. If the data is processed by Google Merchant Center, the injected malicious data, if not properly sanitized, can be interpreted as commands or special values, potentially leading to:
    - Data corruption in Google Merchant Center, altering product data.
    - Unintended modifications of product listings, causing incorrect or disapproved listings.
    - Misrepresentation of product information, damaging brand reputation.
- Impact:
  - **High:** If exploited via spreadsheet software, this vulnerability can lead to arbitrary command execution on a user's machine, potentially allowing an attacker to gain control, steal sensitive information, or perform other malicious actions. Even without command execution, malicious content injection can be used for phishing or social engineering.
  - **Medium:** If exploited via Google Merchant Center, this vulnerability can lead to data corruption, unintended modifications of product listings, and misrepresentation of product information, causing reputation damage, financial loss, and potential legal/compliance issues.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
  - None. The project does not implement any CSV/TSV sanitization or output escaping to prevent CSV injection. The BigQuery Load API is used with default settings that do not inherently sanitize against CSV injection. The project relies on `feed_schema_config.json` for data mapping but not for content sanitization.
- Missing Mitigations:
  - **Input Sanitization:** Implement robust CSV/TSV sanitization within the `_perform_bigquery_load` function in `/code/cloud_functions/gcs-bq-feed-load/main.py` before loading data into BigQuery. This should include:
    - Validating data types according to the `feed_schema_config.json`.
    - Escaping or removing characters that spreadsheet software interprets as formula indicators (e.g., '=', '@', '+', '-').
    - Using a library specifically designed for secure CSV/TSV handling.
  - **Output Encoding:** Ensure proper output encoding when data from BigQuery is used to construct Content API requests to Google Merchant Center.
  - **Documentation and User Warnings:** Add a prominent security warning in the README.md and Dev Ops guide (`/code/documentation/maintenance-guide.md`) about the risks of CSV injection. Advise users to exercise extreme caution when handling CSV/TSV files downloaded from the FeedLoader system and from untrusted sources. Recommend opening CSV files in plain text editors for inspection before using spreadsheet software.
- Preconditions:
  - An attacker must be able to upload a malicious CSV/TSV file to the `FEED_BUCKET`. This could be achieved through:
    - Compromising a user account with write access to the `FEED_BUCKET`.
    - Exploiting a misconfiguration that allows public uploads to the `FEED_BUCKET`.
    - Socially engineering a user with upload access to upload a malicious file.
  - A user with access to the BigQuery `feed_data.items` table or the `FEED_BUCKET` must download and open the processed feed data with spreadsheet software susceptible to CSV injection, or the data must be processed by a vulnerable Google Merchant Center system.
- Source Code Analysis:
  - File: `/code/cloud_functions/gcs-bq-feed-load/main.py`
  - Function: `_perform_bigquery_load`
  - Step-by-step analysis:
    1. The `_perform_bigquery_load` function loads CSV/TSV feed files from Google Cloud Storage into BigQuery.
    2. It initializes a `bigquery.LoadJobConfig` object.
    3. **Vulnerability Point:** The `bigquery.LoadJobConfig` is configured with `source_format=bigquery.SourceFormat.CSV` and `quote_character=''`. Setting `quote_character` to an empty string disables quote-based escaping.
    4. No input sanitization is performed on the CSV/TSV data before loading it into BigQuery.
    5. The `bigquery_client.load_table_from_uri` function loads data from GCS URI into BigQuery `items` table using the vulnerable configuration.
    6. Data from BigQuery is subsequently processed and sent to Google Merchant Center via Content API without sanitization in the FeedLoader pipeline.
  - Visualization:
    ```
    [Malicious CSV/TSV File] --> Upload to FEED_BUCKET --> [Cloud Function: import_storage_file_into_big_query] --> [BigQuery Load API (Vulnerable Config)] --> [BigQuery: feed_data.items] --> [Data Processing Pipeline] --> [Google Merchant Center Content API] --> [Google Merchant Center (Potential Vulnerability)] --> [User Download CSV/TSV OR GMC Display] --> [Spreadsheet Software (Vulnerable) OR GMC Interface (Potentially Vulnerable)] --> [Command Execution/Malicious Content Injection/Data Manipulation]
    ```
- Security Test Case:
  1. **Setup:** Ensure a running FeedLoader instance deployed to GCP, permissions to interact with GCS and BigQuery, and access to a Google Merchant Center account.
  2. **Create Malicious CSV File:** Create `malicious_feed.csv` with the following content, including a formula in the `description` field:
     ```csv
     item_id,title,description
     testitem1,Test Product 1,"=SYSTEM(\"calc.exe\")"
     testitem2,Test Product 2,"Normal description"
     ```
  3. **Upload Malicious CSV:** Upload `malicious_feed.csv` to the `FEED_BUCKET` using `gsutil cp malicious_feed.csv gs://<YOUR_FEED_BUCKET>/`.
  4. **Trigger Feed Processing:** Create an empty EOF file and upload it to the `UPDATE_BUCKET` to initiate processing.
  5. **Wait for Processing:** Monitor Cloud Function logs for completion.
  6. **Query BigQuery:** Query `feed_data.items` table in BigQuery console.
  7. **Download CSV from BigQuery:** Download query results as CSV.
  8. **Open CSV in Spreadsheet Software:** Open downloaded CSV in software like Microsoft Excel or Google Sheets.
  9. **Verify Vulnerability (Spreadsheet Software):** Observe if the spreadsheet software executes the injected formula (e.g., Calculator opens).
  10. **Monitor Google Merchant Center (Optional):** Check product listings in GMC for any unexpected changes or rendering issues, although direct frontend CSV injection in GMC is less likely.
  11. **Check Logs:** Review Cloud Function and App Engine logs for any errors or warnings during processing.

This security test case confirms the CSV injection vulnerability exists in the FeedLoader project, with potential impacts on both users opening exported data and potentially on Google Merchant Center.