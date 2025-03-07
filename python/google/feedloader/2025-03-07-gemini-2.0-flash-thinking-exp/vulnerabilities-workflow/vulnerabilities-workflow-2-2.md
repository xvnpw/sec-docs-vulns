### Vulnerability List

* Vulnerability Name: CSV Injection in Feed Files

* Description:
  1. An attacker crafts a malicious CSV or TSV feed file.
  2. Within this file, the attacker injects special characters or escape sequences into one or more fields. For example, using characters like '=', '@', '+', or '-' at the beginning of a cell, or using formulas if the CSV is opened in spreadsheet software.
  3. The attacker uploads this crafted feed file to the designated Cloud Storage bucket (`FEED_BUCKET`).
  4. FeedLoader's `import_storage_file_into_big_query` Cloud Function is triggered upon file upload.
  5. The Cloud Function processes the feed file using `bigquery_client.load_table_from_uri` and loads the data into a BigQuery table (`feed_data.items`).
  6. If the injected malicious data is not properly sanitized during BigQuery load or subsequent processing, it can be interpreted as commands or special values when the data is later used within Google Merchant Center or exported to other systems.
  7. While BigQuery is generally safe from direct CSV injection exploits that would compromise BigQuery infrastructure, the injected data can still be passed through to Google Merchant Center via Content API.
  8. This could lead to data corruption within the user's Google Merchant Center account, unintended modifications of product listings, or misrepresentation of product information.

* Impact:
  - Data corruption in Google Merchant Center: Malicious formulas or injected content could alter product data displayed in GMC, leading to inaccurate or misleading information for customers.
  - Unintended modifications of product listings: Attackers might be able to manipulate product attributes, potentially causing listings to be disapproved or displayed incorrectly.
  - Misrepresentation of product information: Injected content could lead to the display of false or misleading product details, damaging the user's brand reputation and potentially violating Google Merchant Center policies.

* Vulnerability Rank: Medium

* Currently Implemented Mitigations:
  - The project relies on BigQuery's CSV parsing capabilities for loading feed files. BigQuery itself offers some level of protection against direct CSV injection exploits that could compromise BigQuery infrastructure. However, it does not sanitize data for downstream applications like Google Merchant Center.
  - No explicit data sanitization or validation is implemented within the FeedLoader code to handle potentially malicious CSV content before loading data into BigQuery or sending it to Google Merchant Center.

* Missing Mitigations:
  - Input sanitization: Implement robust input sanitization and validation within the `import_storage_file_into_big_query` Cloud Function before loading data into BigQuery. This should include:
    - Validating data types according to the `feed_schema_config.json`.
    - Escaping special characters that could be misinterpreted by CSV parsers or spreadsheet software.
    - Consider using a dedicated CSV parsing library with security features to handle potential injection attempts.
  - Output Encoding: Ensure proper output encoding when data from BigQuery is used to construct Content API requests. This can help prevent injected code from being executed or misinterpreted by Google Merchant Center.

* Preconditions:
  - The attacker needs to be able to craft a malicious CSV/TSV feed file.
  - The user must upload and process this malicious feed file using FeedLoader.

* Source Code Analysis:

  1. **File Input**: The `import_storage_file_into_big_query` Cloud Function (`/code/cloud_functions/gcs-bq-feed-load/main.py`) is triggered by file uploads to the `FEED_BUCKET`.
  2. **CSV Parsing and BigQuery Load**:
     ```python
     bigquery_job_config = bigquery.LoadJobConfig(
         allow_jagged_rows=True,
         encoding='UTF-8',
         field_delimiter='\t',
         quote_character='',
         schema=items_table_bq_schema,
         skip_leading_rows=1,
         source_format=bigquery.SourceFormat.CSV,
         time_partitioning=bigquery.table.TimePartitioning(
             type_=_TABLE_PARTITION_GRANULARITY,
             expiration_ms=_ITEMS_TABLE_EXPIRATION_DURATION_MS),
         write_disposition='WRITE_APPEND',
     )

     gcs_uri = f'gs://{bucket_name}/{filename}'
     feed_table_path = f"{os.environ.get('BQ_DATASET')}.items"

     bigquery_load_job = bigquery_client.load_table_from_uri(
         gcs_uri, feed_table_path, job_config=bigquery_job_config)
     ```
     - The code uses `bigquery_client.load_table_from_uri` to load CSV/TSV data into BigQuery.
     - The `bigquery.SourceFormat.CSV` is used, indicating CSV parsing.
     - The `quote_character` is set to empty string, which might affect how quotes are handled, but doesn't directly mitigate CSV injection.
     - There is no explicit sanitization or validation of the CSV data before or during the BigQuery load process within this code.
  3. **Data Flow to Content API**:
     - After data is loaded into BigQuery (`feed_data.items`), it is processed further by other components (e.g., `calculate_product_changes` Cloud Function and App Engine uploader) and eventually sent to Google Merchant Center via Content API.
     - The code doesn't show explicit sanitization steps between BigQuery and Content API calls.

  **Visualization**:
  ```
  [Attacker: Malicious CSV Feed File] --> [GCS FEED_BUCKET] --> [Cloud Function: import_storage_file_into_big_query] --> [BigQuery: feed_data.items (potentially vulnerable data)] --> [FeedLoader Processing Pipeline] --> [Google Merchant Center (potentially corrupted data)]
  ```

* Security Test Case:

  1. **Prerequisites**:
     - Set up a FeedLoader instance in a GCP project.
     - Obtain access to upload files to the `FEED_BUCKET` (in a real-world scenario, assume an external attacker cannot directly access the bucket, but can influence the feed data before it's uploaded by the user).
     - Have a Google Merchant Center account linked to the GCP project.

  2. **Steps**:
     - Create a malicious CSV file (e.g., `malicious_feed.csv`) with injected content in a field, for example, in the `title` field, insert `=HYPERLINK("http://malicious.example.com","Click Here")` or a simple string like `=1+1+cmd|' /C calc'!A0`. For TSV, use tab-separated values.
     - Upload `malicious_feed.csv` to the `FEED_BUCKET` using `gsutil cp -j csv malicious_feed.csv gs://$FEED_BUCKET/`.
     - Create an empty EOF file: `touch EOF`.
     - Upload the EOF file to trigger FeedLoader processing: `gsutil cp EOF $UPDATE_BUCKET`.
     - Wait for FeedLoader to process the feed and complete the data upload to Google Merchant Center.
     - Access the Google Merchant Center UI and check the product listings that were supposed to be updated by the malicious feed.
     - Examine the `title` or other fields where you injected the malicious content.

  3. **Expected Result**:
     - In a vulnerable scenario, when opening the GMC product data (or if exported and opened in spreadsheet software), the injected formula or malicious content might be executed or displayed, demonstrating CSV injection. The data in GMC might be corrupted or show unexpected values based on the injected content.
     - In a mitigated scenario, the injected content should be treated as plain text, and no malicious formula execution or data corruption should occur in GMC. The GMC UI should display the injected string literally, without interpreting it as a command or formula.

  4. **Cleanup**:
     - Delete the malicious feed file from the `FEED_BUCKET`.
     - Delete any corrupted product listings from Google Merchant Center if necessary.