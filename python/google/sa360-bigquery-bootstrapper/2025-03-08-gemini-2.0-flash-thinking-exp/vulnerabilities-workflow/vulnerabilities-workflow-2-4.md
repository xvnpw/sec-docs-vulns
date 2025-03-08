- Vulnerability name: CSV Data Injection

- Description:
    1. An attacker crafts a malicious CSV file containing data designed to inject false or misleading information into BigQuery views.
    2. The attacker uploads this malicious CSV file to the Google Cloud Storage bucket used by the bootstrapper, or uploads it directly via Cloud Shell if that option is used.
    3. The user runs the bootstrapper script, which processes the uploaded CSV file using `csv_decoder.py` and `bootstrapper.py`.
    4. `csv_decoder.py` reads the CSV data using pandas and renames columns based on configuration, but it does not sanitize the *data* within the CSV rows.
    5. `bootstrapper.py` loads this data into a BigQuery table (historical data table).
    6. `views.py` creates BigQuery views that query this historical data table.
    7. Because the CSV data is not sanitized, the BigQuery views contain the malicious data. This can lead to:
        - Display of incorrect or misleading data in reports and dashboards connected to these views.
        - Skewed analytics and potentially wrong business decisions.
        - Data integrity issues within the BigQuery datasets.

- Impact:
    - Compromised data integrity in BigQuery views and reports.
    - Display of incorrect or misleading information in connected dashboards (e.g., Data Studio).
    - Potential for skewed business analytics and incorrect decision-making.
    - Risk of data poisoning if the views are used for data export or further processing.

- Vulnerability rank: Medium

- Currently implemented mitigations:
    - Column renaming in `csv_decoder.py` based on a predefined mapping (`dict_map`) helps control column names.
    - Use of `pandas.read_csv` is generally safe from direct code execution during CSV parsing.
    - SQL queries in `views.py` are parameterized using settings and table/column names programmatically.

- Missing mitigations:
    - **Data Sanitization:** Lack of input sanitization for the *data* within the CSV rows. No validation or sanitization of values loaded from CSV.
    - **Data Validation:** No validation of data types, ranges, or formats of the CSV data against expected schemas before loading into BigQuery.

- Preconditions:
    - The attacker needs to upload a malicious CSV file to the GCS bucket used by the bootstrapper or via Cloud Shell. This could be due to:
        - Compromised user's Google Cloud account or write access to the GCS bucket (less likely for external attacks).
        - User being tricked into uploading a malicious file via Cloud Shell (social engineering, less likely a direct system attack).

- Source code analysis:
    1. `/code/csv_decoder.py`: `Decoder.FileDecoder.decode_csv` and `Decoder.FileDecoder.decode_excel` use `pandas.read_csv` and `pandas.read_excel` for parsing, which are safe from direct command injection. `Decoder.__init__` and `Decoder.FileDecoder._read` remap column names, sanitizing headers but not data values.
    2. `/code/bootstrapper.py`: `Bootstrap.combine_folder` uses `csv_decoder.Decoder` for CSV processing. `Bootstrap.load_historical_tables` loads CSV data into BigQuery without sanitization, assuming data from CSV is safe.
    3. `/code/views.py`: View definition methods (e.g., `historical_conversions`, `report_view`) construct parameterized SQL queries using settings and CSV-derived table/column names. Data from the historical table (from CSV) is used directly in queries without further sanitization.

- Security test case:
    1. Setup: Deploy SA360 BigQuery Bootstrapper in a test GCP project with historical data upload enabled.
    2. Malicious CSV: Create a CSV (e.g., `malicious.csv`) with misleading data:
       ```csv
       date,keyword,conversions
       2024-01-01,malicious_keyword,999999999
       2024-01-02,normal_keyword,10
       ```
    3. Upload: Upload `malicious.csv` to the bootstrapper's GCS bucket or via Cloud Shell.
    4. Run Bootstrapper: Execute `run.py` to process historical data with correct configurations.
    5. Check BigQuery Views: Query generated BigQuery views (e.g., `views.ReportView_[Advertiser ID]`).
    6. Verify Data Injection: Confirm presence of injected data in views, e.g., high conversions for "malicious_keyword" on '2024-01-01'.
    7. Impact Demo: Connect a Data Studio dashboard to `ReportView` and verify misleading data is displayed, demonstrating impact on reporting.