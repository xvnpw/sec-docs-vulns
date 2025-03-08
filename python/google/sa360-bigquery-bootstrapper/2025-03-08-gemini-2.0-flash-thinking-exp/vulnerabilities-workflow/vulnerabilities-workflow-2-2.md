### Vulnerability List

- Vulnerability Name: CSV Injection
- Description:
    1. An attacker crafts a malicious CSV file. This file contains a cell with a formula, for example, `=SUM(1+1)`.
    2. The attacker uploads this malicious CSV file as historical data to be processed by the SA360 BigQuery Bootstrapper. This could be done by uploading to a Google Cloud Storage bucket that the application is configured to read from, or via other upload mechanisms if available.
    3. The SA360 BigQuery Bootstrapper processes this CSV file using the `csv_decoder.py` and loads the data, including the injected formula as plain text, into Google BigQuery raw tables.
    4. The application then creates BigQuery views based on this raw data, as defined in `views.py`. These views will also contain the injected formula as data, as no sanitization is performed.
    5. A user then accesses these BigQuery views using a data visualization tool such as DataStudio, or exports the data to a CSV file for use in spreadsheet software.
    6. If the tool used to view or export the data interprets strings starting with an equals sign (`=`) as formulas (like spreadsheet applications such as Google Sheets or Microsoft Excel), the injected formula from the CSV will be executed. This could lead to unintended actions, such as information disclosure if the formula is designed to access external data or perform malicious operations within the viewing application's context.
- Impact:
    - If a user views the BigQuery data through a vulnerable application like DataStudio or exports it to spreadsheet software, the injected formulas can be executed.
    - The impact depends on the capabilities of the viewing application and the nature of the injected formula. Potential impacts include:
        - **Information Disclosure:** Formulas could be crafted to retrieve and display sensitive information accessible to the user viewing the data within the context of the viewing application.
        - **Client-Side Command Execution (in vulnerable viewers):**  In some spreadsheet software, external commands or web requests can be initiated through formulas, potentially leading to further exploitation depending on the viewer's security context and vulnerabilities.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations:
    - None. The provided code does not include any explicit sanitization or input validation to prevent CSV injection. The application processes the CSV data as provided and loads it into BigQuery without inspecting for or neutralizing potentially malicious formulas.
- Missing Mitigations:
    - **Input Sanitization:** The application should sanitize the data read from CSV files before loading it into BigQuery. This should include:
        - **Formula Detection and Neutralization:** Implement checks to identify cells in CSV files that start with characters commonly used to denote formulas (e.g., `=`, `@`, `+`, `-`).
        - **Formula Stripping or Escaping:**  Either remove leading formula characters to treat the cell content as plain text, or escape these characters in a way that prevents formula execution by viewing applications (e.g., by prepending a single quote `'` in CSV, though effectiveness depends on the viewing application).
- Preconditions:
    1. The 'Include Historical Data' option must be enabled in the SA360 BigQuery Bootstrapper configuration, allowing the application to process historical CSV data.
    2. An attacker needs to be able to provide a malicious CSV file. This could involve:
        - Compromising a system or storage location from where the application reads CSV files.
        - Socially engineering a user with access to upload or place the malicious CSV file in a location processed by the application.
    3. A user must interact with the BigQuery data (views or tables created by the application) using a tool that is susceptible to CSV injection, such as DataStudio or spreadsheet software when exporting to CSV and opening it locally.
- Source Code Analysis:
    - **`csv_decoder.py`**: This file is responsible for decoding CSV files. It uses the `pandas` library to read CSV data.
        ```python
        import pandas as pd
        # ...
        df = pd.read_csv(
            self.path,
            encoding=encoding,
            dtype=self.parent.dtypes,
            thousands=self.parent.thousands,
        )
        ```
        - `pandas.read_csv` reads the CSV data into a DataFrame. It does not perform formula execution upon reading. The data is read as strings or numbers based on the CSV content and specified `dtype`.
        - There is no sanitization logic within `csv_decoder.py` to detect or prevent formula injection. The raw content of the CSV is processed and passed along.

    - **`bootstrapper.py`**: This file orchestrates the data loading process. The `load_historical_tables` function uses `csv_decoder.py` to process CSV files and load them into BigQuery:
        ```python
        with Decoder(
            desired_encoding='utf-8',
            locale=s.custom['locale'],
            dest=dest_filename,
            path=path,
            out_type=Decoder.SINGLE_FILE,
            dict_map=dict_map,
        ) as decoder:
            result_dir = decoder.run()
            dest_blob = bucket.blob(dest_filename)
            dest_blob.upload_from_filename(result_dir)
            # ... load to BigQuery ...
        ```
        - The bootstrapper uses the `Decoder` class to handle CSV processing but does not add any sanitization steps before or after decoding.

    - **`views.py`**: This file defines SQL queries to create BigQuery views (e.g., `historical_conversions`, `report_view`, `historical_report`). These views are created based on the raw data loaded from CSVs.
        ```python
        sql = """SELECT
            h.date,
            a.keywordId{deviceSegment},
            a.keywordMatchType MatchType,
            h.ad_group AdGroup,
            {conversions} conversions,
            {revenue} revenue
          FROM `{project}`.`{raw}`.`{historical_table_name}` h
          INNER JOIN (...) a
            ON ...
          GROUP BY ...""" # Example from historical_conversions
        return sql
        ```
        - The SQL queries in `views.py` select and transform data from the raw tables. They do not introduce formula injection themselves, but they propagate any injected formulas from the raw CSV data into the views.
        - The views are created without any sanitization of the underlying data.

    - **Visualization:**
        ```mermaid
        graph LR
        A[Attacker crafts malicious CSV with formula] --> B(Uploads CSV as historical data);
        B --> C(SA360 BigQuery Bootstrapper processes CSV using csv_decoder.py);
        C --> D[Data (including formula as text) loaded into BigQuery raw tables];
        D --> E(BigQuery Views created using views.py);
        E --> F[User views/exports data using DataStudio/Spreadsheet software];
        F --> G{Vulnerable Viewer (e.g., DataStudio, Excel)?};
        G -- Yes --> H[Formula Execution in Viewer];
        G -- No --> I[Data displayed as text];
        H --> J[Potential Information Disclosure or Unintended Actions];
        ```

- Security Test Case:
    1. **Prepare Malicious CSV:** Create a CSV file named `malicious_data.csv` with the following content:
        ```csv
        Date,Account Name,Campaign Name,Ad Group,Keyword,Match Type,Conversions,Revenue
        2023-01-01,Test Account,Test Campaign,Test Ad Group,"=SUM(1+1)",Exact,10,100
        2023-01-02,Test Account,Test Campaign,Test Ad Group,keyword2,Phrase,5,50
        ```
    2. **Upload CSV to Storage Bucket:** Upload `malicious_data.csv` to the Google Cloud Storage bucket configured for historical data input for the SA360 BigQuery Bootstrapper.
    3. **Run Bootstrapper:** Configure and run the SA360 BigQuery Bootstrapper, ensuring that it is set to process historical data and is pointed to the storage bucket containing `malicious_data.csv`. Follow the tutorial steps to execute the bootstrapper, including running `pipenv run python run.py --gcp_project_name={{project-id}} --interactive`.
    4. **Access BigQuery Console:** Navigate to the BigQuery console in your Google Cloud project.
    5. **Query BigQuery View:** Locate the 'views' dataset and the 'ReportView_[Advertiser ID]' view (or any view that includes historical data). Run a query to select data from this view, for example: `SELECT * FROM views.ReportView_[Advertiser ID]`.
    6. **Export to CSV:** In the BigQuery console, export the results of the query to a CSV file (e.g., "Export" -> "CSV (local file)").
    7. **Open Exported CSV in Spreadsheet Software:** Open the exported CSV file (e.g., `export.csv`) using spreadsheet software like Google Sheets or Microsoft Excel.
    8. **Observe Formula Execution:** Check the cell in the "Keyword" column for the first row. If the spreadsheet software executes the formula, you will see "2" displayed in the cell instead of the raw string `=SUM(1+1)`. This confirms the CSV injection vulnerability. Alternatively, observe the same column directly within DataStudio if creating a report based on the BigQuery view.