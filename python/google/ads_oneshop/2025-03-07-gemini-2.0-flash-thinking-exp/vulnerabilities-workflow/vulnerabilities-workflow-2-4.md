### Vulnerability List

* Vulnerability Name: Benchmark CSV Injection
* Description:
    1. An attacker gains access to the publicly available `benchmark_details.csv` and `benchmark_values.csv` files from the GitHub repository.
    2. The attacker opens these CSV files using a text editor or spreadsheet software.
    3. The attacker injects malicious data into the CSV files by adding new rows or modifying existing rows. This injected data can be fabricated to skew benchmark values or introduce misleading information. For example, the attacker could insert extremely high or low benchmark values for specific categories or time periods.
    4. The attacker saves the modified CSV files.
    5. A legitimate user, following the project's setup instructions, downloads these (now compromised) CSV files.
    6. The user manually uploads these modified CSV files to their BigQuery dataset, creating or overwriting the `MEX_benchmark_details` and `MEX_benchmark_values` tables as instructed.
    7. The Ads OneShop pipeline processes this data, and the MEX4P dashboards and reports are generated using the attacker-injected benchmark data.
* Impact:
    - The primary impact is the corruption of data integrity within the Merchant Excellence for Partners (MEX4P) dashboards and reports.
    - Users relying on these dashboards will be presented with flawed and potentially misleading business insights due to the injected false benchmark data.
    - This can lead to merchants making incorrect assessments of their Google Merchant Center performance and adopting inappropriate or ineffective optimization strategies.
    - The credibility and trustworthiness of the Ads OneShop project and its MEX4P solution are severely undermined.
    - Inaccurate benchmark data can also negatively impact any AI/ML models that rely on this benchmark information for training or inference, potentially leading to further flawed recommendations and predictions within the Merchant Excellence solution (as mentioned in `/code/extensions/merchant_excellence/model/README.md`).
* Vulnerability Rank: High
* Currently Implemented Mitigations:
    - None. The project relies on users manually downloading and uploading benchmark CSV files without any implemented validation or sanitization within the provided codebase or setup instructions. There are no checks in the provided scripts or documentation to ensure the integrity of the uploaded benchmark data.
* Missing Mitigations:
    - Implement input validation and sanitization for the benchmark CSV files before they are ingested into BigQuery. This should include:
        - File format validation: Verify that the uploaded files are indeed valid CSV files and adhere to the expected CSV format.
        - Schema validation: Ensure that the CSV files contain the expected columns with correct headers and data types, as defined by the intended schema for `MEX_benchmark_details` and `MEX_benchmark_values` tables.
        - Data type validation: Validate the data type of each column to prevent injection of unexpected data types (e.g., strings where numbers are expected) which could be exploited.
        - Data sanitization: Sanitize the data to escape special characters or malicious payloads that could be injected into the CSV content.
        - Consider automating the benchmark data update process from a trusted source instead of relying on manual uploads from potentially compromised files.
* Preconditions:
    - Public accessibility of `benchmark_details.csv` and `benchmark_values.csv` files in the GitHub repository, making them easily modifiable by anyone.
    - Users must manually download and upload these CSV files to their BigQuery datasets as part of the MEX4P setup, following the instructions which currently lack security guidance.
    - The Merchant Excellence for Partners (MEX4P) feature must be enabled (`export RUN_MERCHANT_EXCELLENCE=true` in `env.sh`) for the benchmark data to be used in the dashboards.
* Source Code Analysis:
    - The provided project files do not contain any code responsible for processing or validating the `benchmark_details.csv` and `benchmark_values.csv` files before they are used in the MEX4P dashboards.
    - The files `/code/deploy_job.sh`, `/code/run_job.sh`, `/code/schedule_job.sh`, and scripts within `/code/src/acit/` and `/code/extensions/merchant_excellence/` directories are focused on the automated data pipeline for Google Ads and Merchant Center data, and the Merchant Excellence model. They do not include any logic for handling the benchmark CSV file uploads or performing validation on them.
    - The `README.md` and `walkthrough.md` documentation explicitly instruct users to manually download and upload these CSV files to BigQuery. This manual upload process occurs outside of the automated pipeline and lacks any security checks within the provided code.
    - The vulnerability arises from the project's design which assumes the integrity of manually uploaded benchmark CSV files without implementing any automated validation or sanitization measures within the provided codebase.

* Security Test Case:
    1. **Setup:** Ensure you have a deployed instance of Ads OneShop with MEX4P enabled and access to the BigQuery dataset associated with your deployment.
    2. **Download Benchmark Files:** Download `benchmark_values.csv` from the project's GitHub repository ([benchmark_values.csv](benchmark/benchmark_values.csv) as linked in `README.md`).
    3. **Modify Benchmark File:** Open the downloaded `benchmark_values.csv` file using a text editor or spreadsheet program.
    4. **Inject Malicious Data:** Locate a specific benchmark metric within the CSV file. For example, find the 'Conversion Rate' metric for a particular product category and date. Modify the corresponding value to an extremely high number (e.g., `999999`).  Alternatively, add a new row with fabricated data, ensuring it conforms to the CSV structure but contains injected false benchmark values.
    5. **Save Modified File:** Save the changes to the `benchmark_values.csv` file.
    6. **Upload to BigQuery:** Using the Google Cloud Console or BigQuery CLI, manually upload the *modified* `benchmark_values.csv` file (and the original `benchmark_details.csv` if you haven't modified it) to your BigQuery dataset, overwriting or creating the `MEX_benchmark_values` (and `MEX_benchmark_details`) tables as per the instructions in `README.md` or `walkthrough.md`. Ensure you use the recommended table names.
    7. **Run Data Pipeline (if necessary):** If the dashboards are not automatically updated, manually trigger the Ads OneShop data pipeline by running `./run_job.sh` or by using Cloud Scheduler if configured. This step might not be necessary if the dashboards directly query the BigQuery tables and update automatically.
    8. **Access MEX4P Dashboard:** Open the MEX4P dashboard in Looker Studio.
    9. **Verify Data Injection:** Navigate to the reports or pages within the MEX4P dashboard that display benchmark data, particularly the metric you modified (e.g., 'Conversion Rate' report).
    10. **Observe Impact:** Check if the injected malicious data is reflected in the dashboard. For instance, verify if the 'Conversion Rate' for the category and date you modified now displays the injected value `999999` or the fabricated data you introduced. If the dashboard reflects the manipulated benchmark data, the CSV injection vulnerability is successfully demonstrated.