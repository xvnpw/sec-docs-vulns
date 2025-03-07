* Vulnerability Name: BigQuery Input Data Manipulation
* Description:
    1. An attacker gains unauthorized write access to the BigQuery tables specified by `TABLE_CONSENT` and `TABLE_NOCONSENT` environment variables.
    2. The attacker inserts malicious data into these BigQuery tables. This could involve injecting fabricated conversion records, modifying existing records to skew features (e.g., adgroup, device type), or deleting legitimate data.
    3. The Cloud Function triggers the Apache Beam pipeline, which reads data directly from these BigQuery tables using the `_load_data_from_bq` function in `pipeline.py`.
    4. The pipeline proceeds with data preprocessing and nearest neighbor calculations using the manipulated data from BigQuery.
    5. Due to the injected or altered data, the nearest neighbor calculations become skewed and inaccurate.
    6. Consequently, the conversion adjustments applied by the pipeline are corrupted, leading to incorrect up-weighting of conversion values for consented users.
    7. The pipeline outputs a CSV file with these inaccurate adjusted conversion values to Google Cloud Storage, intended for Offline Conversion Import (OCI) into Google Ads.
    8. Advertisers using this OCI data will make bidding and campaign performance decisions based on statistically flawed conversion adjustments, negatively impacting their advertising effectiveness.
* Impact:
    - Inaccurate statistical conversion adjustments.
    - Corrupted output CSV data for Offline Conversion Import (OCI).
    - Misinformed bidding strategies and reduced campaign performance for advertisers using Google Ads.
    - Potential financial losses for advertisers due to ineffective ad spending.
    - Loss of trust in the conversion adjustment solution.
* Vulnerability Rank: High
* Currently Implemented Mitigations:
    - None. The code directly reads and processes data from BigQuery without any input validation or sanitization to prevent data manipulation.
* Missing Mitigations:
    - **Input Data Validation:** Implement validation checks within the `_load_data_from_bq` function or within the `ConversionAdjustments` ParDo in `pipeline.py`. This validation should include:
        - Schema validation to ensure the BigQuery tables conform to the expected schema.
        - Data integrity checks to detect anomalies or inconsistencies in the input data, such as unexpected data types, out-of-range values, or duplicate entries.
        - Sanitization of input data to prevent injection attacks, although less relevant in this specific data manipulation context, basic sanitization can still improve robustness.
    - **Access Control Hardening:** While not a code mitigation, emphasize the importance of robust access control measures for the BigQuery tables and the Google Cloud Storage bucket. This includes:
        - Principle of least privilege: Grant write access to the BigQuery tables only to authorized and necessary service accounts or users.
        - Regular audits of access permissions to BigQuery and GCS resources.
        - Strong authentication and authorization mechanisms for accessing Google Cloud resources.
* Preconditions:
    - The attacker must gain write access to the BigQuery tables (`TABLE_CONSENT` and `TABLE_NOCONSENT`) used as input for the pipeline. This could be achieved through:
        - Compromised Google Cloud account credentials with sufficient permissions.
        - Insider threat with malicious intent and necessary BigQuery write permissions.
        - Vulnerabilities in other systems or processes that allow unauthorized modification of BigQuery data.
    - The Cloud Function and Dataflow pipeline must be configured to read from the compromised BigQuery tables.
* Source Code Analysis:
    - **pipeline.py:**
        - The `_load_data_from_bq` function directly executes a SQL query against the BigQuery tables specified by the `table_name` parameter, which is derived from the runtime argument `--table_consent` or `--table_noconsent`.
        ```python
        def _load_data_from_bq(table_name: str, location: str, project: str,
                               start_date: str, end_date: str,
                               date_column: str) -> pd.DataFrame:
          bq_client = bigquery.Client(location=location, project=project)
          query = f"""
                   SELECT * FROM `{table_name}`
                   WHERE {date_column} >= '{start_date}' and {date_column} < '{end_date}'
                   ORDER BY {date_column}
                   """
          return bq_client.query(query).result().to_dataframe()
        ```
        - The `ConversionAdjustments` class in `pipeline.py` processes the DataFrame returned by `_load_data_from_bq` without any explicit validation of the data's integrity or source.
        ```python
        class ConversionAdjustments(beam.DoFn):
            # ...
            def process(
                self, process_date: datetime.date
            ) -> Optional[Sequence[Tuple[str, pd.DataFrame, pd.DataFrame]]]:
                # ...
                data_noconsent = _load_data_from_bq(self._table_noconsent, self._location,
                                                    self._project, start_date, end_date,
                                                    self._date_column)
                data_consent = _load_data_from_bq(self._table_consent, self._location,
                                                  self._project, start_date, end_date,
                                                  self._date_column)
                # ... process data_consent, data_noconsent without validation
        ```
    - **cocoa/preprocess.py and cocoa/nearest_consented_customers.py:**
        - The preprocessing and nearest neighbor calculation logic in the `cocoa` directory operate on the DataFrames received from `pipeline.py`. These modules assume the input data is valid and do not implement checks to detect or handle manipulated data originating from BigQuery.
* Security Test Case:
    1. **Prerequisites:**
        - Set up the Apache Beam pipeline and Cloud Function in a test Google Cloud project.
        - Identify the BigQuery datasets and tables used for consent and non-consent data (e.g., using environment variables in `generate_template.sh` and `cloud_function/main.py`).
        - Obtain write access to these BigQuery tables in the test project (for testing purposes only).
    2. **Data Manipulation:**
        - Directly using BigQuery console, bq command-line tool, or BigQuery API, insert a malicious record into the `TABLE_CONSENT` table. This record should have characteristics designed to skew the nearest neighbor calculations. For example, insert a record with an unusually high `conversion_value` and distinct feature values in columns used for matching (e.g., `conversion_item`, ad group features).
        ```sql
        -- Example SQL to insert malicious data into TABLE_CONSENT (replace with actual table name and schema)
        INSERT INTO `[YOUR_BIGQUERY_PROJECT_ID].[YOUR_BIGQUERY_DATASET].[YOUR_TABLE_CONSENT]` (gclid, conversion_timestamp, conversion_value, conversion_date, conversion_item, ...)
        VALUES ('malicious_gclid_001', '2023-11-20 12:00:00 UTC', 1000000, '2023-11-20', 'malicious_item', ...);
        ```
    3. **Trigger Pipeline:**
        - Trigger the Cloud Function to initiate the Apache Beam pipeline execution (e.g., by simulating a BigQuery log event or manually triggering the Cloud Function).
    4. **Observe Output:**
        - After the pipeline completes, examine the output CSV file in the designated Google Cloud Storage bucket.
        - Analyze the `adjusted_conversion` values in the output CSV. Check if the malicious record injected in step 2 has disproportionately influenced the conversion adjustments for other records, especially those that should not be related to the malicious data.
        - Compare the output with a baseline run without the malicious data to quantify the impact of the data manipulation.
    5. **Verification:**
        - If the `adjusted_conversion` values are significantly skewed due to the injected malicious data, the vulnerability is confirmed. This demonstrates that an attacker with BigQuery write access can successfully manipulate the pipeline's output by injecting data.