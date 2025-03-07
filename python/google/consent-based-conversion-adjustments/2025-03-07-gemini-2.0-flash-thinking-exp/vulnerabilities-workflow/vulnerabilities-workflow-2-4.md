- vulnerability name: Input Data Manipulation / Data Injection in BigQuery tables
  description: |
    Attackers can manipulate the input data in the BigQuery tables (`table_consent`, `table_noconsent`) used by the pipeline.
    This can be done by directly modifying the tables or by injecting new, fabricated records.
    The manipulation can include:
      - Modifying existing records to skew feature values or conversion values.
      - Injecting completely fabricated records with specific features and conversion values designed to influence the nearest neighbor calculations.
      - Deleting genuine records, although this is less likely to be used for skewing and more for denial of service, which is out of scope.

    Step-by-step trigger:
      1. Attacker gains write access to the BigQuery dataset containing the `table_consent` and `table_noconsent` tables. This could be through compromised credentials, misconfigured IAM permissions, or other vulnerabilities in the BigQuery access control system (which are outside the scope of this project itself, but represent the precondition).
      2. Attacker connects to the BigQuery dataset using their gained access.
      3. Attacker crafts and executes SQL queries to insert malicious data into `table_consent` or `table_noconsent`. For example, they could insert rows into `table_noconsent` with extremely high `conversion_value` or with specific feature combinations designed to disproportionately influence the nearest neighbor algorithm.
      4. The Cloud Function is triggered (e.g., by new data insertion in BigQuery or scheduled trigger) and initiates the Dataflow pipeline.
      5. The Dataflow pipeline, in its initial steps, reads the data from the BigQuery tables, including the attacker-injected malicious data.
      6. The pipeline proceeds with data preprocessing and nearest neighbor calculations, unknowingly using the manipulated data.
      7. The final output CSV file contains conversion adjustments that are skewed due to the malicious input data.
  impact: |
    The primary impact is skewed conversion adjustments.
    This leads to inaccurate and unreliable bidding performance for advertisers who rely on this solution.
    Specifically, the consequences are:
      - **Wasted ad spend:**  Bidding strategies might be based on inflated or deflated conversion values, leading to inefficient allocation of advertising budgets.
      - **Missed opportunities:** Inaccurate conversion adjustments can cause advertisers to miss out on valuable conversions by underbidding or targeting the wrong audiences.
      - **Damaged advertiser trust:** If advertisers notice a decline in bidding performance or discrepancies in conversion data due to data manipulation, it can erode their trust in the advertising platform and the provided solution.
  vulnerability rank: High
  currently implemented mitigations: |
    There are no input data validation or sanitization mechanisms implemented within the provided project code.
    The pipeline directly queries and processes data from BigQuery without any checks on data integrity or validity at the pipeline level.
    While BigQuery itself offers some data type enforcement and access control features, these are not utilized or extended within the provided pipeline code to specifically mitigate against malicious data injection.
  missing mitigations: |
    Several mitigations are missing to address this vulnerability:
      - **Input Data Validation:** Implement validation steps within the Dataflow pipeline to check the integrity and validity of the data read from BigQuery. This should include:
        - **Schema validation:** Ensure that the data read from BigQuery conforms to an expected schema, including data types and required fields. While BigQuery enforces schema, the pipeline should re-validate in case of unexpected schema changes or to ensure data integrity after read.
        - **Range checks:** Validate that numerical fields like `conversion_value` fall within acceptable ranges. Detect and flag or reject unusually high or low values that might indicate data manipulation.
        - **Data consistency checks:** Implement checks for consistency across data fields, e.g., if certain feature combinations are logically or statistically improbable, they should be flagged for review.
      - **Data Sanitization:** Sanitize input data to neutralize potentially malicious or unexpected data. For example, if free-text fields are used as features (which is not evident in the provided code, but a general good practice), they should be sanitized to prevent injection attacks (though less relevant in this specific context).
      - **BigQuery Access Control Hardening (Outside Project Scope but Important):** While not a code mitigation, proper configuration of BigQuery IAM roles and permissions is crucial. Follow the principle of least privilege to restrict write access to the BigQuery datasets to only authorized and trusted users or services. Regularly audit and review BigQuery access controls.
      - **Data Provenance and Auditing:** Implement mechanisms to track data provenance and audit data modifications in BigQuery. This can help in detecting and investigating data manipulation incidents. BigQuery audit logs are a native feature that should be utilized.
  preconditions: |
    To successfully exploit this vulnerability, the attacker needs to fulfill the following preconditions:
      - **Write Access to BigQuery:** The attacker must have write privileges to the BigQuery datasets that contain the `table_consent` and `table_noconsent` tables. This is the primary precondition. Without write access, they cannot directly modify the input data. The level of write access required depends on the method of attack (modifying existing data vs. injecting new data).
      - **Knowledge of BigQuery Schema:** The attacker needs some understanding of the schema of the `table_consent` and `table_noconsent` tables to craft effective malicious data injections that are syntactically correct and can influence the pipeline's logic.
      - **Pipeline Triggered:** The pipeline needs to be triggered and run after the attacker has injected the malicious data for the attack to have an effect on the output and subsequent bidding processes. This is typically not a precondition controlled by the attacker, as the pipeline is designed to run automatically based on triggers (Cloud Function).
  source code analysis: |
    1. **`pipeline.py` - `_load_data_from_bq` function:**
       ```python
       def _load_data_from_bq(table_name: str, location: str, project: str,
                             start_date: str, end_date: str,
                             date_column: str) -> pd.DataFrame:
         """Reads data from BigQuery filtered to the given start and end date."""
         bq_client = bigquery.Client(location=location, project=project)
         query = f"""
                  SELECT * FROM `{table_name}`
                  WHERE {date_column} >= '{start_date}' and {date_column} < '{end_date}'
                  ORDER BY {date_column}
                  """
         return bq_client.query(query).result().to_dataframe()
       ```
       - This function is responsible for fetching data from BigQuery.
       - It constructs a simple SQL query using string formatting to select all columns (`SELECT *`) from the specified `table_name`.
       - **Vulnerability Point:**  Critically, there is **no input validation** on the data fetched from BigQuery within this function or anywhere else in the pipeline code. It blindly trusts the data present in the BigQuery tables. If an attacker has modified the data in BigQuery, this function will fetch and return the manipulated data without any detection or sanitization.
       - The function uses `SELECT *`, which while convenient, makes the pipeline vulnerable to schema changes in BigQuery. If columns are added or changed unexpectedly (maliciously or accidentally), the pipeline might break or behave unpredictably. However, for the data injection vulnerability, the lack of validation is the primary concern.

    2. **`pipeline.py` - `ConversionAdjustments` class and `process` method:**
       ```python
       class ConversionAdjustments(beam.DoFn):
           # ... (init method) ...
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
               # ... Pipeline continues to process data_consent and data_noconsent
       ```
       - The `process` method within the `ConversionAdjustments` class calls `_load_data_from_bq` to retrieve data.
       - **Vulnerability Propagation:**  The data fetched by `_load_data_from_bq` (which could be manipulated) is directly used in subsequent data processing steps within the `ConversionAdjustments` class and further down the pipeline. Because there's no validation after loading, any malicious data is propagated through the entire pipeline, affecting the final conversion adjustments.

    **Visualization:**

    ```
    [BigQuery Tables (table_consent, table_noconsent)] --> (Attacker Injection Point) --> [Modified BigQuery Tables]
                                                                    |
                                                                    V
    [pipeline.py - _load_data_from_bq()] --> [Dataframe (potentially malicious data)]
                                                                    |
                                                                    V
    [pipeline.py - ConversionAdjustments.process()] --> [Data Processing (using malicious data)]
                                                                    |
                                                                    V
    [Output CSV] --> [Skewed Conversion Adjustments] --> [Impact on Advertiser Bidding]
    ```
  security test case: |
    1. **Pre-test setup:**
       - Deploy the Consent-based Conversion Adjustments pipeline to a test Google Cloud project.
       - Create test BigQuery datasets and tables for `table_consent` and `table_noconsent` in the designated BigQuery project, matching the schema expected by the pipeline. Populate these tables with representative, valid data.
       - Configure the Cloud Function and Dataflow pipeline to use these test BigQuery tables.
       - Run the pipeline once with the valid test data and store the output CSV files in a designated Cloud Storage location as a baseline. Note down key metrics from the output, such as the sum of `adjusted_conversion` values.

    2. **Attack Step - Data Injection:**
       - Using a BigQuery client (e.g., bq command-line tool, BigQuery console, or a script with BigQuery API access with write permissions to the test dataset), inject malicious records into the `table_noconsent` table.
       - Example malicious record to inject (assuming your table schema includes columns like `gclid`, `conversion_timestamp`, `conversion_value`, and some feature columns):
         ```sql
         INSERT INTO `[YOUR_BQ_PROJECT_ID].[YOUR_BQ_DATASET].table_noconsent` (gclid, conversion_timestamp, conversion_value, feature1, feature2)
         VALUES
           ('malicious_gclid_1', '2023-10-27 10:00:00 UTC', 1000000, 'malicious_feature_value_1', 'malicious_feature_value_2'),
           ('malicious_gclid_2', '2023-10-27 10:00:00 UTC', 999999, 'malicious_feature_value_3', 'malicious_feature_value_4');
         ```
         - The key is to inject records with:
           - **High `conversion_value`:** To artificially inflate the total conversion value and skew adjustments upwards.
           - **Specific feature values:** To try and force matches with certain consenting users, further skewing the distribution. Choose feature values that are either very common in the consenting data or very rare, depending on the desired skew.

    3. **Run the Pipeline (Trigger):**
       - Trigger the Cloud Function (and thus the Dataflow pipeline) to process data for a date range that includes the injected malicious data. This could be done by manually triggering the Cloud Function, or if it's set up with a Pub/Sub trigger based on BigQuery events, by performing an action that triggers the logging sink (e.g., another data insertion into the tables, if the sink is set up for insert events).

    4. **Verification and Observation:**
       - After the pipeline run completes, retrieve the output CSV files from the designated Cloud Storage location.
       - **Compare with Baseline:** Compare the newly generated output CSV files with the baseline CSV files created in the pre-test setup.
       - **Check for Skewed Adjustments:** Analyze the `adjusted_conversion` column in the output. Look for:
         - **Significant increase in the sum of `adjusted_conversion` values:** The injected high conversion values should lead to a noticeable increase compared to the baseline.
         - **Disproportionate adjustments:** Examine the distribution of `adjusted_conversion` values. Are certain consenting users receiving unusually high adjustments, possibly due to the specific feature values in the malicious records?
       - **Examine Logs (Optional but Recommended):** Review the Dataflow job logs and Cloud Function logs for any errors or warnings that might have occurred during processing. While the pipeline is not expected to throw errors due to data injection (as there's no validation), logs might provide insights into the processing of the malicious data.

    5. **Expected Result:**
       - The security test should demonstrate that the output CSV files generated after data injection show significantly skewed `adjusted_conversion` values compared to the baseline.
       - This proves that the pipeline is vulnerable to input data manipulation and that an attacker with write access to the BigQuery tables can successfully influence the conversion adjustments produced by the system.
       - The test validates the "Input Data Manipulation / Data Injection" vulnerability.