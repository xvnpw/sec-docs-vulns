### Vulnerability List

- Vulnerability Name: Data Manipulation in BigQuery Input Tables
- Description:
    1. An attacker gains unauthorized write access to the BigQuery tables used as input for the pipeline (`table_consent` and `table_noconsent`). This could be achieved through compromised credentials, insider threat, or misconfigured access controls.
    2. The attacker manipulates the data within these BigQuery tables. This manipulation can take various forms, including:
        - **Injecting fabricated conversion data:** The attacker adds new rows to the tables with artificially high or low conversion values, or with specific feature combinations designed to skew the nearest neighbor matching.
        - **Altering existing conversion values:** The attacker modifies the `conversion_value` column in existing rows to inflate or deflate the conversion metrics.
        - **Modifying user features:** The attacker changes the values in columns used as features for nearest neighbor matching (e.g., adgroup-title, device type) to create artificial similarity or dissimilarity between users, thus influencing the adjustment process.
    3. When the Apache Beam pipeline is executed (triggered by the Cloud Function), it reads the manipulated data from the BigQuery tables using the `_load_data_from_bq` function in `pipeline.py`.
    4. The pipeline proceeds with its normal operation, using the compromised data for preprocessing, nearest neighbor calculations, and conversion adjustments.
    5. Due to the manipulated input data, the statistical adjustments of conversion values become skewed and inaccurate. The nearest neighbor matching will be based on fabricated or altered features, and the up-weighting of conversion values for consenting users will reflect the attacker's manipulations rather than actual user behavior.
- Impact:
    - Inaccurate Bidding Strategies: The primary impact is on the accuracy of conversion adjustments. Skewed adjustments lead to incorrect data being fed into Smart Bidding and other advertising platforms. This results in suboptimal bidding strategies, potentially wasting ad spend, reducing campaign effectiveness, and hindering the advertiser's ability to achieve their marketing goals.
    - Misleading Reporting and Analytics: Inaccurate conversion data can also pollute reporting and analytics dashboards, leading to flawed insights into campaign performance and user behavior. This can negatively impact business decisions based on these reports.
    - Reputational Damage: If advertisers make poor bidding decisions based on manipulated data and experience negative campaign performance, it could lead to dissatisfaction with the advertising platform or the conversion adjustment solution itself, causing reputational damage.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The provided project files do not include any explicit input validation, access control mechanisms, or data integrity checks for the BigQuery input tables. The system implicitly trusts the integrity and validity of the data present in BigQuery.
- Missing Mitigations:
    - Input Data Validation: Implement robust input validation checks within the pipeline code (`pipeline.py` or within a dedicated Beam transform). This validation should occur immediately after reading data from BigQuery and before any processing. Validation rules should include:
        - Data type validation: Ensure that columns like `conversion_value` are of the expected numeric type and `conversion_date` is a valid date format.
        - Range checks: Verify that conversion values and other numerical features fall within expected ranges. For example, conversion values should be non-negative and within a plausible upper bound.
        - Consistency checks: Implement cross-field validation to ensure data consistency. For instance, check if timestamps are logically consistent with dates.
        - Anomaly detection: Employ statistical anomaly detection techniques to identify unusual patterns or outliers in the input data that could indicate manipulation.
    - Access Control Hardening: Enforce the principle of least privilege for access to the BigQuery project and datasets containing the input tables. Restrict write access to these tables to only authorized and necessary service accounts or user roles. Regularly review and audit access control policies.
    - Data Integrity Monitoring and Alerting: Implement monitoring systems to track data integrity metrics for the BigQuery input tables. This could include monitoring row counts, sum of conversion values, distribution of features, and other relevant metrics. Set up alerts to notify security or operations teams if significant deviations or anomalies are detected in these metrics, which might indicate data manipulation.
    - Data Lineage and Auditing: Enable and utilize BigQuery's audit logging features to track all data modification operations on the input tables. This provides an audit trail to investigate any suspected data manipulation incidents and identify responsible parties or compromised accounts. Data lineage tools can also help trace the origin and transformations of the data to ensure its integrity throughout the pipeline.
- Preconditions:
    - The attacker must have write access to the BigQuery datasets and tables used as input for the Consent-based Conversion Adjustments pipeline (specifically `table_consent` and `table_noconsent`).
- Source Code Analysis:
    1. `pipeline.py`:
        - The function `_load_data_from_bq(table_name, location, project, start_date, end_date, date_column)` is responsible for fetching data from BigQuery.
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
        - This function directly executes a SQL query to select all columns (`SELECT *`) from the specified BigQuery table without any input validation or sanitization of the data read.
        - The `ConversionAdjustments` DoFn in `pipeline.py` then processes this DataFrame directly.

    2. Data Flow Visualization:

    ```mermaid
    graph LR
        A[BigQuery: table_consent & table_noconsent] --> B(_load_data_from_bq\npipeline.py)
        B --> C[Pandas DataFrame\n(Unvalidated Input Data)]
        C --> D(ConversionAdjustments\nDoFn\npipeline.py)
        D --> E[Nearest Neighbor Calculation\ncocoa/nearest_consented_customers.py]
        E --> F[Conversion Adjustment\ncocoa/nearest_consented_customers.py]
        F --> G[Output CSV to GCS\npipeline.py]
    ```

    3. Vulnerability Point:
        - The vulnerability lies in the lack of data validation immediately after the data is read from BigQuery in `_load_data_from_bq`. The pipeline blindly trusts the data from BigQuery.
        - If an attacker manipulates the data in BigQuery tables, this manipulated data flows through the pipeline without any checks, directly impacting the conversion adjustment calculations.

- Security Test Case:
    1. **Prerequisites:**
        - Ensure the Consent-based Conversion Adjustments pipeline is deployed and functional, including the Cloud Function trigger and Dataflow template.
        - Identify the BigQuery dataset and tables used for `table_consent` and `table_noconsent` (e.g., based on environment variables or Cloud Function configuration).
        - You need to be able to simulate write access to these BigQuery tables for testing purposes. In a real-world scenario, this would be the attacker's compromised access. For testing, you might use your own credentials with sufficient permissions or set up a test environment with controlled access.

    2. **Steps:**
        a. **Baseline Run:** Execute the Cloud Function to trigger the Dataflow pipeline with the original, unmanipulated data in the BigQuery tables. Note down the output CSV files in GCS and, specifically, the sum of 'adjusted_conversion' values from the output for `table_consent`. This serves as the baseline.
        b. **Data Manipulation:** Directly manipulate the `table_consent` BigQuery table. For example, use the BigQuery UI or `bq` command-line tool to:
            - **Inflate Conversion Values:** For a subset of rows (e.g., 10-20 rows), significantly increase the `conversion_value` (e.g., multiply it by 10 or 100). Choose rows somewhat randomly or based on features if you want to test specific skewing scenarios.
            ```sql
            -- Example SQL to inflate conversion_value in BigQuery (replace with your table and column names)
            UPDATE `your-project-id.your_dataset.your_consent_table`
            SET conversion_value = conversion_value * 100
            WHERE RAND() < 0.1; -- Affects approximately 10% of rows
            ```
            c. **Trigger Pipeline Again:** Execute the Cloud Function again. This will trigger a new run of the Dataflow pipeline, now using the manipulated data in `table_consent`.
        d. **Compare Outputs:** Once the pipeline completes, examine the new output CSV files in GCS. Compare the sum of 'adjusted_conversion' values for `table_consent` in this run with the baseline sum from step 2a.
        e. **Verification:**
            - **Increased Adjusted Conversions:** You should observe a noticeable increase in the sum of 'adjusted_conversion' values in the output CSV files compared to the baseline run. This increase demonstrates that the inflated conversion values in the manipulated `table_consent` table have directly skewed the pipeline's adjustment calculations.
            - **Analyze Summary Statistics:** Check if the summary statistics in the output CSVs (if any are generated by the pipeline) also reflect the data manipulation, e.g., changes in percentage of matched conversions, average distances, etc.

    3. **Expected Result:** The security test case should successfully demonstrate that by manipulating the input data in BigQuery, an attacker can directly influence the output of the Consent-based Conversion Adjustments pipeline, leading to skewed and inaccurate conversion adjustments. The 'adjusted_conversion' values should be demonstrably different (specifically, increased in this test case) compared to the baseline run with unmanipulated data. This proves the vulnerability of data manipulation in BigQuery input tables.