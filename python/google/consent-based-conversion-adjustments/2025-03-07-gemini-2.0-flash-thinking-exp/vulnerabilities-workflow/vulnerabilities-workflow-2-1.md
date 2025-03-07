### Vulnerability 1: Lack of Input Data Validation in BigQuery Queries

*   **Vulnerability Name:** Input Data Manipulation leading to Skewed Conversion Adjustments
*   **Description:**
    1.  The Apache Beam pipeline reads data from two BigQuery tables (`TABLE_CONSENT` and `TABLE_NOCONSENT`) based on dates provided in an input file.
    2.  The pipeline uses SQL queries constructed in the `_load_data_from_bq` function in `/code/pipeline.py` to fetch data from these tables.
    3.  These queries are vulnerable to data manipulation if an attacker gains write access to the BigQuery tables.
    4.  An attacker could inject malicious or fabricated data into the BigQuery tables, such as inflating conversion values for non-consenting users or deflating values for consenting users, or altering feature columns to skew the nearest neighbor calculations.
    5.  When the pipeline runs, it will process this manipulated data without any validation or sanitization.
    6.  This will result in skewed conversion adjustments, as the nearest neighbor calculations and subsequent value distribution will be based on the attacker's fabricated data.
*   **Impact:**
    *   Advertisers using this pipeline will receive inaccurate conversion adjustments.
    *   This inaccurate data can negatively impact their bidding strategies in advertising platforms like Google Ads, leading to wasted ad spend and reduced campaign performance.
    *   The integrity of the advertiser's data and the effectiveness of their marketing efforts are compromised.
*   **Vulnerability Rank:** High
*   **Currently Implemented Mitigations:**
    *   None. The code assumes the integrity of the data in the BigQuery tables.
*   **Missing Mitigations:**
    *   **Input Data Validation:** Implement validation checks within the `_load_data_from_bq` function or in the `ConversionAdjustments` DoFn to verify the integrity and expected format of the data read from BigQuery. This could include:
        *   Data type validation for each column.
        *   Range checks for conversion values (e.g., ensuring they are within a reasonable range).
        *   Schema validation to ensure the BigQuery table structure matches the expected schema.
        *   Anomaly detection to identify unusual patterns or outliers in the input data that might indicate manipulation.
    *   **Access Control:** While not a code mitigation, ensure proper access control and permissions are configured for the BigQuery tables to restrict write access to authorized users and systems only. This is crucial to prevent unauthorized data injection.
*   **Preconditions:**
    *   Attacker must have write access to the BigQuery tables (`TABLE_CONSENT` and `TABLE_NOCONSENT`) used as input for the pipeline. This could be achieved through compromised credentials, insider threat, or misconfigured IAM permissions.
*   **Source Code Analysis:**

    1.  **`/code/pipeline.py` - `_load_data_from_bq` function:**
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
        *   This function constructs a simple SQL query to select all columns (`SELECT *`) from the specified BigQuery table.
        *   It filters data based on `date_column`, `start_date`, and `end_date`.
        *   **Vulnerability:** There is no input validation or sanitization of the data fetched from BigQuery. If the data in the BigQuery tables is manipulated, this function will blindly read and return the malicious data.

    2.  **`/code/pipeline.py` - `ConversionAdjustments.process` function:**
        ```python
        def process(
            self, process_date: datetime.date
        ) -> Optional[Sequence[Tuple[str, pd.DataFrame, pd.DataFrame]]]:
          """Calculates conversion adjustments for the given date.
          ...
          """
          ...
          data_noconsent = _load_data_from_bq(self._table_noconsent, self._location,
                                              self._project, start_date, end_date,
                                              self._date_column)
          data_consent = _load_data_from_bq(self._table_consent, self._location,
                                            self._project, start_date, end_date,
                                            self._date_column)
          ...
          data_consent, data_noconsent = preprocess.concatenate_and_process_data(
              data_consent, data_noconsent, self._conversion_column,
              self._drop_columns, self._non_dummy_columns)
          ...
        ```
        *   This function calls `_load_data_from_bq` to fetch data.
        *   It then passes the data to `preprocess.concatenate_and_process_data`.
        *   **Vulnerability Propagation:** The `process` function directly uses the data returned by `_load_data_from_bq` without any checks, thus propagating the vulnerability further into the pipeline.

    3.  **`/code/cocoa/preprocess.py` - `preprocess_data` and `_clean_data` functions:**
        ```python
        def _clean_data(data: pd.DataFrame, conversion_column: str) -> pd.DataFrame:
          """Cleans data from NaNs and invalid conversion values.
          ...
          """
          # Optional: Fill NaNs based on additional information/other columns.
          data.dropna(subset=[conversion_column], inplace=True)
          has_valid_conversion_value = data[conversion_column].values > 0
          data = data[has_valid_conversion_value]
          # Optional: Deduplicate consented users based on timestamp and gclid.
          return data


        def preprocess_data(data: pd.DataFrame, drop_columns: List[Any],
                            non_dummy_columns: List[Any],
                            conversion_column: str) -> pd.DataFrame:
          """Preprocesses the passed dataframe.
          ...
          """
          data = _clean_data(data, conversion_column=conversion_column)
          data = _additional_feature_engineering(data)
          data_dummies = pd.get_dummies(
              data.drop(drop_columns + non_dummy_columns, axis=1, errors="ignore"),
              sparse=True)
          ...
          return data_dummies
        ```
        *   The `_clean_data` function performs basic cleaning by removing rows with NaN conversion values and ensuring conversion values are greater than zero.
        *   `preprocess_data` performs further preprocessing, including dummy coding.
        *   **Limited Mitigation:** While `_clean_data` provides some basic cleaning, it is insufficient to prevent the impact of maliciously injected data. It does not validate the overall integrity or reasonableness of the data. For example, it does not prevent injection of valid data types with malicious values.

*   **Security Test Case:**

    1.  **Precondition:** Assume you have write access to the BigQuery dataset and tables specified by environment variables `TABLE_CONSENT` and `TABLE_NOCONSENT` in a test environment.
    2.  **Steps:**
        a.  Identify a specific date (e.g., '2021-11-20') that will be processed by the pipeline using the default configuration.
        b.  In the `TABLE_NOCONSENT` BigQuery table, for the chosen date, locate a specific record (e.g., with `gclid = '21'`).
        c.  Modify the `conversion_value` for this record to a significantly inflated value (e.g., from `20.0` to `20000.0`).
        d.  Trigger the pipeline to run for the chosen date. This can be done by manually executing the `generate_template.sh` script and then triggering the Cloud Function or by directly running the pipeline using `python -m pipeline ...` with appropriate parameters.
        e.  After the pipeline execution completes, examine the output CSV files in the GCS bucket specified by `PIPELINE_BUCKET` and `output_csv_path`.
        f.  Download the `adjustments_data.csv` file for the processed date.
        g.  Analyze the `adjusted_conversion` column in the output CSV.
        h.  **Verification:** Observe that the inflated `conversion_value` in `TABLE_NOCONSENT` has resulted in a disproportionately large adjustment in the `adjusted_conversion` values in the output. This demonstrates that the pipeline processed the manipulated data and produced skewed results, confirming the vulnerability.

This vulnerability allows an attacker with write access to the input BigQuery tables to directly influence the output of the conversion adjustment pipeline, leading to inaccurate data for advertisers and potentially impacting their advertising campaign performance.