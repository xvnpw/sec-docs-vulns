### Vulnerability List

- Vulnerability Name: CSV Data Manipulation leading to Misleading Statistics
- Description:
  1. An attacker crafts a malicious CSV input file.
  2. The malicious CSV file contains data values specifically designed to manipulate the calculated statistics. For example, for numerical columns, the attacker injects extremely large values.
  3. The `MonitoringCustomMetrics` package reads this malicious CSV file using pandas `read_csv`.
  4. The package calculates data quality or model quality statistics based on the data in the DataFrame, including the injected malicious values.
  5. The injected data manipulates the calculated statistics (e.g., inflates the sum, average, etc.).
  6. If the system is in "run monitor" mode, the manipulated statistics are compared against baseline constraints. Due to the manipulated statistics, violations might be missed or falsely triggered, leading to misleading monitoring reports.
  7. If the system is in "suggest baseline" mode, the generated baseline constraints will be based on the manipulated statistics, leading to ineffective future monitoring.
- Impact: Misleading monitoring reports, bypassed quality checks, incorrect baseline constraints, leading to potentially undetected data or model quality issues.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations: None
- Missing Mitigations:
  - Input validation and sanitization for CSV data to detect and reject anomalous or out-of-range values.
  - Implement checks for statistical anomalies in the input data before calculating metrics.
  - Consider adding configurable limits or thresholds for acceptable statistical ranges.
  - Document the potential risk of data manipulation through malicious CSV inputs and advise users on secure input data handling.
- Preconditions:
  - The attacker must be able to provide a malicious CSV file as input to the `MonitoringCustomMetrics` package. This could be through any input channel that the application supports (e.g., local file, S3 path).
- Source Code Analysis:
  1. **File:** `/code/src/monitoring_custom_metrics/util.py`
     ```python
     def get_dataframe_from_csv(path=None) -> pandas.DataFrame:
         # ...
         data_frames = []
         for filename in filenames:
             full_path = os.path.join(folder_path, filename)
             print(f"  Reading data from file: {folder_path}") # path is folder_path, not filename
             data_frames.append(pd.read_csv(full_path)) # Vulnerable point: Reads CSV without validation
         # ...
     ```
     - The `get_dataframe_from_csv` function reads CSV files using `pd.read_csv` without any validation or sanitization of the input data. This function is used to load the input data for both data quality and model quality monitoring.
  2. **File:** `/code/src/monitoring_custom_metrics/data_quality/numerical/sum.py` (Example Metric)
     ```python
     class Sum(DataQualityMetric):
         # ...
         def calculate_statistics(
             self, column: Union[pandas.Series, pandas.DataFrame]
         ) -> Union[int, str, bool, float]:
             return column.sum() # Vulnerable point: Directly calculates sum without input checks
         # ...
     ```
     - Metric calculation functions, like `Sum.calculate_statistics`, operate directly on the pandas DataFrame column without any checks for extreme or invalid values. This allows injected malicious data to directly influence the calculated statistics. The same pattern applies to other metrics in `/code/src/monitoring_custom_metrics/data_quality/` and `/code/src/monitoring_custom_metrics/model_quality/`.
- Security Test Case:
  1. **Setup:** Configure and run the `MonitoringCustomMetrics` package in "suggest baseline" mode for data quality analysis, using the `Sum` metric.
  2. **Baseline Input (`clean_input.csv`):**
     ```csv
     value
     1
     2
     3
     4
     5
     ```
  3. **Run Baseline:** Execute the package with `clean_input.csv`. Capture the `community_constraints.json` file. Example content (constraints may vary slightly):
     ```json
     {
         "version": 0.0,
         "features": [
             {
                 "name": "value",
                 "inferred_type": "Integral",
                 "num_constraints": {
                     "sum": {
                         "lower_bound": 13.5,
                         "upper_bound": 16.5,
                         "additional_properties": null
                     }
                 }
             }
         ]
     }
     ```
  4. **Malicious Input (`malicious_input.csv`):**
     ```csv
     value
     1
     2
     3
     4
     5
     1000000
     ```
  5. **Run with Malicious Input:** Execute the package with `malicious_input.csv`. Capture the new `community_constraints.json` file. Example content:
     ```json
     {
         "version": 0.0,
         "features": [
             {
                 "name": "value",
                 "inferred_type": "Integral",
                 "num_constraints": {
                     "sum": {
                         "lower_bound": 900004.5,
                         "upper_bound": 1100005.5,
                         "additional_properties": null
                     }
                 }
             }
         ]
     }
     ```
  6. **Verification:** Observe that the "lower_bound" and "upper_bound" for the `sum` constraint in the `malicious_input.csv`'s `community_constraints.json` are significantly inflated compared to the `clean_input.csv`'s constraints. This demonstrates successful data manipulation.
  7. **Run Monitor with Malicious Input and Original Constraints:** Run the package in "run monitor" mode with `malicious_input.csv` and use the `community_constraints.json` generated from `clean_input.csv` (step 3) as baseline constraints. Check `community_constraint_violations.json`. No violation should be reported for the `sum` metric, even though a large value was injected, because the constraints are now too wide and based on clean data, effectively bypassing the intended monitoring.