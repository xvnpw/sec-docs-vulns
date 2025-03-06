## Combined Vulnerability List

### CSV Injection Vulnerability

- **Vulnerability Name:** CSV Injection
- **Description:**
    - An attacker crafts a malicious CSV file containing formulas in cells, such as those starting with '=', '@', '+', or '-'.
    - This malicious CSV file is provided as input to the `MonitoringCustomMetrics` package.
    - The `get_dataframe_from_csv` function in `src/monitoring_custom_metrics/util.py` uses `pandas.read_csv()` to parse the CSV file. If default pandas configurations or specific engines are used, formulas within the CSV can be executed during parsing.
    - Alternatively, even if formulas are not executed during parsing, the injected formulas are processed and can be written to output JSON files (community_statistics.json, community_constraints.json, community_constraint_violations.json).
    - If a user opens these generated JSON output files with a CSV reader application (like Microsoft Excel or LibreOffice Calc), these applications may interpret the data within the JSON as CSV and execute the injected formulas without sanitization.
    - This execution of injected formulas, either during pandas parsing or when opening output files in spreadsheet software, can lead to arbitrary command execution on the server processing the CSV or on the user's local machine opening the output files.
- **Impact:**
    - **Information disclosure:** An attacker could potentially read sensitive local files or environment variables by crafting formulas to exfiltrate data from the server or the user's local machine.
    - **Unexpected behavior:** Injected formulas could disrupt the intended data processing flow, leading to incorrect metric calculations or other unintended application behavior on the server.
    - **System compromise (user's machine):** If an unsuspecting user opens the generated JSON output files with a vulnerable CSV reader application, arbitrary commands can be executed on their local machine, potentially leading to malware installation, credential theft, or other malicious activities.
- **Vulnerability Rank:** Medium
- **Currently implemented mitigations:** None
- **Missing mitigations:**
    - **Disable formula execution in pandas `read_csv`**: Use `engine='python'` or `engine='c'` and explicitly set `usecols` and `dtype` parameters when using `pandas.read_csv` to prevent formula execution during CSV parsing.
    - **Input validation and sanitization**: Implement input validation and sanitization to inspect and sanitize the input CSV data before parsing with pandas. Remove or escape potentially malicious characters or formula syntax (e.g., prefix cells starting with '=', '@', '+', or '-' with a space or single quote).
    - **Output sanitization**: Sanitize output data in JSON files to prevent CSV injection. Before writing data to JSON files, especially string type data that originated from CSV input, apply sanitization to escape or remove characters that could be interpreted as formula injection by CSV readers.
    - **User warnings**: Add documentation to warn users about the potential risks of opening output JSON files in CSV reader applications and recommend reviewing the files in a text editor first.

- **Preconditions:**
    - The `MonitoringCustomMetrics` package is used to process CSV files that could originate from untrusted sources or be tampered with by an attacker.
    - For server-side vulnerability: The pandas library, in the environment where `MonitoringCustomMetrics` is deployed, is configured in a way that allows for the execution of formulas embedded within CSV files or default pandas engine is vulnerable.
    - For client-side vulnerability: A user needs to open the generated JSON output files with a CSV reader application that is vulnerable to CSV injection (e.g., Microsoft Excel, LibreOffice Calc) and the application must be configured to execute formulas when opening CSV/similar files.

- **Source code analysis:**
    - **File:** `/code/src/monitoring_custom_metrics/util.py`
    - **Function:** `get_dataframe_from_csv(path=None)`
    ```python
    def get_dataframe_from_csv(path=None) -> pandas.DataFrame:
        folder_path: str = ""
        if os.environ.get(DATASET_SOURCE_ENV_VAR) is not None:
            folder_path = os.environ[DATASET_SOURCE_ENV_VAR]
        elif path is not None:
            folder_path = path
        else:
            folder_path = DEFAULT_DATA_PATH

        print(f"Retrieving data from path: {folder_path}")

        filenames: List[str] = get_files_in_directory(folder_path)
        data_frames = []

        for filename in filenames:
            full_path = os.path.join(folder_path, filename)
            print(f"  Reading data from file: {folder_path}")
            data_frames.append(pd.read_csv(full_path)) # Vulnerable line
        print(f"Finished retrieving data from path: {folder_path}")
        return pd.concat(data_frames)
    ```
    - The vulnerability is located in the `pd.read_csv(full_path)` line within the `get_dataframe_from_csv` function. This function directly uses `pandas.read_csv` to parse CSV files without specifying parameters to disable formula execution. This default behavior of `pandas.read_csv` can be exploited for server-side CSV injection.
    - **File:** `/code/src/monitoring_custom_metrics/output_generator.py`
    - **Function:** `write_output_file(data, output_file_path)`
    ```python
    def write_output_file(data, output_file_path):
        formatted_json = json.dumps(data, default=int, indent=4)
        with open(output_file_path, "w") as file:
            file.write(formatted_json)
    ```
    - The data read from the CSV (potentially containing malicious formulas) is written to JSON output files without sanitization using `json.dumps`. This allows for client-side CSV injection when these JSON files are opened with vulnerable spreadsheet software.

- **Security test case:**
    - **Server-side CSV Injection Test Case:**
        1. Create a malicious CSV file named `malicious.csv` with the following content and save it in the `local_resources/data_quality/` directory:
        ```csv
        name,age
        "=SYSTEM('touch /tmp/pwned')","25"
        "test","30"
        ```
        2. Modify the `Dockerfile` to ensure the malicious CSV is used as input for the data quality analysis:
        ```dockerfile
        ENV analysis_type=DATA_QUALITY
        COPY local_resources/data_quality/malicious.csv /opt/ml/processing/input/data
        ```
        3. Execute the `run_local.sh` script.
        4. Access a shell inside the running Docker container and verify if the `/tmp/pwned` file exists using `ls /tmp/pwned`. If the file exists, server-side CSV injection is confirmed.

    - **Client-side CSV Injection Test Case:**
        1. Create a file named `malicious_input.csv` in the `local_resources/data_quality/` directory with the following content:
        ```csv
        Name,Age
        "=cmd|' /C calc'!A0",30
        ```
        2. Modify the `Dockerfile` to use `malicious_input.csv` as input:
        ```dockerfile
        COPY local_resources/data_quality/malicious_input.csv /opt/ml/processing/input/data
        ```
        3. Run the `run_local.sh` script.
        4. Navigate to the `local_output/<IMAGE_ID>/` directory after the script finishes.
        5. Open the `community_statistics.json` file using Microsoft Excel or LibreOffice Calc (importing from JSON if necessary).
        6. Observe if the calculator application is launched. If it is, client-side CSV injection is confirmed.

### CSV Data Manipulation leading to Misleading Statistics

- **Vulnerability Name:** CSV Data Manipulation leading to Misleading Statistics
- **Description:**
    - An attacker crafts a malicious CSV input file containing manipulated data values.
    - The malicious CSV file is provided as input to the `MonitoringCustomMetrics` package.
    - The package reads this malicious CSV file using pandas `read_csv`.
    - The package calculates data quality or model quality statistics based on the data, including the injected malicious values (e.g., extremely large values).
    - The injected data manipulates the calculated statistics (e.g., inflates sum, average).
    - In "run monitor" mode, the manipulated statistics can lead to missed or falsely triggered constraint violations, resulting in misleading monitoring reports.
    - In "suggest baseline" mode, the generated baseline constraints will be based on the manipulated statistics, leading to ineffective future monitoring.
- **Impact:** Misleading monitoring reports, bypassed quality checks, incorrect baseline constraints, potentially leading to undetected data or model quality issues.
- **Vulnerability Rank:** Medium
- **Currently Implemented Mitigations:** None
- **Missing Mitigations:**
    - **Input validation and sanitization**: Implement input validation and sanitization for CSV data to detect and reject anomalous or out-of-range values before processing.
    - **Statistical anomaly checks**: Implement checks for statistical anomalies in the input data before calculating metrics to identify and flag suspicious data.
    - **Configurable limits/thresholds**: Consider adding configurable limits or thresholds for acceptable statistical ranges to detect extreme values.
    - **Documentation**: Document the potential risk of data manipulation through malicious CSV inputs and advise users on secure input data handling and data validation practices.
- **Preconditions:**
    - The attacker must be able to provide a malicious CSV file as input to the `MonitoringCustomMetrics` package through any supported input channel (e.g., local file, S3 path).
- **Source Code Analysis:**
    - **File:** `/code/src/monitoring_custom_metrics/util.py`
    - **Function:** `get_dataframe_from_csv(path=None)`
    ```python
    def get_dataframe_from_csv(path=None) -> pandas.DataFrame:
        # ...
        data_frames = []
        for filename in filenames:
            full_path = os.path.join(folder_path, filename)
            print(f"  Reading data from file: {folder_path}")
            data_frames.append(pd.read_csv(full_path)) # Vulnerable point: Reads CSV without validation
        # ...
    ```
    - The `get_dataframe_from_csv` function reads CSV files using `pd.read_csv` without any validation or sanitization of the input data.
    - **File:** `/code/src/monitoring_custom_metrics/data_quality/numerical/sum.py` (Example Metric)
    - **Function:** `calculate_statistics`
    ```python
    class Sum(DataQualityMetric):
        # ...
        def calculate_statistics(
            self, column: Union[pandas.Series, pandas.DataFrame]
        ) -> Union[int, str, bool, float]:
            return column.sum() # Vulnerable point: Directly calculates sum without input checks
        # ...
    ```
    - Metric calculation functions directly operate on the pandas DataFrame column without checks for extreme or invalid values, allowing injected malicious data to directly influence statistics. This pattern is present in other metric calculations as well.

- **Security Test Case:**
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
    3. **Run Baseline:** Execute the package with `clean_input.csv` and capture the `community_constraints.json` file.
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
    5. **Run with Malicious Input:** Execute the package with `malicious_input.csv` and capture the new `community_constraints.json` file.
    6. **Verification:** Compare the `community_constraints.json` files generated from `clean_input.csv` and `malicious_input.csv`. Observe the significant inflation of the "lower_bound" and "upper_bound" for the `sum` constraint in the malicious input case, demonstrating successful data manipulation.
    7. **Run Monitor with Malicious Input and Original Constraints:** Run the package in "run monitor" mode with `malicious_input.csv` and use the `community_constraints.json` generated from `clean_input.csv` as baseline constraints. Check `community_constraint_violations.json`. Verify that no violation is reported for the `sum` metric, even with the injected large value, due to the inflated constraints, showing bypassed monitoring.