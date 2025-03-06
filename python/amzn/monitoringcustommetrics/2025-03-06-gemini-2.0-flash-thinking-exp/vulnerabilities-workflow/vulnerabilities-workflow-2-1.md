- Vulnerability name: CSV Injection
- Description:
    1. An attacker crafts a malicious CSV file.
    2. This CSV file contains formulas in cells, such as those starting with '=', '@', '+', or '-'.
    3. The user provides this malicious CSV file as input to `MonitoringCustomMetrics`.
    4. The `get_dataframe_from_csv` function in `src/monitoring_custom_metrics/util.py` uses `pandas.read_csv()` to parse the CSV file.
    5. If the pandas environment or engine is configured to execute formulas (which can be default behavior or enabled via specific engines), these formulas within the CSV will be executed during parsing.
    6. This execution of injected formulas can lead to arbitrary command execution on the server or information disclosure, depending on the nature of the injected formulas.
- Impact:
    - Information disclosure: An attacker could potentially read sensitive local files or environment variables by crafting formulas to exfiltrate data.
    - Unexpected behavior: Injected formulas could disrupt the intended data processing flow, leading to incorrect metric calculations or other unintended application behavior.
- Vulnerability rank: Medium
- Currently implemented mitigations: None
- Missing mitigations:
    - Disable formula execution in pandas `read_csv` by using `engine='python'` or `engine='c'` and explicitly setting `usecols` and `dtype` parameters for enhanced security.
    - Implement input validation and sanitization to inspect and sanitize the input CSV data, removing or escaping potentially malicious characters or formula syntax before parsing with pandas.
- Preconditions:
    - The `MonitoringCustomMetrics` package is used to process CSV files that could originate from untrusted sources or be tampered with by an attacker.
    - The pandas library, in the environment where `MonitoringCustomMetrics` is deployed, is configured in a way that allows for the execution of formulas embedded within CSV files.
- Source code analysis:
    - File: `/code/src/monitoring_custom_metrics/util.py`
    - Function: `get_dataframe_from_csv(path=None)`
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
    - The vulnerability is located in the `pd.read_csv(full_path)` line within the `get_dataframe_from_csv` function. This function directly uses `pandas.read_csv` to parse CSV files without specifying any parameters to disable formula execution. This default behavior of `pandas.read_csv` can be exploited. If a malicious CSV file containing formulas is provided as input, pandas might execute these formulas, leading to potential security issues.
- Security test case:
    1. Create a malicious CSV file named `malicious.csv` with the following content and save it in the `local_resources/data_quality/` directory:
    ```csv
    name,age
    "=SYSTEM('touch /tmp/pwned')","25"
    "test","30"
    ```
    This CSV file contains a formula `=SYSTEM('touch /tmp/pwned')` in the first row of the 'name' column. This formula, if executed, will attempt to create a file named `pwned` in the `/tmp` directory within the container.
    2. Modify the `Dockerfile` to ensure the malicious CSV is used as input for the data quality analysis. Update the Dockerfile section for local execution parameters as follows:
    ```dockerfile
    ##### Parameters for running locally should be put here: #####################################
    ENV analysis_type=DATA_QUALITY
    COPY local_resources/data_quality/malicious.csv /opt/ml/processing/input/data
    ##### End of Parameters for running locally ###########################################################################################
    ```
    This configuration sets the analysis type to `DATA_QUALITY` and copies the `malicious.csv` file into the container's input data directory.
    3. Execute the `run_local.sh` script from the project's root directory. This script builds and runs the Docker container locally.
    ```bash
    ./run_local.sh
    ```
    4. After the script completes, access a shell inside the running Docker container to check for the presence of the `pwned` file. You can typically do this by finding the container ID from the output of `docker image list` (using the `IMAGE_ID` printed by `run_local.sh`) and then executing:
    ```bash
    docker run -it --entrypoint bash <IMAGE_ID>
    ```
    5. Once inside the container's shell, verify if the `/tmp/pwned` file exists:
    ```bash
    ls /tmp/pwned
    ```
    If the file `/tmp/pwned` is listed, it confirms that the formula within the CSV was executed by pandas during the parsing process, demonstrating a successful CSV injection vulnerability. If the file is created, it indicates that arbitrary commands can be injected and executed through CSV input, confirming the vulnerability.