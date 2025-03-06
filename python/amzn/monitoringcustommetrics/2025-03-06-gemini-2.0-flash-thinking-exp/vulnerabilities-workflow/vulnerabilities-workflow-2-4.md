- vulnerability name: CSV Injection
- description:
  - An attacker can craft a malicious CSV input file.
  - This malicious CSV file is provided as input to the monitoring tool.
  - The monitoring tool processes the CSV file using pandas.read_csv.
  - If the malicious CSV contains CSV injection payloads (e.g., formulas starting with '=', '@', '+', or '-'), these payloads are processed by pandas.
  - The monitoring tool generates output files (community_statistics.json, community_constraints.json, community_constraint_violations.json) that may include data from the processed CSV, including the injected payloads.
  - If a user opens these output JSON files with vulnerable software (like spreadsheet applications that support CSV interpretation within JSON), the injected payloads can be executed, potentially compromising the user's system.
- impact:
  - If a user opens the generated output files (JSON format, but containing CSV-like data) with vulnerable software (e.g., spreadsheet applications), arbitrary commands embedded in the malicious CSV input can be executed.
  - This could lead to:
    - Information disclosure: Access to sensitive data on the user's system.
    - System compromise: Execution of arbitrary code, potentially allowing the attacker to gain control over the user's machine.
    - Credential theft: If the executed commands are designed to steal credentials.
- vulnerability rank: medium
- currently implemented mitigations:
  - None. The code does not implement any explicit sanitization or mitigation against CSV injection.
- missing mitigations:
  - Input sanitization: Sanitize the input CSV data to remove or escape any characters that could be interpreted as formulas by spreadsheet software (e.g., '=', '@', '+', '-').
  - Output sanitization: Sanitize the data written to the output JSON files to prevent CSV injection. This could involve escaping special characters or using a format that is not vulnerable to CSV injection when opened by spreadsheet software.
  - User warnings: Display a clear warning to users about the potential risks of opening the output files with spreadsheet software, especially if the input data source is untrusted.
- preconditions:
  - The attacker must be able to provide a malicious CSV file as input to the monitoring tool. This could be through direct file upload if such functionality exists or by influencing the data source that the monitoring tool processes.
  - A user must open the generated output JSON files (community_statistics.json, community_constraints.json, community_constraint_violations.json) with vulnerable software, such as Microsoft Excel, Google Sheets, or LibreOffice Calc.
- source code analysis:
  - The vulnerability stems from the use of `pandas.read_csv` in `src/monitoring_custom_metrics/util.py` within the `get_dataframe_from_csv` function:
    ```python
    import pandas as pd

    def get_dataframe_from_csv(path=None) -> pandas.DataFrame:
        # ...
        data_frames = []
        for filename in filenames:
            full_path = os.path.join(folder_path, filename)
            print(f"  Reading data from file: {folder_path}")
            data_frames.append(pd.read_csv(full_path)) # Vulnerable point: pandas.read_csv is used without sanitization
        # ...
    ```
  - `pandas.read_csv` by default does not prevent CSV injection. If the CSV file contains cells starting with characters like '=', '@', '+', or '-', spreadsheet software may interpret these as formulas.
  - The `get_dataframe_from_csv` function is called in `src/monitoring_custom_metrics/main.py`:
    ```python
    from src.monitoring_custom_metrics.util import (
        get_dataframe_from_csv,
    )

    def monitoring():
        # ...
        df: pandas.DataFrame = get_dataframe_from_csv() # DataFrame is created from CSV input
        # ...
    ```
  - The DataFrame `df` is then processed, and its data is used to generate output JSON files in `src/monitoring_custom_metrics/output_generator.py` using `json.dumps`.
  - Although the output is in JSON format, if the data within the JSON originates from a malicious CSV and is displayed in a spreadsheet program (which can interpret CSV-like data within JSON), the CSV injection vulnerability can be triggered.
- security test case:
  - Step 1: Create a malicious CSV file (e.g., `malicious_input.csv`) with the following content:
    ```csv
    Name,Age
    "test","=SYSTEM('calc')"
    "another","25"
    ```
    This CSV contains a formula `=SYSTEM('calc')` in the 'Age' column, which, if executed, would open the calculator application on a Windows system when opened in vulnerable spreadsheet software.
  - Step 2: Place the `malicious_input.csv` file in the `local_resources/data_quality/` directory.
  - Step 3: Modify the `Dockerfile` to use the malicious CSV file as input and set the analysis type to DATA_QUALITY:
    ```dockerfile
    ##### Parameters for running locally should be put here: #####################################
    ENV analysis_type=DATA_QUALITY
    COPY local_resources/data_quality/malicious_input.csv /opt/ml/processing/input/data
    ##### End of Parameters for running locally ###########################################################################################
    ```
  - Step 4: Run the monitoring tool locally using the `run_local.sh` script:
    ```bash
    ./run_local.sh
    ```
  - Step 5: After the script finishes, navigate to the `local_output/<IMAGE_ID>` directory.
  - Step 6: Open the `community_statistics.json` file (or any other output JSON file) using a vulnerable spreadsheet application like Microsoft Excel or LibreOffice Calc.
  - Step 7: Observe if the calculator application (or any other command injected) is executed. If the calculator opens, it confirms the CSV injection vulnerability.
  - Step 8: Inspect the `community_statistics.json` file. You should find the injected formula `=SYSTEM('calc')` within the JSON structure, likely under the 'Age' column statistics. This confirms that the malicious payload was processed and included in the output.