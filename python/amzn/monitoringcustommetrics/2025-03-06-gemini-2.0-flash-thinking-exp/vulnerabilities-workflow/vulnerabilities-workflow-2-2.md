- CSV Injection Vulnerability
  - Description:
    - An attacker can inject malicious formulas into the CSV input file.
    - When the `MonitoringCustomMetrics` package processes this CSV file using pandas, if the output files (community_statistics.json, community_constraints.json, community_constraint_violations.json) are opened with a CSV reader application (like Microsoft Excel or LibreOffice Calc), these formulas can be executed without sanitization.
    - Steps to trigger:
      1. Prepare a CSV file with a column containing a CSV injection payload, for example, `=cmd|' /C calc'!A0`.
      2. Place this malicious CSV file in the `local_resources/data_quality/input.csv` location.
      3. Run the `run_local.sh` script to execute the `MonitoringCustomMetrics` package locally using Docker.
      4. The package will process the CSV and generate output JSON files in the `local_output` directory.
      5. Open any of the generated JSON files (e.g., `local_output/<IMAGE_ID>/community_statistics.json`) with a CSV reader application like Microsoft Excel or LibreOffice Calc by choosing to import data from JSON file.
      6. If the CSV reader application executes formulas, the injected formula `=cmd|' /C calc'!A0` will be executed, in this example, opening the calculator application.
  - Impact:
    - If an unsuspecting user opens the generated JSON output files with a vulnerable CSV reader application, arbitrary commands can be executed on their local machine, depending on the injected payload. This can lead to information disclosure, malware installation, or other malicious activities on the user's local system.
  - Vulnerability rank: Medium
  - Currently implemented mitigations:
    - None. The code processes CSV files using pandas and outputs results to JSON files without any sanitization of data that could be interpreted as formulas by CSV reader applications.
  - Missing mitigations:
    - Sanitize output data in JSON files to prevent CSV injection. Before writing data to JSON files, especially string type data that originated from CSV input, apply sanitization to escape or remove characters that could be interpreted as formula injection by CSV readers. For example, prefixing cells starting with '=', '@', '+', or '-' with a space or single quote can prevent formula execution in many CSV readers.
    - Documentation should be added to warn users about the potential risks of opening output JSON files in CSV reader applications and recommend reviewing the files in a text editor first.
  - Preconditions:
    - The attacker needs to be able to provide a malicious CSV file as input to the `MonitoringCustomMetrics` package. In a real-world scenario, this might happen if the input CSV is not from a trusted source or if there is a way for an attacker to influence the input data.
    - The user needs to open the generated JSON output files with a CSV reader application that is vulnerable to CSV injection (e.g., Microsoft Excel, LibreOffice Calc) and the application must be configured to execute formulas when opening CSV/similar files.
  - Source code analysis:
    - The vulnerability occurs because the `MonitoringCustomMetrics` package reads CSV input using `pandas.read_csv` in `src/monitoring_custom_metrics/util.py` within the `get_dataframe_from_csv` function:
      ```python
      def get_dataframe_from_csv(path=None) -> pandas.DataFrame:
          # ...
          data_frames.append(pd.read_csv(full_path))
          # ...
      ```
    - The data read from the CSV is then processed and written to JSON output files using `json.dumps` in `src/monitoring_custom_metrics/output_generator.py` within the `write_output_file` function:
      ```python
      def write_output_file(data, output_file_path):
          formatted_json = json.dumps(data, default=int, indent=4)
          with open(output_file_path, "w") as file:
              file.write(formatted_json)
      ```
    - There is no sanitization step between reading the CSV input and writing to the JSON output. Therefore, if the CSV input contains formula injection payloads, these payloads will be directly written into the JSON output files. When a user opens these JSON files with a CSV reader application, the application may interpret and execute these payloads.
  - Security test case:
    1. Create a file named `malicious_input.csv` in the `local_resources/data_quality/` directory with the following content:
    ```csv
    Name,Age
    "=cmd|' /C calc'!A0",30
    ```
    2. Modify the `Dockerfile` to copy the malicious CSV file as input for the container. Change the following line in `Dockerfile`:
    ```dockerfile
    COPY test/resources/data_quality/input.csv /opt/ml/processing/input/data
    ```
    to:
    ```dockerfile
    COPY local_resources/data_quality/malicious_input.csv /opt/ml/processing/input/data
    ```
    3. Run the `run_local.sh` script in the `/code` directory.
    ```bash
    ./run_local.sh
    ```
    4. After the script finishes, navigate to the `local_output/<IMAGE_ID>/` directory.
    5. Open the `community_statistics.json` file using Microsoft Excel or LibreOffice Calc (or another CSV reader application that supports formula execution from CSV files and JSON import). When opening in Excel, choose 'From JSON' in the 'Data' tab and select the `community_statistics.json` file. In LibreOffice Calc, choose 'Open' and select the `community_statistics.json` file, ensuring the file type is set to 'JSON' or 'All files'.
    6. Observe if the calculator application is launched. If it is, the CSV injection vulnerability is confirmed. The calculator launching indicates successful command execution from the injected payload within the CSV file via the JSON output when opened in a CSV reader application.