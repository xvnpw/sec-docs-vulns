### Vulnerability List

* Vulnerability Name: Unvalidated File Path in Configuration Leads to Local File Inclusion
* Description:
    1. The `run.sh` script accepts a file path for the configuration file (`config_avs.json`) as a command-line argument.
    2. This file path is passed to the Python script `run.py` without any validation or sanitization in the shell script itself.
    3. Inside `run.py`, the script opens and reads the file specified by the user-provided path.
    4. If a user provides a path to a file outside the intended configuration directory, the script will still attempt to read and parse it as a JSON configuration.
    5. An attacker could provide a path to a sensitive file on the user's local system, hoping that the Python script will read and potentially process its contents.
    6. While the script is designed to parse JSON, if the attacker can predict or control how certain file contents might be interpreted (even if not valid JSON), they might be able to influence the script's behavior or leak information.
    7. Although the primary intended attack vector is malicious JSON within a `config_avs.json`, the lack of file path validation introduces a broader Local File Inclusion vulnerability.
* Impact:
    - Low to Medium.
    - An attacker could potentially read the contents of local files on the system where the script is executed, depending on file permissions and how the script processes the file content.
    - This could lead to information disclosure if sensitive files are accessed.
    - The impact is limited as the script primarily expects JSON configuration, and simply reading a file might not directly lead to code execution or system compromise. However, depending on future script modifications or unforeseen interactions, the risk could increase.
* Vulnerability Rank: Medium
* Currently Implemented Mitigations:
    - None. The script directly uses the user-provided file path without validation.
* Missing Mitigations:
    - **File Path Validation**: Implement validation to ensure the provided file path is within an expected directory or conforms to a specific pattern.
    - **Input Sanitization**: While not directly related to file inclusion, ensure all inputs read from the configuration file are properly sanitized and validated to prevent further vulnerabilities like command injection or arbitrary code execution in other parts of the script.
* Preconditions:
    - The attacker needs to trick a user into running the `run.sh` or `run.ps1` script with a maliciously crafted file path as the configuration file argument.
    - The user must execute the script on a system where they have access to sensitive files that the attacker wants to read.
* Source Code Analysis:
    1. **`src/run.sh`**:
        ```bash
        if [ -n "$2" ] && [ -f "$2" ]
        then
          # ... proxy configurations based on $2 ...
        fi
        ...
        python ./appliance_setup/run.py "$1" "$2" "${3:-INFO}" "${4:-false}"
        ```
        - The script takes the second command-line argument `$2` as the file path.
        - It checks if `$2` is not empty and if the file exists using `[ -f "$2" ]`.
        - However, it does not validate the *path* itself. It only checks for file existence, not the allowed location of the file.
        - `$2` is then directly passed as an argument to the Python script `run.py`.

    2. **`src/appliance_setup/run.py`**:
        ```python
        file_path = None
        try:
            file_path = sys.argv[2]
        except IndexError:
            raise FilePathNotFoundInArgs('Config file path is not given in command line arguments.')
        config = None
        with open(file_path, 'r') as f:
            data = f.read()
            config = json.loads(data)
        ```
        - `run.py` retrieves the file path from `sys.argv[2]`.
        - It directly opens the file using `open(file_path, 'r')`.
        - No validation is performed on `file_path` to restrict it to a specific directory or pattern.
        - The content of the file is then read and parsed as JSON using `json.loads(data)`.

    *Visualization:*

    ```
    User Input (malicious file path) --> run.sh --> run.py --> open(file_path) --> Read Local File
    ```

* Security Test Case:
    1. **Prerequisites**:
        - Access to the project code.
        - A system where the `run.sh` script can be executed (Linux-based).
        - A sensitive file on the system, for example, a text file named `sensitive_data.txt` in the user's home directory containing some dummy sensitive information.

    2. **Steps**:
        - Open a terminal in the project's `/code/src` directory.
        - Execute the `run.sh` script with the `onboard` operation and the path to the sensitive file as the config file argument. For example:
          ```bash
          sudo chmod +x run.sh
          sudo bash run.sh onboard /home/$USER/sensitive_data.txt
          ```
        - Observe the script's output and logs (in the `logs` directory if logging is configured to DEBUG or INFO).

    3. **Expected Result**:
        - The script will attempt to read and parse the contents of `/home/$USER/sensitive_data.txt` as JSON.
        - If `sensitive_data.txt` is not valid JSON, the `json.loads(data)` in `run.py` will likely throw a `json.JSONDecodeError`. However, the script will still have successfully *read* the file.
        - Check the log files (e.g., `logs/log_YYYY-MM-DD-HH.MM.SS.err` or `.info`). While the script might fail due to JSON parsing error, the logs or standard output might inadvertently reveal parts of the content of `sensitive_data.txt` if the error messages or subsequent processing attempts include parts of the file content before the JSON parsing failure occurs.
        - Even if no content is directly revealed in logs, the fact that the script attempts to open and process an arbitrary file path demonstrates the Local File Inclusion vulnerability.

    4. **Pass/Fail**:
        - **Fail**: If the script attempts to open and process the file specified by `/home/$USER/sensitive_data.txt` without any path validation. This indicates a Local File Inclusion vulnerability exists.
        - **Pass**: If the script validates the file path and refuses to process `/home/$USER/sensitive_data.txt`, or if it consistently handles the error in a way that prevents any information leakage and confirms path validation is in place.

This test case demonstrates that the script attempts to process a file outside the intended scope, confirming the Local File Inclusion vulnerability due to lack of file path validation.