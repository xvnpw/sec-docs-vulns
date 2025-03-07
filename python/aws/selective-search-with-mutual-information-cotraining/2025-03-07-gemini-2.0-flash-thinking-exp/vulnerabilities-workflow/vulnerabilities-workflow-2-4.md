- ### Vulnerability 1: Path Traversal in Data Loading

    - Description:
        1. An attacker can control the `train_folder_path` or `test_folder_path` parameters provided to the `main.py` script, either directly or through the `run_mico.sh` script.
        2. By providing a maliciously crafted path containing path traversal sequences like `../`, the attacker can instruct the application to access file system locations outside the intended data directories.
        3. The application uses the `os.listdir` function on these user-provided paths to enumerate CSV files.
        4. Subsequently, it constructs full file paths by simply concatenating the potentially malicious base path with the filenames obtained from `os.listdir`.
        5. When the application attempts to open and process these files as CSV datasets, it may access files located anywhere on the server's filesystem, depending on the permissions of the process.
        6. This path traversal vulnerability allows an attacker to read sensitive files or potentially overwrite files if write operations were performed based on these paths (although the current code only reads files).

    - Impact:
        - High. Successful exploitation of this vulnerability allows an attacker to read arbitrary files on the server's filesystem that the application process has permissions to access. This could include sensitive data, configuration files, source code, or other confidential information.

    - Vulnerability Rank: High

    - Currently Implemented Mitigations:
        - None. The codebase lacks any input validation, sanitization, or checks to prevent path traversal via the `train_folder_path` and `test_folder_path` parameters. The paths are used directly with file system operations.

    - Missing Mitigations:
        - **Input Validation and Sanitization**: Implement robust validation and sanitization of the `train_folder_path` and `test_folder_path` parameters. This should include checks to ensure that the paths are within the expected data directories and do not contain path traversal sequences (e.g., `../`).
        - **Secure Path Manipulation**: Utilize secure path manipulation functions provided by the operating system or libraries that prevent traversal outside of designated directories. For example, using functions that resolve paths relative to a safe base directory and prevent escaping this base.
        - **Principle of Least Privilege**: Restrict the file system permissions of the application process to the minimum necessary. This limits the impact of a successful path traversal exploit by reducing the set of files an attacker can access even if the vulnerability is exploited.

    - Preconditions:
        - The attacker must be able to execute the `main.py` script or `run_mico.sh` script.
        - The attacker must have the ability to control the command-line arguments, specifically `train_folder_path` and `test_folder_path`. This could be through direct execution of the scripts or indirectly if these parameters are exposed through a configuration interface or API.

    - Source Code Analysis:
        1. File: `/code/mico/dataloader/query_doc_pair.py`
        2. Function: `QueryDocumentsPair.__init__`
        3. Vulnerable Code Snippet:
            ```python
            train_files = list(map(lambda x : train_folder_path + '/' + x, (filter(lambda x : x.endswith("csv"), sorted(os.listdir(train_folder_path))))))
            test_files = list(map(lambda x : test_folder_path + '/' + x, (filter(lambda x : x.endswith("csv"), sorted(os.listdir(test_folder_path))))))
            ```
        4. **Step-by-step analysis:**
            - The `QueryDocumentsPair` class constructor takes `train_folder_path` and `test_folder_path` as input parameters, which are derived from the command-line arguments.
            - `os.listdir(train_folder_path)` and `os.listdir(test_folder_path)` are called directly using these paths. `os.listdir` lists the contents of the directory specified by the path. If a path traversal sequence is present in `train_folder_path` or `test_folder_path`, `os.listdir` will operate on a directory outside the intended data directory.
            - The code then uses a `map` function along with a lambda expression to construct file paths. The lambda expression `lambda x : train_folder_path + '/' + x` (and similarly for `test_folder_path`) concatenates the base folder path with each filename `x` obtained from `os.listdir`. This concatenation is vulnerable because if `train_folder_path` (or `test_folder_path`) is malicious, the resulting file paths will also be malicious.
            - The `filter(lambda x : x.endswith("csv"), ...)` part only filters the list of files to include those ending with ".csv", but it does not prevent path traversal.
            - The resulting `train_files` and `test_files` lists contain full, potentially malicious, file paths that are then used by `LazyTextDataset` to open and read the CSV files.

    - Security Test Case:
        1. Set up a testing environment where the MICO project is installed. Assume the project root directory is `/app/mico`.
        2. Create a sensitive file outside the intended data directories, for example, `/tmp/sensitive_data.txt` with content "This is sensitive information.".
        3. Execute the `run_mico.sh` script, but modify the `train_folder_path` parameter to traverse to the `/tmp` directory and attempt to list and process `sensitive_data.txt` (renamed to have a `.csv` extension for the filter to pass):
            ```bash
            ./example/scripts/run_mico.sh --train_folder_path="/tmp/../tmp/" --test_folder_path="./example/data/example_dataset_test_csv/"
            ```
            *(Note: We use `/tmp/../tmp/` to explicitly show path traversal and ensure the path resolves to `/tmp` even if there are symbolic links or other path manipulations)*
        4. Rename `/tmp/sensitive_data.txt` to `/tmp/sensitive_data.csv` to match the `.csv` file extension filter.
        5. Run the modified `run_mico.sh` command.
        6. Observe the application logs. If the path traversal is successful, the application will attempt to read and parse `/tmp/sensitive_data.csv` as a training data file. While the CSV parsing might fail if `/tmp/sensitive_data.csv` is not a valid CSV file, the attempt to open and read this file from outside the intended data directory confirms the path traversal vulnerability.
        7. To further confirm, you can place a valid CSV file in `/tmp/` (e.g., `/tmp/test_traversal.csv`) and verify that the application processes this file when `train_folder_path` is set to `/tmp/`. This clearly demonstrates that the application is loading data from an attacker-controlled location outside the intended project data directory, proving the path traversal vulnerability.