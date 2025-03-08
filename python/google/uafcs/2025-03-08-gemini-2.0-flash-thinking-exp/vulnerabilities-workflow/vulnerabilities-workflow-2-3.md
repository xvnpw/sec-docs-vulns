- Vulnerability name: Path Traversal

- Description:
    The application is vulnerable to path traversal. By manipulating the `ds_name` command-line argument, an attacker can potentially read or write files outside of the intended `datasets` directory. This occurs because the application directly incorporates the user-supplied `ds_name` argument into file paths without proper sanitization or validation. Specifically, when loading dataset splits in `util.py`, or when loading and saving datasets in `generate_data_splits.py` and `generate_asymm_splits.py`, the `ds_name` argument is used to construct paths to `.csv` and `.pickle` files. By providing a crafted `ds_name` such as `../../malicious_file`, an attacker could navigate up the directory structure and access or overwrite files in arbitrary locations on the file system, depending on the script's permissions.

    Steps to trigger:
    1.  Prepare a malicious `ds_name` payload, for example: `../../../../tmp/malicious_file`.
    2.  Execute `generate_data_splits.py` or `generate_asymm_splits.py` script, providing the malicious payload as the `--ds_name` argument:
        ```bash
        python generate_data_splits.py --ds_name "../../../../tmp/malicious_file" --gamma 10
        ```
        or
        ```bash
        python generate_asymm_splits.py --ds_name "../../../../tmp/malicious_file"
        ```
    3.  Alternatively, execute `main.py` with the malicious payload as the `--ds_name` argument:
        ```bash
        python main.py --model_type test_model --ds_name "../../../../tmp/malicious_file" --do_train --k_shot 0
        ```
    4.  Observe the application's behavior. It will attempt to access files based on the manipulated path. If successful, depending on the attacker's payload, it could read sensitive files or cause other unintended actions.

- Impact:
    Successful exploitation of this path traversal vulnerability could allow an attacker to:
    - Read sensitive files on the server's file system, potentially including configuration files, application code, or data.
    - Overwrite existing files, potentially leading to application malfunction or data corruption.
    - In more severe scenarios, if the application has write permissions in certain directories, an attacker might be able to upload and execute malicious scripts or binaries, leading to remote code execution.

- Vulnerability rank: High

- Currently implemented mitigations:
    There are no input sanitization or validation mechanisms implemented in the provided code to prevent path traversal through the `ds_name` argument. The code directly uses the provided `ds_name` in string formatting to construct file paths without any checks.

- Missing mitigations:
    - Input validation: Implement a whitelist of allowed dataset names. The application should check if the provided `ds_name` is in the whitelist. If not, the application should reject the request.
    - Path sanitization: Use secure file path manipulation functions like `os.path.basename()` to extract only the filename and prevent directory traversal attempts. Construct the full file path by joining a safe base directory with the sanitized filename.
    - Running with least privileges: Ensure that the application runs with the minimum necessary file system permissions to limit the impact of a successful path traversal attack.

- Preconditions:
    - The attacker needs to be able to execute `generate_data_splits.py`, `generate_asymm_splits.py`, or `main.py` scripts. In a real-world scenario, this might involve providing command-line arguments through a web interface, API, or directly if the attacker has access to the system.
    - The application must have file system read permissions for a read vulnerability and write permissions for a write/overwrite vulnerability in the targeted directories.

- Source code analysis:
    1. **`util.py` - `load_dataset` function:**
        ```python
        def load_dataset(args, runid):
        		with open('datasets/{0}/split.pickle'.format(args.ds_name), 'rb') as handle:
        				dataset = pickle.load(handle)
        		return dataset
        ```
        - This function constructs the file path `'datasets/{0}/split.pickle'.format(args.ds_name)` by directly embedding the `args.ds_name` value.
        - If `args.ds_name` is, for example, `../../malicious`, the constructed path becomes `'datasets/../../malicious/split.pickle'`, which resolves to `'malicious/split.pickle'` relative to the script's current directory, effectively traversing out of the intended `datasets` directory.

    2. **`generate_data_splits.py` and `generate_asymm_splits.py`:**
        ```python
        data_X = pd.read_csv('./datasets/{0}/{0}_X.csv'.format(args.ds_name))
        data_y = pd.read_csv('./datasets/{0}/{0}_y.csv'.format(args.ds_name))
        ...
        with open('datasets/{0}/split.pickle'.format(args.ds_name), 'wb') as handle:
        		pickle.dump(dataset, handle, protocol=pickle.HIGHEST_PROTOCOL)
        ```
        - These scripts also use string formatting with `args.ds_name` to construct paths for reading CSV files (`'./datasets/{0}/{0}_X.csv'.format(args.ds_name)`, `'./datasets/{0}/{0}_y.csv'.format(args.ds_name)`) and saving the split pickle file (`'datasets/{0}/split.pickle'.format(args.ds_name)`).
        - Similar to `util.py`, a malicious `ds_name` can lead to path traversal during file operations in these scripts.

    **Visualization:**

    ```
    User Input (ds_name) --> Command Line Argument Parsing (arguments.py) --> args.ds_name -->
    String Formatting in File Path (util.py, generate_data_splits.py, generate_asymm_splits.py) -->
    Unsanitized File Path --> File System Access
    ```

- Security test case:
    1.  Environment setup:
        -  Ensure you have the project code and dependencies installed as described in `README.md`.
        -  Navigate to the `/code` directory in your terminal.
        -  Create a test file in the `/tmp` directory (or a directory outside of the project's `datasets` directory to demonstrate traversal), for example:
            ```bash
            echo "This is a test file to check path traversal" > /tmp/test_traversal_file.txt
            ```
    2.  Execute `main.py` with a malicious `ds_name` to attempt to read the test file:
        ```bash
        python main.py --model_type test_model --ds_name "../../../../tmp/test_traversal_file" --do_train --k_shot 0
        ```
        -  **Expected behavior (Vulnerable):** The script execution will likely fail when trying to load `split.pickle` because `/tmp/test_traversal_file` is not a valid dataset directory and does not contain `split.pickle`. However, if you modify the `util.py` to just print the constructed path instead of attempting to open it, you will see that it constructs a path that traverses outside the intended directory:

            ```python
            # Modified util.py - load_dataset function for testing
            def load_dataset(args, runid):
                    file_path = 'datasets/{0}/split.pickle'.format(args.ds_name)
                    print(f"Attempting to access path: {file_path}") # Added print statement
                    # with open(file_path, 'rb') as handle: # Commented out file access
                    #     dataset = pickle.load(handle)
                    # return dataset
                    return {} # Return empty dict to avoid further errors

            ```
        - Run `main.py` again with the modified `util.py` and the same malicious `ds_name`:
            ```bash
            python main.py --model_type test_model --ds_name "../../../../tmp/test_traversal_file" --do_train --k_shot 0
            ```
        - **Observed behavior (Vulnerable):** The output will show that the script attempts to access the path `datasets/../../../../tmp/test_traversal_file/split.pickle`, demonstrating path traversal.

    3.  (Optional - for demonstrating file overwrite - requires write permissions and careful execution): To test for file overwrite, you would need to modify the `generate_data_splits.py` or `generate_asymm_splits.py` to attempt to *write* to a known location outside the `datasets` directory using a manipulated `ds_name`. This test should be performed with caution and in a controlled environment to avoid accidental data loss. For example, you could modify `generate_data_splits.py` to attempt to create a file in `/tmp`:

        ```python
        # Modified generate_data_splits.py - save_split function for testing (CAUTION: potential file creation in /tmp)
        def save_split(args):
                dataset = {"test": "test data"} # dummy dataset
                malicious_filepath = '/tmp/test_traversal_write.txt' # File to attempt to create/overwrite
                filepath = '{0}'.format(malicious_filepath) # Use absolute path directly, or construct with traversal from datasets directory if testing traversal write
                print(f"Attempting to write to path: {filepath}") # Added print statement
                with open(filepath, 'w') as handle: # Attempt to write to the file
                        handle.write("Maliciously written content")
                print(f"Successfully wrote to {filepath}")

        # ... rest of the generate_data_splits.py code ...
        ```
        -  **Caution**:  The above code is for demonstration only and may have unintended consequences. Run it in a safe test environment.
        -  Run the modified `generate_data_splits.py`:
            ```bash
            python generate_data_splits.py --ds_name ignored_dataset_name --gamma 10 # ds_name is ignored in this modified test case, focus on hardcoded path
            ```
        - **Expected behavior (Vulnerable if write permissions):** If the script runs with sufficient permissions, it will create or overwrite the file `/tmp/test_traversal_write.txt` with "Maliciously written content", demonstrating a write path traversal vulnerability (although this example uses a direct path for simplicity, a traversal path can also be constructed).

This security test case demonstrates that the application is vulnerable to path traversal due to the insecure handling of the `ds_name` command-line argument.