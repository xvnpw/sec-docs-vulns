### Combined Vulnerability Report

This report summarizes the path traversal vulnerabilities identified in the application. The vulnerabilities stem from the insecure handling of the `ds_name` command-line argument in `generate_data_splits.py`, `generate_asymm_splits.py`, and `main.py` scripts.

#### Vulnerability Name: Path Traversal via Dataset Name

- Description:
    - The application is vulnerable to path traversal. By manipulating the `ds_name` command-line argument, an attacker can potentially read or write files outside of the intended `datasets` directory. This occurs because the application directly incorporates the user-supplied `ds_name` argument into file paths without proper sanitization or validation. Specifically, when loading dataset splits in `util.py`, or when loading and saving datasets in `generate_data_splits.py` and `generate_asymm_splits.py`, the `ds_name` argument is used to construct paths to `.csv` and `.pickle` files. By providing a crafted `ds_name` such as `../../malicious_file`, an attacker could navigate up the directory structure and access or overwrite files in arbitrary locations on the file system, depending on the script's permissions.
    - Steps to trigger:
        1. Prepare a malicious `ds_name` payload, for example: `../../../../tmp/malicious_file`.
        2. Execute `generate_data_splits.py` or `generate_asymm_splits.py` script, providing the malicious payload as the `--ds_name` argument:
            ```bash
            python generate_data_splits.py --ds_name "../../../../tmp/malicious_file" --gamma 10
            ```
            or
            ```bash
            python generate_asymm_splits.py --ds_name "../../../../tmp/malicious_file"
            ```
        3. Alternatively, execute `main.py` with the malicious payload as the `--ds_name` argument:
            ```bash
            python main.py --model_type test_model --ds_name "../../../../tmp/malicious_file" --do_train --k_shot 0
            ```
        4. Observe the application's behavior. It will attempt to access files based on the manipulated path. If successful, depending on the attacker's payload, it could read sensitive files or cause other unintended actions.

- Impact:
    - Successful exploitation of this path traversal vulnerability could allow an attacker to:
        - Information Disclosure: Read sensitive files on the server's file system, potentially including configuration files, application code, or data.
        - Data Integrity: Overwrite existing files, potentially leading to application malfunction or data corruption.
        - Privilege Escalation (Potentially): In more severe scenarios, if the application has write permissions in certain directories, an attacker might be able to upload and execute malicious scripts or binaries, leading to remote code execution.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None. The code directly uses the user-provided dataset name in file path construction without any sanitization or validation.

- Missing Mitigations:
    - Input validation: Sanitize and validate the `ds_name` input to ensure it only contains allowed characters (alphanumeric, underscores, hyphens) and explicitly disallows path traversal sequences like `../` or `..\\`. Implement a whitelist of allowed dataset names. The application should check if the provided `ds_name` is in the whitelist. If not, the application should reject the request.
    - Path sanitization: Employ secure path manipulation functions like `os.path.basename()` to extract only the filename and prevent directory traversal attempts. Construct the full file path by joining a safe base directory with the sanitized filename.
    - Principle of least privilege: Ensure that the application runs with the minimum necessary file system permissions to limit the impact of a successful path traversal attack.

- Preconditions:
    - The attacker needs to be able to execute `generate_data_splits.py`, `generate_asymm_splits.py`, or `main.py` scripts. In a real-world scenario, this might involve providing command-line arguments through a web interface, API, or directly if the attacker has access to the system.
    - The application must have file system read permissions for a read vulnerability and write permissions for a write/overwrite vulnerability in the targeted directories.

- Source Code Analysis:
    1. **`arguments.py`**:
        - Defines the `--ds_name` argument: `parser.add_argument("--ds_name", type=str, required=True, help='Dataset name : ["compas","adult","lawschool","communities"]')`
        - No input validation is performed on `ds_name`.
    2. **`util.py` - `load_dataset` function:**
        ```python
        def load_dataset(args, runid):
        		with open('datasets/{0}/split.pickle'.format(args.ds_name), 'rb') as handle:
        				dataset = pickle.load(handle)
        		return dataset
        ```
        - This function constructs the file path `'datasets/{0}/split.pickle'.format(args.ds_name)` by directly embedding the `args.ds_name` value. If `args.ds_name` is, for example, `../../malicious`, the constructed path becomes `'datasets/../../malicious/split.pickle'`, which resolves to `'malicious/split.pickle'` relative to the script's current directory, effectively traversing out of the intended `datasets` directory.
    3. **`generate_data_splits.py` and `generate_asymm_splits.py`:**
        ```python
        data_X = pd.read_csv('./datasets/{0}/{0}_X.csv'.format(args.ds_name))
        data_y = pd.read_csv('./datasets/{0}/{0}_y.csv'.format(args.ds_name))
        ...
        with open('datasets/{0}/split.pickle'.format(args.ds_name), 'wb') as handle:
        		pickle.dump(dataset, handle, protocol=pickle.HIGHEST_PROTOCOL)
        ```
        - These scripts also use string formatting with `args.ds_name` to construct paths for reading CSV files (`'./datasets/{0}/{0}_X.csv'.format(args.ds_name)`, `'./datasets/{0}/{0}_y.csv'.format(args.ds_name)`) and saving the split pickle file (`'datasets/{0}/split.pickle'.format(args.ds_name)`). Similar to `util.py`, a malicious `ds_name` can lead to path traversal during file operations in these scripts.

    ```mermaid
    graph LR
        A[User Input: --ds_name] --> B(arguments.py: parse_arguments);
        B --> C{args.ds_name};
        C --> D(generate_data_splits.py/generate_asymm_splits.py: save_split);
        C --> E(util.py: load_dataset);
        D --> F[File Path Construction: 'datasets/{ds_name}/...'];
        E --> F;
        F --> G[File System Access];
    ```

- Security Test Case:
    1. Environment setup:
        - Ensure you have the project code and dependencies installed.
        - Navigate to the `/code` directory in your terminal.
    2. Test Steps:
        - Execute `main.py` with a malicious `ds_name` to attempt path traversal:
            ```bash
            python main.py --model_type test_model --ds_name "../../../../tmp/test_traversal_file" --do_train --k_shot 0
            ```
        - To verify the path construction, modify `util.py` to print the constructed path before file access:
            ```python
            # Modified util.py - load_dataset function for testing
            def load_dataset(args, runid):
                    file_path = 'datasets/{0}/split.pickle'.format(args.ds_name)
                    print(f"Attempting to access path: {file_path}")
                    return {} # Return empty dict to avoid file errors
            ```
        - Run `main.py` again with the modified `util.py` and the same malicious `ds_name`:
            ```bash
            python main.py --model_type test_model --ds_name "../../../../tmp/test_traversal_file" --do_train --k_shot 0
            ```
        - Observe the output. The script should print the attempted file path, demonstrating the path traversal vulnerability. For example, the output will show that the script attempts to access the path `datasets/../../../../tmp/test_traversal_file/split.pickle`.
    3. Expected Result:
        - The script output should show that it is attempting to open a file path that includes the path traversal sequence from the malicious `ds_name`, demonstrating that the user-controlled input is directly used in file path construction without sanitization, thus confirming the path traversal vulnerability.