### Vulnerability List

- Vulnerability Name: Path Traversal in Dataset Name (generate_data_splits.py and generate_asymm_splits.py)
- Description:
    1. The `generate_data_splits.py` and `generate_asymm_splits.py` scripts take the dataset name as a command-line argument `--ds_name`.
    2. This `ds_name` argument is used to construct file paths for reading dataset files.
    3. Specifically, in `generate_data_splits.py` and `generate_asymm_splits.py`, the scripts use the dataset name to read CSV files from the `./datasets/{ds_name}/{ds_name}_X.csv` and `./datasets/{ds_name}/{ds_name}_y.csv` paths.
    4. If an attacker provides a maliciously crafted `ds_name` containing path traversal characters (e.g., `../../`), the script might attempt to access files outside of the intended `./datasets/` directory.
    5. For example, providing `--ds_name '../../sensitive_data'` could make the script attempt to read files like `./datasets/../../sensitive_data/../../sensitive_data_X.csv`, potentially accessing sensitive information or system files, depending on file system permissions and the script's error handling.
- Impact:
    - Information Disclosure: An attacker could potentially read arbitrary files from the file system if the script is run with sufficient permissions. This could include sensitive data or configuration files.
    - Data Integrity: In scenarios where the script attempts to write files based on the dataset name (though not evident in the provided code snippets for data splitting), path traversal could lead to writing data to unexpected locations, potentially corrupting system files or other datasets.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations: None
- Missing Mitigations:
    - Input validation for the `ds_name` argument in `generate_data_splits.py` and `generate_asymm_splits.py`.
    - Sanitize the `ds_name` input to remove or escape path traversal characters.
    - Implement a whitelist of allowed dataset names and check the provided `ds_name` against this whitelist. This is the most secure approach.
- Preconditions:
    - The attacker must be able to execute the `generate_data_splits.py` or `generate_asymm_splits.py` script.
    - The attacker must be able to provide command-line arguments to the script, specifically the `--ds_name` argument.
- Source Code Analysis:
    - File: `/code/generate_data_splits.py`
    ```python
    def load_datasets(args):
        data_X = pd.read_csv('./datasets/{0}/{0}_X.csv'.format(args.ds_name))
        data_y = pd.read_csv('./datasets/{0}/{0}_y.csv'.format(args.ds_name))
        # ...
    ```
    - File: `/code/generate_asymm_splits.py`
    ```python
    def load_other_datasets(args):
        data_X = pd.read_csv('./datasets/{0}/{0}_X.csv'.format(args.ds_name))
        data_y = pd.read_csv('./datasets/{0}/{0}_y.csv'.format(args.ds_name))
        # ...
    ```
    - In both scripts, `args.ds_name` is directly embedded into the file path using string formatting without any validation or sanitization. This allows an attacker to manipulate the file path by providing path traversal sequences in `args.ds_name`. For example, if `args.ds_name` is set to `'../../test'`, the script will try to open `./datasets/../../test/../../test_X.csv`, which resolves to `./test/../../test_X.csv` relative to the script's execution directory, effectively traversing out of the intended `datasets` directory.

- Security Test Case:
    1. **Setup:** Ensure you have the project code and can execute `generate_data_splits.py` or `generate_asymm_splits.py`.
    2. **Execution:** Run the `generate_data_splits.py` script with a malicious dataset name using the following command:
        ```bash
        python generate_data_splits.py --ds_name '../../test_dataset' --gamma 10.0
        ```
        Or run `generate_asymm_splits.py` with:
        ```bash
        python generate_asymm_splits.py --ds_name '../../test_dataset'
        ```
    3. **Verification:** Observe the output and error messages. If the script attempts to access a file path that includes the path traversal sequence `../../test_dataset`, such as  `datasets/../../test_dataset/../../test_dataset_X.csv` or similar, it indicates a path traversal vulnerability. Ideally, the script should either throw a `FileNotFoundError` if the dataset path is invalid within the intended `datasets` directory, or it should be prevented from even attempting to access paths outside of the `./datasets/` directory due to proper input validation. If the script attempts to open a file in a directory like `./test_dataset` (relative to the project root, outside of `./datasets`), this confirms the vulnerability.
    4. **Expected Result:** The script should attempt to read a file from a path that includes the injected path traversal sequence, demonstrating that the input is not properly validated and the path traversal vulnerability exists. A secure implementation would prevent accessing paths outside of the intended datasets directory, possibly by validating the dataset name against a whitelist or sanitizing the input.

- Vulnerability Name: Path Traversal in Dataset Name (main.py)
- Description:
    1. The `main.py` script also takes the dataset name as a command-line argument `--ds_name`.
    2. This `ds_name` argument is used to construct a file path for loading a pickled dataset split file.
    3. Specifically, in `main.py`, the script uses the dataset name to open a pickle file from the path `'datasets/{0}/split.pickle'.format(args.ds_name)`.
    4. Similar to the data splitting scripts, if an attacker provides a maliciously crafted `ds_name` containing path traversal characters (e.g., `../../`), the script might attempt to access files outside of the intended `./datasets/` directory.
    5. For example, providing `--ds_name '../../sensitive_dataset'` could make the script attempt to read a file like `'datasets/../../sensitive_dataset/split.pickle'`, potentially leading to information disclosure if sensitive files are accessible.
- Impact:
    - Information Disclosure: An attacker could potentially read arbitrary files if the script is run with permissions to access them.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations: None
- Missing Mitigations:
    - Input validation for the `ds_name` argument in `main.py`.
    - Sanitize the `ds_name` input.
    - Implement a whitelist of allowed dataset names.
- Preconditions:
    - The attacker must be able to execute the `main.py` script.
    - The attacker must be able to provide command-line arguments, specifically the `--ds_name` argument.
- Source Code Analysis:
    - File: `/code/main.py`
    ```python
    def perform_run(args, runid):
        # ...
        dataset = util.load_dataset(args, runid)
        # ...

    # File: /code/util.py
    def load_dataset(args, runid):
        with open('datasets/{0}/split.pickle'.format(args.ds_name), 'rb') as handle:
            dataset = pickle.load(handle)
        return dataset
    ```
    - In `util.load_dataset`, `args.ds_name` is directly used in string formatting to construct the file path without any validation. This allows for path traversal if a malicious `ds_name` is provided.
- Security Test Case:
    1. **Setup:** Ensure you have the project code and can execute `main.py`.
    2. **Execution:** Run the `main.py` script with a malicious dataset name using the following command:
        ```bash
        python main.py --model_type wass_and_entropy_model --ds_name '../../test_dataset' --do_train --k_shot 0
        ```
        (Replace `wass_and_entropy_model` with a valid `model_type` if needed, though model type is not relevant for this test).
    3. **Verification:** Observe the output and error messages. If the script attempts to access a file path that includes the path traversal sequence `../../test_dataset`, such as `datasets/../../test_dataset/split.pickle`, it indicates a path traversal vulnerability.
    4. **Expected Result:** Similar to the data splitting scripts, the script should attempt to read a file from a path that includes the injected path traversal sequence, confirming the vulnerability. A secure implementation would prevent such access through input validation or whitelisting.