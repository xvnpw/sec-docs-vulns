- Vulnerability Name: Path Traversal via Dataset Name
- Description:
    - The scripts `generate_data_splits.py`, `generate_asymm_splits.py`, and `main.py` use the `--ds_name` argument to construct file paths for loading dataset related files.
    - The dataset name is incorporated into paths like `'datasets/{ds_name}/{ds_name}_X.csv'` and `'datasets/{ds_name}/split.pickle'`.
    - If a malicious user provides a crafted dataset name containing path traversal characters (e.g., `../`, `..\\`), they can escape the intended 'datasets' directory.
    - This allows an attacker to access or potentially overwrite arbitrary files on the system when the scripts are executed.
    - For example, setting `--ds_name '../sensitive_data'` could lead to accessing files in the parent directory.
- Impact:
    - An attacker could read sensitive files from the server's file system if the Python scripts are running with sufficient privileges.
    - In a more severe scenario, if the application were extended to write data based on dataset name (not present in current code, but a potential future risk), an attacker could potentially overwrite system files or inject malicious data.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The code directly uses the user-provided dataset name in file path construction without any sanitization or validation.
- Missing Mitigations:
    - Input validation: Sanitize and validate the `ds_name` input to ensure it only contains allowed characters (alphanumeric, underscores, hyphens) and explicitly disallows path traversal sequences like `../` or `..\\`.
    - Path sanitization: Employ secure path manipulation functions to prevent path traversal, although input validation is the most direct and effective solution here.
    - Principle of least privilege: Ensure the scripts are run with minimal necessary privileges to limit the potential damage from a successful path traversal.
- Preconditions:
    - An attacker needs to be able to execute one of the Python scripts (`generate_data_splits.py`, `generate_asymm_splits.py`, or `main.py`).
    - The scripts must be running in an environment where the file system can be accessed based on the crafted path.
- Source Code Analysis:
    - **`arguments.py`**:
        - Defines the `--ds_name` argument: `parser.add_argument("--ds_name", type=str, required=True, help='Dataset name : ["compas","adult","lawschool","communities"]')`
        - No input validation is performed on `ds_name`.
    - **`generate_data_splits.py` and `generate_asymm_splits.py`**:
        - In `save_split(args)` function, `args.ds_name` is used directly in file path construction:
            - `open('datasets/{0}/split.pickle'.format(args.ds_name), 'wb')`
            - `open('datasets/{0}/split.pickle'.format(args.ds_name), 'rb')` (indirectly through `load_datasets` and `load_other_datasets`)
            - `'./datasets/{0}/{0}_X.csv'.format(args.ds_name)` (indirectly through `load_datasets` and `load_other_datasets`)
            - `'./datasets/{0}/{0}_y.csv'.format(args.ds_name)` (indirectly through `load_datasets` and `load_other_datasets`)
        - No sanitization or validation of `args.ds_name` is performed before file path construction.
    - **`util.py`**:
        - In `load_dataset(args, runid)` function, `args.ds_name` is used directly in file path construction:
            - `open('datasets/{0}/split.pickle'.format(args.ds_name), 'rb')`
        - No sanitization or validation of `args.ds_name` is performed.
    - **`main.py`**:
        - Calls `util.load_dataset(args, runid)`, passing the potentially malicious `args.ds_name`.

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
    1. Prerequisites:
        - Set up the project in a test environment.
        - Identify a file outside the 'datasets' directory that the user running the script has permissions to read (e.g., `../../README.md` if a README.md exists in the parent directory relative to the project root).
    2. Test Steps:
        - Navigate to the project's code directory in a terminal.
        - Execute `generate_data_splits.py` (or `generate_asymm_splits.py`) with a crafted `ds_name` to attempt path traversal to read the identified file.
          ```bash
          python generate_data_splits.py --ds_name '../../README' --gamma 1.0
          ```
        - To confirm the vulnerability, temporarily modify `generate_data_splits.py` (or `util.py` or `generate_asymm_splits.py`) to print the file path being constructed just before the `open()` call in the `save_split` or `load_dataset` function. For example, in `generate_data_splits.py`:
          ```python
          # ... inside save_split function, before 'with open(...)':
          file_path = 'datasets/{0}/split.pickle'.format(args.ds_name) # or similar vulnerable path
          print(f"Attempting to open file: {file_path}") # Add this line
          with open(file_path, 'wb') as handle:
              pickle.dump(dataset, handle, protocol=pickle.HIGHEST_PROTOCOL)
          ```
        - Run the modified script again with the same malicious `ds_name`:
          ```bash
          python generate_data_splits.py --ds_name '../../README' --gamma 1.0 > output.txt 2>&1
          ```
        - Examine the output (`output.txt`). Check if the printed file path in the output shows the attempted path traversal (e.g., if it prints `'datasets/../../README/split.pickle'` or similar, indicating the `../../README` was used in path construction).
        - If the script attempts to open a file path that includes the traversal sequence, it confirms the path traversal vulnerability. Further steps could involve trying to read the content of `../../README.md` within the script (after confirming path construction) to demonstrate arbitrary file reading, but observing the attempted path is sufficient to validate the vulnerability.
    3. Expected Result:
        - The script output should show that it is attempting to open a file path that includes the path traversal sequence from the malicious `ds_name`, demonstrating that the user-controlled input is directly used in file path construction without sanitization, thus confirming the path traversal vulnerability.