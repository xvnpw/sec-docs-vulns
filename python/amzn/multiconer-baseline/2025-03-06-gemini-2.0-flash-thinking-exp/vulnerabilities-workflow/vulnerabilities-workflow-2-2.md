### Vulnerability 1: Path Traversal in File Path Arguments

- **Vulnerability Name:** Path Traversal in File Path Arguments
- **Description:**
    1. The application uses command-line arguments `--train`, `--test`, `--dev`, and `--model` to specify file paths for training, testing, development data, and model files.
    2. The `parse_args` function in `utils.py` defines these arguments as strings without any input validation or sanitization.
    3. The `get_reader` function in `utils.py` takes the file path argument and passes it to `CoNLLReader.read_data`.
    4. The `CoNLLReader.read_data` function in `reader.py` directly uses the provided file path to open files using `gzip.open` or `open` without any sanitization.
    5. An attacker can provide a malicious file path, such as "../../sensitive_file.txt", as the value for `--train`, `--test`, `--dev`, or `--model`.
    6. The application will then attempt to open and process the file at the attacker-specified path, potentially leading to reading arbitrary files outside the intended directory.
- **Impact:**
    - An attacker can read arbitrary files on the system, including sensitive data, by providing a path traversal string as a file path argument.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:** None
- **Missing Mitigations:**
    - Input validation and sanitization for file path arguments to prevent path traversal.
    - Implement checks to ensure that the provided file paths are within the expected directories or use allow lists for permitted paths.
    - Consider using secure file path handling mechanisms, such as limiting access to a specific directory or using a safe path library to resolve and validate paths.
- **Preconditions:**
    - The application must be running and accessible to the attacker.
    - The attacker must be able to provide command-line arguments to the application, either directly or indirectly through a wrapper script or API.
- **Source Code Analysis:**
    1. **`utils.py:parse_args()`**: Defines command-line arguments `--train`, `--test`, `--dev`, and `--model` as strings without any validation.
    ```python
    def parse_args():
        p = argparse.ArgumentParser(description='Model configuration.', add_help=False)
        p.add_argument('--train', type=str, help='Path to the train data.', default=None)
        p.add_argument('--test', type=str, help='Path to the test data.', default=None)
        p.add_argument('--dev', type=str, help='Path to the dev data.', default=None)
        p.add_argument('--model', type=str, help='Model path.', default=None)
        ...
        return p.parse_args()
    ```
    2. **`utils.py:get_reader()`**:  Passes the file path argument directly to the `CoNLLReader`.
    ```python
    def get_reader(file_path, max_instances=-1, max_length=50, target_vocab=None, encoder_model='xlm-roberta-large'):
        if file_path is None:
            return None
        reader = CoNLLReader(max_instances=max_instances, max_length=max_length, target_vocab=target_vocab, encoder_model=encoder_model)
        reader.read_data(file_path)
        return reader
    ```
    3. **`reader.py:CoNLLReader.read_data()`**: Uses `gzip.open` or `open` directly with the user-provided file path, leading to potential path traversal.
    ```python
    class CoNLLReader(Dataset):
        ...
        def read_data(self, data):
            dataset_name = data if isinstance(data, str) else 'dataframe'
            logger.info('Reading file {}'.format(dataset_name))
            instance_idx = 0

            for fields, metadata in get_ner_reader(data=data):
                ...
            logger.info('Finished reading {:d} instances from file {}'.format(len(self.instances), dataset_name))

    def get_ner_reader(data):
        fin = gzip.open(data, 'rt') if data.endswith('.gz') else open(data, 'rt') # Vulnerability: Path traversal here
        for is_divider, lines in itertools.groupby(fin, _is_divider):
            ...
    ```

- **Security Test Case:**
    1. Create a dummy file named "test_file.txt" in the parent directory of the project with content "This is a test file to check path traversal".
    2. Run the `predict_tags.py` script, providing the path to the dummy file using path traversal as the `--test` argument:
       ```bash
       python -m ner_baseline.predict_tags --test ../test_file.txt --out_dir . --model MODEL_FILE_PATH --prefix traversal_test
       ```
       *(Replace `MODEL_FILE_PATH` with a valid model path. If a model is not strictly required for the reader to execute and potentially fail due to file format, a dummy path is sufficient).*
    3. Check the output in the console or logs. If the application attempts to read or process `../test_file.txt`, it indicates a path traversal vulnerability. For example, if the application expects a CoNLL format file and tries to parse `test_file.txt`, it will likely throw an error related to file format, but this confirms that the file was accessed from the traversed path.
    4. To further confirm, you can temporarily modify `utils/reader.py` within the `get_ner_reader` function to print the `data` variable (which holds the file path) right before opening the file.
       ```python
       def get_ner_reader(data):
           print(f"Attempting to open file: {data}") # Added print statement for debugging
           fin = gzip.open(data, 'rt') if data.endswith('.gz') else open(data, 'rt')
           ...
       ```
       After running the test case again, the console output will show the attempted file path, confirming if path traversal is occurring. Remember to remove the print statement after testing.