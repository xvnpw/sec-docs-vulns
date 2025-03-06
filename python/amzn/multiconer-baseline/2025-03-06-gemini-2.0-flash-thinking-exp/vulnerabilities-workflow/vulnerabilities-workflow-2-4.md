### Vulnerability List

- Vulnerability Name: Path Traversal
- Description: The application is vulnerable to path traversal. By manipulating the command line arguments `--train`, `--test`, `--dev`, or `--out_dir`, an attacker can specify arbitrary file paths. This allows an attacker to read arbitrary files from the system by providing a path to a sensitive file as input to `--train`, `--test`, or `--dev`. Additionally, an attacker can write files to arbitrary locations by providing a malicious path to `--out_dir`, potentially overwriting existing files or placing malicious files in sensitive directories.
- Impact:
    - Read arbitrary files: An attacker can read any file on the server that the application has read access to, potentially including sensitive configuration files, source code, or data.
    - Write arbitrary files: An attacker can write files to any directory on the server that the application has write access to. This can be used to overwrite existing files, inject malicious code, or cause other damage.
- Vulnerability Rank: Critical
- Currently implemented mitigations: None
- Missing mitigations:
    - Sanitize user-provided file paths: Validate and sanitize the file paths provided by users to ensure they are within expected directories.
    - Use absolute paths for intended directories: Configure the application to use absolute paths for intended directories and prevent users from navigating outside of these directories.
    - Principle of least privilege: Run the application with minimal necessary privileges to limit the impact of potential file system access vulnerabilities.
- Preconditions:
    - The application must be running.
    - An attacker must be able to provide command-line arguments to the application (e.g., through a web interface if exposed, or direct command execution).
- Source code analysis:
    1. `utils/utils.py` - `parse_args()`: The function parses command-line arguments including `--train`, `--test`, `--dev`, and `--out_dir` and stores them as strings without any validation.
    ```python
    def parse_args():
        p = argparse.ArgumentParser(...)
        p.add_argument('--train', type=str, help='Path to the train data.', default=None)
        p.add_argument('--test', type=str, help='Path to the test data.', default=None)
        p.add_argument('--dev', type=str, help='Path to the dev data.', default=None)
        p.add_argument('--out_dir', type=str, help='Output directory.', default='.')
        # ...
        return p.parse_args()
    ```
    2. `utils/utils.py` - `get_reader(file_path, ...)`: This function takes `file_path` argument and passes it to `CoNLLReader`.
    ```python
    def get_reader(file_path, ...):
        if file_path is None:
            return None
        reader = CoNLLReader(...)
        reader.read_data(file_path)
        return reader
    ```
    3. `utils/reader.py` - `CoNLLReader.read_data(data)`: This function takes `data` (which is `file_path`) and passes it to `get_ner_reader`.
    ```python
    class CoNLLReader(Dataset):
        # ...
        def read_data(self, data):
            dataset_name = data if isinstance(data, str) else 'dataframe'
            logger.info('Reading file {}'.format(dataset_name))
            # ...
            for fields, metadata in get_ner_reader(data=data):
                # ...
    ```
    4. `utils/reader_utils.py` - `get_ner_reader(data)`: This function directly opens the file using `gzip.open` or `open` with the user-provided `data` path.
    ```python
    def get_ner_reader(data):
        fin = gzip.open(data, 'rt') if data.endswith('.gz') else open(data, 'rt')
        for is_divider, lines in itertools.groupby(fin, _is_divider):
            # ...
    ```
    5. `utils/utils.py` - `save_model(trainer, out_dir, ...)`: This function takes `out_dir` argument and uses it to create directory and save model files.
    ```python
    def save_model(trainer, out_dir, model_name='', timestamp=None):
        out_dir = out_dir + '/lightning_logs/version_' + str(trainer.logger.version) + '/checkpoints/'
        os.makedirs(out_dir, exist_ok=True)
        outfile = out_dir + '/' + model_name + '_timestamp_' + str(timestamp) + '_final.ckpt'
        trainer.save_checkpoint(outfile, weights_only=True)
        # ...
    ```
- Security test case:
    1. Assume the attacker has access to execute the training script `train_model.py`.
    2. To test arbitrary file read, the attacker sets the `--train` argument to point to a sensitive file, e.g., `/etc/passwd`.
    ```bash
    python -m ner_baseline.train_model --train /etc/passwd --dev dev.txt --out_dir . --model_name test_read --gpus 0 --epochs 1
    ```
    3. Run the script. The script will attempt to read and process `/etc/passwd` as a training dataset. While the script might fail due to format incompatibility, it demonstrates the ability to open and attempt to read the specified file. If successful in parsing, the content of `/etc/passwd` would be processed.
    4. To test arbitrary file write, the attacker sets the `--out_dir` argument to a sensitive directory, e.g., `/tmp/evil_dir`.
    ```bash
    python -m ner_baseline.train_model --train train.txt --dev dev.txt --out_dir /tmp/evil_dir --model_name test_write --gpus 0 --epochs 1
    ```
    5. Run the script. The script will create directories and save model files under `/tmp/evil_dir`, demonstrating the ability to write to arbitrary locations.