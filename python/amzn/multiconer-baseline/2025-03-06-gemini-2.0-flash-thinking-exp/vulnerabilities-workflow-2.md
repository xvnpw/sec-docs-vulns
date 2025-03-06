## Combined Vulnerability Report: Path Traversal in Command Line Arguments

This report identifies a critical Path Traversal vulnerability within the application, stemming from insufficient validation of file paths provided through command-line arguments. This vulnerability allows an attacker to read arbitrary files from the server and potentially write files to arbitrary locations.

### Vulnerability: Path Traversal in Command Line Arguments

- **Vulnerability Name:** Path Traversal in Command Line Arguments
- **Description:**
    The application is susceptible to path traversal attacks due to the insecure handling of file paths provided via command-line arguments: `--train`, `--test`, `--dev`, `--model`, and `--out_dir`. These arguments, intended to specify file paths for data, models, and output directories, are processed without adequate validation or sanitization.

    1. The application accepts file paths as command-line arguments for training, testing, and development datasets via the `--train`, `--test`, and `--dev` parameters, for model loading via `--model`, and for specifying the output directory via `--out_dir`.
    2. These file paths are parsed by the `argparse` module in `utils.py` and stored as strings without any initial validation.
    3. For data loading arguments (`--train`, `--test`, `--dev`), the paths are passed to the `get_reader` function in `utils.py`.
    4. The `get_reader` function initializes a `CoNLLReader` object and subsequently calls its `read_data` method, passing the provided file path.
    5. Within the `read_data` method of `CoNLLReader` (in `utils/reader.py`), the application calls `get_ner_reader` from `utils/reader_utils.py` with the user-supplied file path.
    6. The `get_ner_reader` function in `utils/reader_utils.py` directly opens the file path using either `gzip.open` or `open` based on the file extension without any validation or sanitization to prevent path traversal.
    7. For the model loading argument (`--model`), the path is used in the `load_model` function in `utils.py`. This function attempts to load a model using `NERBaseAnnotator.load_from_checkpoint` without proper path validation, although it includes an insufficient `os.path.isfile` check.
    8. For the output directory argument (`--out_dir`), the path is used in the `save_model` function in `utils.py` to create directories and save model files using `os.makedirs`, again without sufficient path validation.
    9. By supplying maliciously crafted file paths containing directory traversal sequences (e.g., `../`), an attacker can bypass intended directory restrictions to read arbitrary files from the server's file system or write files to arbitrary locations, depending on the vulnerable argument used.

- **Impact:**
    - **Arbitrary File Read:** An attacker can read sensitive files from the server's file system that the application user has access to. This could include configuration files, source code, data files, or other sensitive information, potentially leading to information disclosure and further compromise of the system.
    - **Arbitrary File Write:** An attacker can write files to arbitrary locations on the server's file system. This could be exploited to overwrite existing files, inject malicious code into system directories, or cause denial of service by filling up disk space, although the primary risk in this context is unauthorized file manipulation and potential code injection if writable directories are misused.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - None. The application directly utilizes the provided file paths without any input validation or sanitization to prevent path traversal attacks for data loading and output directories.
    - Insufficient `os.path.isfile(model_file)` check in `load_model` function. This check only verifies if a file exists at the given path but does not prevent path traversal, as it does not validate if the path is within an allowed directory.

- **Missing Mitigations:**
    - **Input Validation and Sanitization:** Implement robust input validation and sanitization for all file paths provided via command-line arguments (`--train`, `--test`, `--dev`, `--model`, `--out_dir`).
    - **Path Restriction:** Implement checks to ensure that the provided file paths are restricted to within expected directories or a predefined set of allowed directories. For data and model files, enforce paths to be within designated input directories. For output directories, restrict to allowed output locations.
    - **Directory Traversal Sequence Neutralization:** Sanitize file paths to remove or neutralize directory traversal sequences (e.g., `../`, `..\\`). Use secure path manipulation functions to resolve canonical paths and validate them against allowed base directories.
    - **Secure File Path Handling:** Utilize secure file path handling functions provided by the operating system or libraries to mitigate traversal vulnerabilities. Consider using functions that resolve paths securely and prevent traversal outside of designated directories.
    - **Principle of Least Privilege:** Ensure the application runs with the minimum necessary privileges to limit the impact of potential file system access vulnerabilities.

- **Preconditions:**
    - The attacker must be able to execute one of the Python scripts (`train_model.py`, `evaluate.py`, `predict_tags.py`, or `fine_tune.py`).
    - The attacker must be able to provide command-line arguments to these scripts, specifically the vulnerable arguments: `--train`, `--test`, `--dev`, `--model`, or `--out_dir`.

- **Source Code Analysis:**
    1. **Argument Parsing (`utils.py`, `parse_args`):** The `parse_args` function in `utils.py` defines command-line arguments `--train`, `--test`, `--dev`, `--model`, and `--out_dir` as strings using `argparse`. No input validation is applied to these arguments.
    ```python
    def parse_args():
        p = argparse.ArgumentParser(...)
        p.add_argument('--train', type=str, help='Path to the train data.', default=None)
        p.add_argument('--test', type=str, help='Path to the test data.', default=None)
        p.add_argument('--dev', type=str, help='Path to the dev data.', default=None)
        p.add_argument('--model', type=str, help='Model path.', default=None)
        p.add_argument('--out_dir', type=str, help='Output directory.', default='.')
        return p.parse_args()
    ```
    2. **Data Reader Initialization (`utils.py`, `get_reader`):** The `get_reader` function takes the `file_path` argument and passes it directly to the `CoNLLReader` constructor, which subsequently uses it in the `read_data` method without validation.
    ```python
    def get_reader(file_path, ...):
        if file_path is None:
            return None
        reader = CoNLLReader(...)
        reader.read_data(file_path)
        return reader
    ```
    3. **Vulnerable File Opening (`utils/reader_utils.py`, `get_ner_reader`):** The `get_ner_reader` function receives the `data` argument (file path) and directly opens the file using `gzip.open` or `open` based on file extension, without any path validation or sanitization, leading to path traversal.
    ```python
    def get_ner_reader(data):
        fin = gzip.open(data, 'rt') if data.endswith('.gz') else open(data, 'rt')
        # ... rest of the function ...
    ```
    4. **Model Loading (`utils.py`, `load_model`):** The `load_model` function uses `os.path.isfile` for a file existence check, which is insufficient for security. It then loads the model directly using `NERBaseAnnotator.load_from_checkpoint` with the user-provided `model_file` path, making it vulnerable to path traversal.
    ```python
    def load_model(model_file, ...):
        if ~os.path.isfile(model_file): # Insecure check
            model_file = get_models_for_evaluation(model_file)
        model = NERBaseAnnotator.load_from_checkpoint(model_file, ...) # Vulnerable file operation
        return model, model_file
    ```
    5. **Output Directory Handling (`utils.py`, `save_model`):** The `save_model` function uses the `out_dir` argument directly with `os.makedirs(out_dir, exist_ok=True)` to create output directories, allowing an attacker to specify arbitrary paths for directory creation and model saving.
    ```python
    def save_model(trainer, out_dir, ...):
        os.makedirs(out_dir, exist_ok=True) # Vulnerable directory creation
        outfile = out_dir + '/' + model_name + '_timestamp_' + str(timestamp) + '_final.ckpt'
        trainer.save_checkpoint(outfile, weights_only=True)
    ```
    *Visualization of Vulnerable Data Flow:*
    ```
    [command-line arguments] --> parse_args (utils.py) --> file_path (train/test/dev) --> get_reader (utils.py) --> CoNLLReader.read_data (utils/reader.py) --> get_ner_reader (utils/reader_utils.py) --> open/gzip.open (utils/reader_utils.py) --> [File Read]
    [command-line arguments] --> parse_args (utils.py) --> model_file (model) --> load_model (utils.py) --> NERBaseAnnotator.load_from_checkpoint --> [File Read]
    [command-line arguments] --> parse_args (utils.py) --> out_dir --> save_model (utils.py) --> os.makedirs/trainer.save_checkpoint --> [File Write/Directory Creation]
    ```

- **Security Test Case:**
    To demonstrate the Path Traversal vulnerability, the following steps can be performed:
    1. **Setup:** Assume an attacker has access to execute the `train_model.py` script on a deployed application instance.
    2. **Arbitrary File Read Test (using `--train` argument):**
        - Execute the `train_model.py` script with a maliciously crafted `--train` argument to attempt reading the `/etc/passwd` file (or `C:\Windows\win.ini` on Windows):
        ```bash
        python -m ner_baseline.train_model --train "../../../../../../../../../etc/passwd" --dev dev.txt --out_dir output_dir --model_name test_model
        ```
        - Observe the application logs and output. Even if the script fails to process `/etc/passwd` due to format issues, the attempt to open and read from this path confirms the vulnerability.
    3. **Arbitrary File Read Test (using `--model` argument):**
        - Create a dummy model file named `dummy_model.ckpt` in a location outside the expected model directories, for example, in the parent directory.
        - Execute the `evaluate.py` script with a malicious `--model` argument to attempt loading this dummy model via path traversal:
        ```bash
        python -m ner_baseline.evaluate --test test.txt --out_dir output_eval --encoder_model xlm-roberta-base --model '../../dummy_model.ckpt' --prefix test_eval
        ```
        - Verify if the application attempts to access and load from `../../dummy_model.ckpt`.
    4. **Arbitrary File Write Test (using `--out_dir` argument):**
        - Execute the `train_model.py` script with a malicious `--out_dir` argument to attempt writing model output to a sensitive directory like `/tmp/evil_dir`:
        ```bash
        python -m ner_baseline.train_model --train train.txt --dev dev.txt --out_dir /tmp/evil_dir --model_name test_write --epochs 1
        ```
        - Check if directories and model files are created under `/tmp/evil_dir`, confirming the ability to write to arbitrary locations.
    5. **Verification:** In all test cases, even if the application encounters errors due to file format or content, the successful attempt to access or write to the attacker-specified path outside of intended directories is sufficient evidence to confirm the Path Traversal vulnerability.