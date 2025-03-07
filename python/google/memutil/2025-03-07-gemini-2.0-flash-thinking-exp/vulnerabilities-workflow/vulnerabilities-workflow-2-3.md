- Vulnerability Name: Path Traversal in PsUtilLogger `output_dir`

- Description:
  - The `PsUtilLogger` class in `memutil/logger.py` is designed to log memory metrics to a CSV file within a specified directory.
  - The `output_dir` parameter of the `PsUtilLogger` constructor allows users to define the directory where log files will be stored.
  - If an application using `memutil` allows user-controlled input to specify the `output_dir` parameter without proper validation, an attacker can exploit a path traversal vulnerability.
  - By providing a malicious `output_dir` string containing path traversal sequences like `../`, an attacker can manipulate the file path.
  - This allows the attacker to write log files to locations outside the intended output directory, potentially overwriting sensitive files or writing to protected system directories, depending on the application's permissions.
  - For example, an attacker could set `output_dir` to `../../../../tmp` to write log files into the `/tmp` directory, regardless of the intended base output directory.

- Impact:
  - **File Overwrite:** An attacker could potentially overwrite existing files in arbitrary locations if the application process has sufficient write permissions. This could lead to data corruption or system instability if critical files are overwritten.
  - **Information Disclosure:** While less direct, if an attacker can write to a publicly accessible directory, it might indirectly aid in information gathering or further attacks.
  - **Privilege Escalation (Potentially):** In highly specific scenarios, if the application runs with elevated privileges and writes to system directories based on user-controlled paths, this could be a component in a privilege escalation attack. However, in the context of this library, direct privilege escalation is less likely. The primary risk is file overwrite and potential disruption or data corruption.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
  - None.
  - The code directly uses `pathlib.Path(output_dir)` to construct the output file path without any validation or sanitization of the `output_dir` input.

- Missing Mitigations:
  - **Input Validation and Sanitization:** The `output_dir` parameter should be strictly validated to prevent path traversal sequences. This could include:
    -  Validating that the provided path is a relative path or resolving it to an absolute path and ensuring it is within an allowed base directory.
    -  Sanitizing the input to remove or escape path traversal characters like `../` and `..\\`.
  - **Secure Path Manipulation:** Use secure path manipulation functions provided by `pathlib` to construct file paths safely, ensuring that the final path remains within the intended directory. For example, using `Path.resolve()` after joining paths to canonicalize and check the final path.

- Preconditions:
  - The application using the `memutil` library must allow user-controlled input to be passed as the `output_dir` parameter to the `PsUtilLogger` constructor.
  - The application process must have write permissions to the directories targeted by the path traversal attack.

- Source Code Analysis:
  - **File:** `/code/memutil/logger.py`
  - **Class:** `PsUtilLogger`
  - **Method:** `__init__(self, output_dir: str, label: Optional[str] = None)`
  - **Vulnerable Code Snippet:**
    ```python
    self._output_path = (pathlib.Path(output_dir) /
                             csv_basename).with_suffix('.csv')
    ```
  - **Step-by-step analysis:**
    1. The `PsUtilLogger` class constructor takes `output_dir` as an argument, which is a string representing the directory to store log files.
    2. `pathlib.Path(output_dir)` creates a `Path` object directly from the user-provided `output_dir` string. **Crucially, no validation or sanitization is performed on `output_dir` before creating the `Path` object.**
    3. `csv_basename` is constructed based on the prefix, label (optional), and a timestamp, ensuring a unique filename.
    4. `(pathlib.Path(output_dir) / csv_basename).with_suffix('.csv')` constructs the full output file path by joining the `Path` object created from `output_dir` with the `csv_basename` and appending the `.csv` suffix. The `/` operator in `pathlib` performs path joining.
    5. Because `pathlib.Path` directly interprets the input string, if `output_dir` contains path traversal sequences like `../`, these sequences will be honored and reflected in the final `_output_path`.
    6. When `logger_.snapshot()` is called and the context manager exits, the log file will be written to the path represented by `self._output_path`, which could be outside the intended directory due to path traversal.

- Security Test Case:
  - **Objective:** Verify that a path traversal vulnerability exists in `PsUtilLogger` via the `output_dir` parameter.
  - **Precondition:**  Need to be able to run Python code that uses the `memutil` library. Assume a test environment where we can create temporary directories and check file system locations.
  - **Steps:**
    1. Create a temporary base output directory, e.g., using Python's `tempfile.TemporaryDirectory`. Let's call this `base_dir`.
    2. Define a malicious `output_dir` string that includes path traversal sequences, for example: `malicious_output_dir = '../../evil_logs'`.
    3. Instantiate `PsUtilLogger` with this malicious `output_dir`, relative to the `base_dir`. For example: `logger_ = logger.PsUtilLogger(output_dir=pathlib.Path(base_dir) / malicious_output_dir)`.
    4. Call `logger_.snapshot()` to trigger log file creation.
    5. After the `with` block (or after manually exiting the logger context manager), check the file system to see where the log file was created.
    6. **Expected Result (Vulnerability Confirmation):** The log file should be created in a directory outside of `base_dir`. In this example, it should be created at a path like `<parent_directory_of_base_dir>/evil_logs/psutil-log-<timestamp>.csv`. This confirms successful path traversal.
    7. **Cleanup:** Remove the created log file and temporary directories.

  - **Python Test Code Example (Conceptual):**
    ```python
    import tempfile
    import pathlib
    from memutil import logger
    import os

    def test_path_traversal_psutil_logger():
        with tempfile.TemporaryDirectory() as base_dir:
            evil_dir = '../../evil_logs'
            malicious_output_dir = pathlib.Path(base_dir) / evil_dir
            test_logger = logger.PsUtilLogger(output_dir=str(malicious_output_dir)) # Convert Path to string for output_dir

            with test_logger:
                test_logger.snapshot()

            expected_evil_log_dir = pathlib.Path(base_dir).parent / 'evil_logs'
            output_file_path = expected_evil_log_dir / test_logger.output_path.name

            assert output_file_path.exists()
            assert base_dir not in str(output_file_path.absolute()) # Check file is outside base_dir

            # Cleanup (optional, tempfile should handle this, but good practice)
            if output_file_path.exists():
                os.remove(output_file_path)
            if expected_evil_log_dir.exists():
                os.rmdir(expected_evil_log_dir)

    test_path_traversal_psutil_logger()
    ```
    **Note:** This test code is conceptual and might need adjustments to run in a specific test environment. The core idea is to demonstrate that the log file is written outside the intended temporary directory using a path traversal payload in `output_dir`.