### Vulnerability List

* Vulnerability Name: Path Traversal in Output Directory
* Description:
    1. An attacker can control the `output_dir` parameter when instantiating logger classes like `PsUtilLogger`, `BuddyInfoLogger`, or `MemoryLogger`.
    2. By providing a malicious `output_dir` string containing path traversal sequences such as `../`, the attacker can manipulate the file path where log files are written.
    3. For example, setting `output_dir` to `'../../../tmp'` will cause the log files to be written into the `/tmp` directory, regardless of the intended output location.
    4. This is because the code uses `pathlib.Path(output_dir) / output_basename` to construct the output file path without sanitizing or validating the `output_dir` input.
* Impact:
    * An attacker can write files to arbitrary locations on the file system where the Python process has write permissions.
    * This could lead to overwriting critical system files, creating malicious files in sensitive directories, or achieving code execution by writing scripts to locations like cron job directories or web server directories if the application runs with sufficient privileges.
* Vulnerability Rank: High
* Currently implemented mitigations:
    * None. The code uses `pathlib.Path` which normalizes paths, but does not prevent path traversal if malicious sequences are provided in the initial `output_dir` string.
* Missing mitigations:
    * Input validation and sanitization of the `output_dir` parameter.
    * Implement checks to ensure that the resolved output path remains within the intended directory or a set of allowed directories.
    * Consider using absolute paths for the intended output directory and validating that the user-provided path resolves to a subdirectory within the allowed base directory.
* Preconditions:
    * The attacker needs to be able to control the `output_dir` parameter passed to the logger classes (`PsUtilLogger`, `BuddyInfoLogger`, or `MemoryLogger`). This is typically the case if the `output_dir` is configurable by a user or read from an external, potentially untrusted source.
* Source code analysis:
    1. **File: /code/memutil/logger.py**
    2. **Classes: `BuddyInfoLogger` and `PsUtilLogger`**
    3. **`__init__` method:**
        ```python
        class BuddyInfoLogger(BaseLogger):
            # ...
            def __init__(self, output_dir: str, label: Optional[str] = None) -> None:
                # ...
                self._output_path = (pathlib.Path(output_dir) /
                                     output_basename).with_suffix(self._OUTPUT_SUFFIX)
                # ...

        class PsUtilLogger(BaseLogger):
            # ...
            def __init__(self, output_dir: str, label: Optional[str] = None):
                # ...
                self._output_path = (pathlib.Path(output_dir) /
                                     csv_basename).with_suffix('.csv')
                # ...
        ```
        4. In both `BuddyInfoLogger` and `PsUtilLogger`, the `output_dir` parameter, which is a string provided during object instantiation, is directly used to create a `pathlib.Path` object.
        5. This `pathlib.Path` object is then used to construct the full output file path by joining it with `output_basename` and adding a suffix.
        6. **Vulnerability:** If the `output_dir` string contains path traversal sequences like `../`, `pathlib.Path` will normalize the path, but it will still allow writing files outside the intended base directory. For example, if `output_dir` is set to `'../../../tmp'` and `output_basename` is `'test_log'`, the resulting path will be effectively `../../../tmp/test_log`.
    ```
    output_dir (user controlled input) --> pathlib.Path(output_dir) -->  pathlib.Path(output_dir) / output_basename --> self._output_path --> File creation
    ```
* Security test case:
    1. Create a temporary directory for testing, e.g., `/tmp/test_memutil`.
    2. Instantiate `PsUtilLogger` with a malicious `output_dir` parameter:
        ```python
        import tempfile
        from memutil import logger
        import os

        tmp_dir = tempfile.mkdtemp()
        malicious_output_dir = os.path.join(tmp_dir, '../../../tmp') # Attempt to write to /tmp
        log_label = 'path-traversal-test'
        test_logger = logger.PsUtilLogger(output_dir=malicious_output_dir, label=log_label)
        ```
    3. Enter the context manager and trigger a snapshot:
        ```python
        with test_logger:
            test_logger.snapshot()
        ```
    4. Check if the log file was created in the `/tmp` directory. The expected file path would be something like `/tmp/psutil-log-path-traversal-test-YYYY-MM-DD-HH-MM-SS.csv`.
    5. Verify that the file is created in `/tmp` and not within the intended temporary directory, confirming the path traversal vulnerability.