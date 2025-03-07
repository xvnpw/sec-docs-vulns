- Vulnerability Name: Path Traversal in `output_dir` parameter
- Description:
    1. The `output_dir` parameter is used in the `BuddyInfoLogger`, `PsUtilLogger`, and `MemoryLogger` classes to specify the directory for saving log files.
    2. An attacker can control the `output_dir` parameter (assuming it's configurable via user input, configuration files, or command-line arguments in a real-world application using this library).
    3. By providing a malicious `output_dir` string containing path traversal sequences like `../`, the attacker can manipulate the file path where logs are written.
    4. When the logger attempts to create and write log files, it will use the attacker-controlled path, leading to file creation outside the intended directory.
    5. This can allow writing files to arbitrary locations on the file system accessible to the Python process.
- Impact:
    - Arbitrary File Write: An attacker can write files to any location on the file system where the Python process has write permissions.
    - Configuration Overwrite: Critical system or application configuration files could be overwritten, leading to application malfunction or compromise.
    - Sensitive Data Exposure: An attacker might be able to write files containing sensitive information to publicly accessible directories.
    - Potential for further exploitation: In some scenarios, arbitrary file write can be a stepping stone to remote code execution or privilege escalation, depending on the context and the system's configuration.
- Vulnerability rank: High
- Currently implemented mitigations:
    - None. The code directly uses the provided `output_dir` parameter without any validation or sanitization before constructing file paths.
- Missing mitigations:
    - Input validation: Sanitize the `output_dir` parameter to remove or neutralize path traversal characters (e.g., `../`, `./`).
    - Path restriction: Validate that the resolved output directory is within an expected base directory. Use absolute paths and canonicalization to prevent traversal.
    - Filesystem permissions: Ensure the process running the logger operates with minimal necessary privileges to limit the impact of arbitrary file write.
- Preconditions:
    - The attacker needs to control the `output_dir` parameter passed to the logger classes (`BuddyInfoLogger`, `PsUtilLogger`, or `MemoryLogger`).
    - The Python process running the logger must have write permissions to the directories targeted by the path traversal.
- Source code analysis:
    1. **File:** `/code/memutil/logger.py`
    2. **Classes:** `BuddyInfoLogger`, `PsUtilLogger` (and `MemoryLogger`) `__init__` methods.
    3. **Vulnerable code:**
        ```python
        # BuddyInfoLogger and PsUtilLogger classes in memutil/logger.py
        self._output_path = (pathlib.Path(output_dir) / output_basename).with_suffix(self._OUTPUT_SUFFIX or '.csv')
        ```
    4. **Explanation:**
        - The `pathlib.Path(output_dir)` directly creates a Path object from the `output_dir` string provided as input to the logger's constructor.
        - There is no validation or sanitization of the `output_dir` string before it is used to create the `Path` object.
        - If the `output_dir` string contains path traversal sequences like `../`, `pathlib.Path` will resolve the path accordingly, allowing the subsequent file operations to occur outside the intended directory.
    5. **Visualization:**
        Imagine `output_dir` is user-controlled input.
        ```
        User Input (output_dir) --> pathlib.Path(output_dir) --> _output_path --> File Write Operation
        ```
        If `output_dir` = `'../../../../tmp/evil'`, then `_output_path` will resolve to a path under `/tmp/evil`, regardless of the intended base directory.

- Security test case:
    1. **Setup:**
        - Assume you have the `memutil` library installed.
        - Create a Python script named `test_logger.py` with the following content:
        ```python
        import memutil.logger as memlogger
        import sys
        import os

        output_dir = sys.argv[1] if len(sys.argv) > 1 else "output"

        # Clean up potentially created directory from previous runs
        malicious_path = "/tmp/evil_path_traversal"
        if os.path.exists(malicious_path):
            os.rmdir(malicious_path)

        try:
            with memlogger.PsUtilLogger(output_dir=output_dir) as logger:
                logger.snapshot()
            print(f"Log file created at: {logger.output_path}")
        except Exception as e:
            print(f"Error: {e}")

        # Check if file was created in malicious path
        malicious_file_path = os.path.join(malicious_path, os.listdir(malicious_path)[0]) if os.path.exists(malicious_path) and os.listdir(malicious_path) else None
        if malicious_file_path:
            print(f"Vulnerability confirmed: Log file created in malicious path: {malicious_file_path}")
        else:
            print("Vulnerability not confirmed in malicious path.")

        ```
    2. **Execution:**
        - Open a terminal and navigate to the directory containing `test_logger.py`.
        - Execute the script with a path traversal payload as a command-line argument:
        ```bash
        python test_logger.py '../../../../tmp/evil_path_traversal'
        ```
    3. **Verification:**
        - Check the output of the script. It should indicate the created log file path.
        - Check if a log file (e.g., `psutil-log-YYYY-MM-DD-HH-MM-SS.csv`) was created in the `/tmp/evil_path_traversal` directory.
        - If the log file is found in `/tmp/evil_path_traversal`, the path traversal vulnerability is confirmed. The script should print "Vulnerability confirmed: Log file created in malicious path: ...". If the directory `/tmp/evil_path_traversal` does not exist before running the script, ensure that the user running the script has permissions to create directories in `/tmp`.