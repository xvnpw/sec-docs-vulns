### Vulnerability List

- Vulnerability Name: Path Traversal in `output_dir`
- Description:
    1. An attacker can control the `output_dir` parameter when instantiating a logger class (`PsUtilLogger`, `BuddyInfoLogger`, or `MemoryLogger`). This parameter specifies the directory where log files will be written.
    2. The attacker provides a malicious string containing path traversal characters, such as `../../../../tmp/`, as the `output_dir`.
    3. When the logger object is created, the library uses `pathlib.Path(output_dir)` to construct the full path for the log file.
    4. `pathlib.Path` resolves relative path components like `..`, effectively allowing the attacker to navigate out of the intended logging directory.
    5. Subsequently, when the `snapshot()` method is called, the log file is written to the attacker-specified location outside the intended directory, for example, to `/tmp/` in the case of `'../../../../tmp/'`.
- Impact:
    - An attacker can write log files to arbitrary locations on the file system where the Python process has write permissions.
    - This can lead to:
        - **Information Disclosure:** If sensitive information is logged, it could be written to a world-readable location, making it accessible to unauthorized users.
        - **File Overwrite (Potentially):** While less likely to cause direct system compromise in this specific scenario, an attacker might be able to overwrite existing files if they know the exact path and filename, potentially leading to disruption of services or misconfiguration.
        - **Planting Files for Further Exploitation:** An attacker could write files to specific locations to facilitate subsequent attacks, such as writing configuration files in unexpected locations if the application later reads from those locations.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations:
    - The library uses `pathlib.Path` to handle file paths, which is a better practice than string concatenation and offers some basic protection against naive path traversal attempts. However, `pathlib.Path` itself resolves path traversal sequences and does not prevent path traversal vulnerabilities if the input is not sanitized before being passed to `pathlib.Path`.
- Missing Mitigations:
    - **Input Sanitization:** The library lacks input sanitization or validation for the `output_dir` parameter. It should validate that the provided path is within an expected or allowed directory.
    - **Path Restriction:** The library should enforce that the `output_dir` is a subdirectory of a predefined base directory. This could be achieved by:
        - Resolving both the intended base directory and the user-provided `output_dir` to absolute paths.
        - Checking if the user-provided path is a subdirectory of the allowed base directory.
        - Rejecting or sanitizing the path if it is outside the allowed base directory.
- Preconditions:
    - The application using the `memutil` library must allow user-controlled input to be passed directly or indirectly as the `output_dir` parameter when instantiating a logger class.
- Source Code Analysis:
    - **File: `/code/memutil/logger.py`**
    - **Classes: `BuddyInfoLogger`, `PsUtilLogger`, `MemoryLogger`**
    - In the `__init__` method of `BuddyInfoLogger` and `PsUtilLogger`, the `output_dir` parameter is directly used to construct the output file path using `pathlib.Path`:
        - **`BuddyInfoLogger.__init__`:**
          ```python
          self._output_path = (pathlib.Path(output_dir) /
                               output_basename).with_suffix(self._OUTPUT_SUFFIX)
          ```
        - **`PsUtilLogger.__init__`:**
          ```python
          self._output_path = (pathlib.Path(output_dir) /
                               csv_basename).with_suffix('.csv')
          ```
    - `MemoryLogger` initializes instances of `BuddyInfoLogger` and `PsUtilLogger`, passing the provided `output_dir` without any modification or sanitization.
    - `pathlib.Path` is designed to handle and resolve path components, including `..`. When a path like `'../../../../tmp/'` is passed to `pathlib.Path`, it will resolve to a path outside the current directory structure, based on where the Python script is executed.
    - There is no code in `logger.py` that validates or sanitizes the `output_dir` input to prevent path traversal. The library trusts the input `output_dir` without any security checks.

- Security Test Case:
    1. **Setup:** Ensure you have the `memutil` library installed. Create a Python script, for example, `test_path_traversal.py`, with the following content:
        ```python
        from memutil import logger
        import os

        malicious_output_dir = '../../../../tmp/'
        log_label = 'path-traversal-test'

        # Using PsUtilLogger as an example, but the same applies to BuddyInfoLogger and MemoryLogger
        try:
            ps_logger = logger.PsUtilLogger(output_dir=malicious_output_dir, label=log_label)
            with ps_logger:
                ps_logger.snapshot()
            output_file_path = ps_logger.output_path
            print(f"Log file should have been written to: {output_file_path}")

            # Check if the log file is created in the malicious directory (/tmp)
            expected_log_file_in_tmp = os.path.join('/tmp', f'psutil-log-{log_label}-' ) # Timestring will be added
            found_in_tmp = False
            for filename in os.listdir('/tmp'):
                if filename.startswith(f'psutil-log-{log_label}-') and filename.endswith('.csv'):
                    found_in_tmp = True
                    break

            if found_in_tmp:
                print(f"Vulnerability confirmed: Log file created in /tmp")
            else:
                print(f"Vulnerability test failed: Log file not found in /tmp")


        except Exception as e:
            print(f"Error during test: {e}")

        ```
    2. **Execution:** Run the Python script from the command line: `python test_path_traversal.py`
    3. **Verification:**
        - The script will print the intended output path based on the malicious `output_dir`.
        - Check the `/tmp/` directory. A CSV log file starting with `psutil-log-path-traversal-test-` and ending with `.csv` should be present in `/tmp/`.
        - The script should also print "Vulnerability confirmed: Log file created in /tmp" if the log file is found in `/tmp`.

    4. **Expected Result:** The log file is successfully created in the `/tmp/` directory, demonstrating that the path traversal vulnerability exists because the user-controlled `output_dir` was not properly sanitized, allowing file creation outside the intended logging directory.