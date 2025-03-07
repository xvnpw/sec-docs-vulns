- Vulnerability name: Path Traversal via Observer Name
- Description:
  1. The `certaintimes.py` script accepts an optional observer name using the `-o` or `--observer` command-line argument.
  2. This observer name is intended to be used as part of the log file name and as a prefix in each log entry.
  3. The script constructs the log file name by directly embedding the provided observer name into the filename string using string formatting: `logfile = "certaintimes-{}.log".format(args.observer)`.
  4. There is no input validation or sanitization performed on the observer name before using it in the file path.
  5. An attacker can provide a malicious observer name containing path traversal characters such as `../` to manipulate the log file's destination path.
  6. For example, executing the command `certaintimes -o "../../../tmp/evil"` would lead to the creation of a log file named `certaintimes-../../../tmp/evil.log`. Due to path traversal, this file will be created in the `/tmp` directory as `evil.log` instead of the intended directory relative to the script's execution.
  7. This allows an attacker to write log files to arbitrary locations on the file system, potentially overwriting existing files or writing to sensitive directories if the script is run with sufficient permissions.
- Impact:
  - Arbitrary File Write: An attacker can write files to any location on the file system where the user running the `certaintimes` script has write permissions.
  - Overwrite Sensitive Files: If the script is run with elevated privileges (e.g., by root or a privileged user), an attacker could potentially overwrite critical system files, leading to system instability or compromise.
  - Information Disclosure: An attacker could write log files containing sensitive information to publicly accessible directories, leading to information disclosure.
  - Potential for Further Exploitation: Arbitrary file write vulnerabilities can sometimes be chained with other vulnerabilities to achieve code execution or privilege escalation.
- Vulnerability rank: High
- Currently implemented mitigations:
  - None. The code directly uses the user-provided observer name without any sanitization or validation.
- Missing mitigations:
  - Input Sanitization: The observer name provided by the user should be sanitized to remove or escape any path traversal characters (e.g., `../`, `..\\`).
  - Input Validation: The observer name should be validated to ensure it conforms to an expected format, such as allowing only alphanumeric characters, underscores, and hyphens. A regular expression can be used for this validation.
  - Path Normalization: After constructing the file path, it should be normalized to remove any redundant or directory traversal components. However, sanitization and validation are preferred to prevent malicious path construction in the first place.
- Preconditions:
  - The attacker must have the ability to execute the `certaintimes` script.
  - The attacker must be able to provide command-line arguments to the script, specifically the `-o` or `--observer` option.
- Source code analysis:
  - File: `/code/certaintimes/scripts/certaintimes.py`
  - Function: `main()`
  - Line:
    ```python
    if args.observer:
        prefix = "{}: ".format(args.observer)
        logfile = "certaintimes-{}.log".format(args.observer)
    else:
        prefix = ""
        logfile = "certaintimes.log"
    ```
  - Analysis:
    1. The code retrieves the observer name from the parsed command-line arguments (`args.observer`).
    2. It then constructs the `logfile` string by directly embedding the `args.observer` value using an f-string.
    3. There is no sanitization or validation of the `args.observer` value before it is used to construct the file path.
    4. This allows an attacker to inject path traversal characters into `args.observer` and manipulate the resulting `logfile` path.

- Security test case:
  1. Save the `certaintimes.py` script to a file named `certaintimes.py`.
  2. Open a terminal and navigate to the directory where you saved the file.
  3. Run the script with a malicious observer name to trigger the path traversal vulnerability:
     ```bash
     python certaintimes.py -o "../../../tmp/evil"
     ```
  4. Enter some text and press Enter, then type `q` and press Enter to quit the script and finalize the log file. For example:
     ```
     Enter text to append it as a UTC timed log entry to certaintimes-../../../tmp/evil.log, q or quit to exit.

     local time: 2024-01-15 10:00:00.000000
            UTC: 2024-01-15 09:00:00.000000+00:00

     IMPORTANT: WSL can get out of sync over sleep!
     If this time does not look close, please exit and fix e.g. with 'sudo hwclock -s'
     test log entry
     00:00:01 test log entry
     q
     ```
  5. Check if a file named `evil.log` has been created in the `/tmp` directory.
     ```bash
     ls -l /tmp/evil.log
     ```
  6. If the file `evil.log` exists in `/tmp` and contains the log entries, the path traversal vulnerability is confirmed.
  7. Expected output in `/tmp/evil.log`:
     ```log
     2024-01-15T09:00:01.234Z 00:00:00 ====== Starting session ======
     2024-01-15T09:00:02.234Z 00:00:01 test log entry
     2024-01-15T09:00:03.234Z 00:00:02 ====== Ending session ======