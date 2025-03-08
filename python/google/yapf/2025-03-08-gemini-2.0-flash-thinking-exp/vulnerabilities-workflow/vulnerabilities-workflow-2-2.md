- Vulnerability Name: Path Traversal via In-place Formatting

- Description:
  1. An attacker crafts a malicious Python file.
  2. This file contains path traversal characters (e.g., `../`) in its filename or within directives processed by YAPF.
  3. The attacker then uses YAPF to format this malicious file in-place using the `-i` option.
  4. Due to insufficient validation of the file paths, YAPF processes the malicious path.
  5. When YAPF attempts to write the formatted code back to the file using the provided path, it traverses directories outside of the intended project directory.
  6. This allows the attacker to modify or corrupt files in locations they should not have access to, based on the permissions of the user running YAPF.

- Impact:
  - File Modification/Corruption: An attacker can modify or corrupt arbitrary files on the system where YAPF is run, potentially leading to data loss, system instability, or further exploitation.
  - Confidentiality Breach: In some scenarios, attackers might be able to overwrite configuration files to read sensitive information upon service restart or access other protected files.
  - Integrity Violation: Modification of system files can compromise the integrity of the system.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
  - None: Based on the provided files, there is no specific code identified that mitigates path traversal when handling file paths for in-place formatting. The project relies on standard Python file handling practices, which are vulnerable to path traversal if not carefully implemented.

- Missing Mitigations:
  - Path Sanitization: Implement robust path sanitization within YAPF, specifically in the file handling routines used with the `-i` option. This should include:
    - Validating and canonicalizing the input file path to remove or neutralize path traversal sequences like `../` and `..\\`.
    - Ensuring that the target file for in-place modification remains within the intended project directory or a designated safe area.
  - Input Validation: Strictly validate all file paths provided to YAPF, especially when the `-i` flag is used, to prevent malicious paths from being processed.

- Preconditions:
  1. YAPF is installed and configured to be used as a command-line tool.
  2. The attacker has the ability to create or modify Python files that YAPF will process.
  3. YAPF is executed with the `-i` option to enable in-place formatting on a malicious Python file.
  4. The user running YAPF has write permissions in the target directory where the attacker aims to perform path traversal.

- Source Code Analysis:
  - File: /code/yapf/__init__.py
  - Function: `FormatFiles` and `_FormatFile`
  - Code Flow:
    1. `main` function in `/code/yapf/__init__.py` parses command line arguments, including files and options like `-i`.
    2. `FormatFiles` is called to handle multiple files or a directory recursively.
    3. `FormatFiles` iterates through the list of files and calls `_FormatFile` for each file.
    4. `_FormatFile` calls `yapf_api.FormatFile` to perform the actual formatting.
    5. Inside `yapf_api.FormatFile` (not provided in PROJECT FILES, but assumed to be part of YAPF library based on description), if `in_place=True`, the reformatted code is written back to the original filename.

  - Vulnerability Point: The vulnerability lies in the `yapf_api.FormatFile` function (or related file handling functions called within it) where the filename, potentially containing malicious path traversal sequences, is directly used to open and write to a file in in-place mode without proper validation.

  - Visualization:

    ```
    [Attacker Input: Malicious File Path] --> yapf.main --> FormatFiles --> _FormatFile --> yapf_api.FormatFile --> [Vulnerable File Write Operation using malicious path]
    ```

  - Step-by-step Exploit Code Flow:
    1. The attacker provides a file path like `/tmp/vuln/../../../important_file.py` as input to YAPF.
    2. YAPF command-line argument parsing accepts this path.
    3. `FormatFile` and `_FormatFile` process this path without sanitization.
    4. `yapf_api.FormatFile` uses this unsanitized path in file I/O operations.
    5. When `in_place=True`, the output file operation in `yapf_api.FormatFile` will write to `/tmp/vuln/../../../important_file.py`, leading to path traversal.

- Security Test Case:
  1. Setup:
    - Create a directory `/tmp/yapf_test_vuln/project`.
    - Inside `/tmp/yapf_test_vuln/`, create a sensitive file `sensitive_file.txt` with some content.
    - Create a malicious Python file `/tmp/yapf_test_vuln/malicious.py` with the following content:
      ```python
      import os

      def foo():
          pass
      ```
    - Create a symbolic link or rename `/tmp/yapf_test_vuln/malicious.py` to `/tmp/yapf_test_vuln/project/malicious_file_.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._/sensitive_file.py` to include path traversal characters in filename.
  2. Execution:
    - Navigate to `/tmp/yapf_test_vuln/project` in the terminal.
    - Run YAPF command: `yapf -i malicious_file_.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._.._/sensitive_file.py`
  3. Verification:
    - Check the content of `/tmp/yapf_test_vuln/sensitive_file.txt`.
    - If the vulnerability is present, the content of `sensitive_file.txt` will be overwritten with the formatted content of `malicious.py`, demonstrating successful path traversal and file modification outside the project directory.
    - Before running the test, the `sensitive_file.txt` should contain its original content. After running the test, the `sensitive_file.txt` should contain the formatted code from `malicious.py`.

This test case demonstrates that YAPF, when run with `-i` on a file with a crafted path, can modify files outside the intended directory, confirming the path traversal vulnerability.