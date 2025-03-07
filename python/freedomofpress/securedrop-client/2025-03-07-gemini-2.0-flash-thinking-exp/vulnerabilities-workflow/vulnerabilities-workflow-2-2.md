- Vulnerability Name: Path Traversal in File Handling

- Description:
  1. A malicious source submits a crafted submission file containing a filename designed to exploit path traversal vulnerabilities.
  2. The journalist, using the SecureDrop Client, downloads and attempts to open or export this submission file.
  3. Due to insufficient sanitization of filenames during file processing (download, open, export), the application attempts to access or write files outside of the intended directory.
  4. This could allow an attacker to overwrite critical files, access sensitive information, or potentially achieve arbitrary code execution if exploited in conjunction with other vulnerabilities.

- Impact:
  -  File Overwrite: An attacker could overwrite critical system or application files within the Qubes OS disposable VM, potentially leading to system instability or malicious modification of the SecureDrop Client application.
  -  Information Disclosure: An attacker might be able to read files outside the intended submission directory, potentially accessing sensitive data within the disposable VM environment.
  -  Potential Code Execution: In a more severe scenario, if combined with other vulnerabilities, path traversal could be leveraged to achieve arbitrary code execution within the disposable VM.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
  - Based on changelog entries "Prevent path traversal in downloaded files (#1226)" and "Prevent path manipulation/traversal attacks in SDK (CVE-2025-24888)", mitigations have been implemented in the codebase to address path traversal vulnerabilities in file handling within the client and SDK. However, without source code, the exact nature and effectiveness of these mitigations cannot be fully assessed.
  - The project uses `safe_mkdir`, `safe_gzip_extract`, `safe_move`, `safe_copy`, `safe_copyfileobj`, `relative_filepath`, `check_path_traversal`, `check_all_permissions`, `check_dir_permissions` functions in `securedrop_client/utils.py` to handle file operations safely and mitigate path traversal.
  - Filenames from source submissions are sanitized using `sanitize_submissions_or_replies` and `VALID_FILENAME` regex in `securedrop_client/storage.py`.

- Missing Mitigations:
  - Without source code analysis, it is difficult to determine specific missing mitigations. However, general missing mitigations for path traversal vulnerabilities could include:
    - Strict input validation and sanitization of filenames received from sources, ensuring filenames are normalized and only contain allowed characters.
    - Using secure file handling APIs that prevent path traversal, such as ensuring that file operations are performed relative to a safe base directory and not allowing absolute paths or relative paths that traverse above the base directory.
    - Implementing robust allowlisting or denylisting of file paths and extensions to restrict the types of files processed and their potential locations.
    - While `VALID_FILENAME` regex in `securedrop_client/storage.py` provides some sanitization, it may not be comprehensive enough to prevent all types of path traversal attacks. Further review of this regex and its usage is recommended.
    - Review and ensure consistent and correct usage of `check_path_traversal` and other safe file handling functions throughout the codebase, especially in file download, export, and open operations.

- Preconditions:
  - A malicious source is able to submit a crafted submission file to the SecureDrop server.
  - A journalist uses the SecureDrop Client to download and process the malicious submission file.

- Source Code Analysis:
  - Source code is not provided, so detailed analysis is not possible.
  - Based on the vulnerability description, the vulnerability likely arises in code paths that handle file operations related to submissions, such as:
    - File download and saving logic within the `client` component.
    - File export logic within the `export` component.
    - Potentially file opening/preview logic if it directly handles file paths.
  - Vulnerable code would likely involve using filenames provided in the submission data without proper validation to construct file paths for saving, opening, or exporting files.
  - For example, code might directly concatenate a base directory with a source-provided filename without checking if the filename contains path traversal sequences like `../` or absolute paths.
  - Visualization:
  ```
  [Untrusted Filename] --> [Vulnerable Code] --> [File System Operation]
  ```
  In vulnerable code, the untrusted filename is directly used in file system operations without validation, leading to path traversal.

- Security Test Case:
  1. **Setup:**
     - Set up a SecureDrop development environment or staging environment.
     - Create a test journalist account and log in to the SecureDrop Client.
     - Create a malicious submission file. The filename should contain path traversal characters, e.g., `"../../../.bashrc"`, `"evil.sh"`, or similar, and be encrypted as a source submission. The content of the file is not critical for this test, it can be a simple text file.
     - As a malicious source, submit this crafted file to the SecureDrop instance.
  2. **Execution:**
     - Log in to the SecureDrop Client as the test journalist.
     - Locate the new submission from the source.
     - Attempt to download and open or export the malicious submission file using the SecureDrop Client's GUI.
  3. **Expected Result:**
     - The SecureDrop Client should prevent the path traversal attempt.
     - The file operation (open or export) should either fail gracefully with an error message indicating an invalid filename or path, or the operation should be contained within the intended directory, and not traverse to other parts of the file system.
     - The test should **not** result in:
       - File overwrite outside the designated submission directory.
       - Information disclosure from outside the submission directory.
       - Code execution outside the intended disposable VM environment.
  4. **If Vulnerability Exists:**
     - If the test allows path traversal, e.g., by successfully creating a file in a location outside the intended submission directory or accessing a file outside the submission directory, then the vulnerability is confirmed.