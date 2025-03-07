## Combined Vulnerability List

### Path Traversal in File Handling (CVE-2025-24888)

- **Vulnerability Name:** Path Traversal in File Handling (CVE-2025-24888)
- **Description:**
    - The SecureDrop Client SDK was found to be vulnerable to path traversal attacks when processing filenames within submission archives or handling file paths in general.
    - A malicious source could exploit this by crafting a submission file or archive containing a filename with directory traversal sequences (e.g., "../", "..\\").
    - When a journalist uses the SecureDrop Client to download, process, open, or export such a submission, the vulnerability in the SDK's file path handling logic is triggered.
    - Due to insufficient sanitization of filenames during file processing, the application may attempt to access or write files to locations outside of the intended directory. This occurs during file operations like download, export, or opening submissions.

- **Impact:**
    - **Critical**
    - **File Overwrite:** An attacker could overwrite critical system or application files within the Qubes OS disposable VM, potentially leading to system instability or malicious modification of the SecureDrop Client application.
    - **Information Disclosure:** An attacker might be able to read files outside the intended submission directory, potentially accessing sensitive data within the disposable VM environment. This could extend to accessing files in dom0 or other VMs in a Qubes OS environment, depending on the exploit's specifics.
    - **Potential Code Execution:** In a severe scenario, if combined with other vulnerabilities, path traversal could be leveraged to achieve arbitrary code execution within the disposable VM, especially if critical system or application configuration files are overwritten with malicious content.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - Mitigations have been implemented in the codebase to address path traversal vulnerabilities in file handling within the client and SDK.
    - The changelog for version 0.14.1 of `securedrop-client` mentions a security fix specifically for path manipulation/traversal attacks in the SDK (CVE-2025-24888).
    - The project utilizes several utility functions in `securedrop_client/utils.py` to handle file operations securely and mitigate path traversal. These include: `safe_mkdir`, `safe_gzip_extract`, `safe_move`, `safe_copy`, `safe_copyfileobj`, `relative_filepath`, `check_path_traversal`, `check_all_permissions`, and `check_dir_permissions`.
    - Filenames from source submissions are sanitized using `sanitize_submissions_or_replies` and validated against the `VALID_FILENAME` regular expression in `securedrop_client/storage.py`.

- **Missing Mitigations:**
    - While mitigations are implemented, continuous review and hardening of file extraction and handling logic are recommended to prevent similar vulnerabilities in the future.
    - It is important to ensure consistent and correct usage of `check_path_traversal` and other safe file handling functions throughout the codebase, especially in all file download, export, and open operations.
    - Further review of the `VALID_FILENAME` regex in `securedrop_client/storage.py` and its usage is recommended to ensure it comprehensively prevents all types of path traversal attacks.
    - Consider adopting secure archive extraction libraries that inherently prevent path traversal by design for handling submission archives.

- **Preconditions:**
    - The journalist must be logged into the SecureDrop Client.
    - An attacker must be able to submit a crafted file or archive to the SecureDrop instance that is processed by the SecureDrop Client.
    - The SecureDrop Client version must be vulnerable (prior to 0.14.1).
    - For archive-based exploits, the journalist must attempt to download and process a malicious submission archive.

- **Source Code Analysis:**
    - Detailed source code analysis of the `securedrop-sdk` is not possible with the provided project files.
    - Based on the vulnerability description and changelog, the vulnerability likely resided in the file extraction logic within the SDK, specifically in how filenames from archives were handled during extraction and in general file path handling within the SDK.
    - Vulnerable code would likely involve using filenames provided in the submission data without proper validation to construct file paths for saving, opening, or exporting files.
    - For example, vulnerable code might directly concatenate a base directory with a source-provided filename without checking for path traversal sequences like `../` or absolute paths.
    - The fix likely involves sanitizing or validating filenames to remove or neutralize directory traversal sequences before file extraction or file operations occur.
    - Visualization of vulnerable code flow:
    ```
    [Untrusted Filename] --> [Vulnerable SDK Code] --> [File System Operation]
    ```
    In vulnerable code, the untrusted filename from a submission is directly used in file system operations within the SDK without sufficient validation, leading to path traversal.

- **Security Test Case:**
    1. **Setup:**
        - Set up a SecureDrop testing environment with a vulnerable version of the SecureDrop Client (prior to 0.14.1) or simulate the vulnerable code behavior.
        - Create a test journalist account and log in to the SecureDrop Client.
        - Create a malicious submission. This could be either:
            - A single file submission with a malicious filename, e.g., `"../../../.bashrc"`, `"evil.sh"`.
            - A malicious submission archive (e.g., tar.gz) containing a file with a path traversal filename, such as "../../evil.sh". This file can contain simple content or malicious code like `#!/bin/bash\n touch /tmp/pwned`.
        - As a malicious source, submit this crafted file or archive to the SecureDrop instance.
    2. **Execution:**
        - Log in to the SecureDrop Client as the test journalist.
        - Locate the new submission from the source.
        - Attempt to download and open or export the malicious submission file or archive using the SecureDrop Client's GUI.
    3. **Expected Result (Vulnerable Version):**
        - The test should result in path traversal. For example:
            - If a malicious archive is used, after export/open operation, check if the file "/tmp/pwned" exists in the disposable VM if the archive contained a file designed to create it.
            - Observe if file operations result in accessing or writing files outside the intended submission directory.
    4. **Expected Result (Mitigated Version - 0.14.1 or later):**
        - The SecureDrop Client should prevent the path traversal attempt.
        - The file operation (open or export) should either fail gracefully with an error message indicating an invalid filename or path, or the operation should be contained within the intended directory.
        - The test should **not** result in:
            - File overwrite outside the designated submission directory.
            - Information disclosure from outside the submission directory.
            - Code execution outside the intended disposable VM environment.
    5. **Verification:**
        - Verify that in version 0.14.1 or later, this path traversal is prevented and the test case fails, demonstrating the effectiveness of the implemented mitigation.