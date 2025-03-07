- Vulnerability Name: Path Traversal in SDK File Handling (CVE-2025-24888)
- Description: The SecureDrop Client SDK is vulnerable to path traversal attacks when handling filenames within submission archives. An attacker could craft a malicious submission archive containing filenames with directory traversal sequences (e.g., "../", "..\\") that, when extracted by the SecureDrop Client, could write files to arbitrary locations outside the intended export directory. This can lead to arbitrary file write and potentially code execution if an attacker overwrites critical system files or application configuration files.
- Impact: Critical
- Vulnerability Rank: Critical
- Currently Implemented Mitigations: Path traversal check in SDK (fixed in version 0.14.1). The changelog mentions "Prevent path manipulation/traversal attacks in SDK (CVE-2025-24888)" and "Refactor path-traversal check for improved readability" in export/changelog.md.
- Missing Mitigations: Further hardening of file extraction and handling logic to prevent similar vulnerabilities in the future. Consider using secure archive extraction libraries that prevent path traversal by design.
- Preconditions:
    - A journalist receives a malicious submission archive from a source.
    - The journalist attempts to download and process this submission archive using the SecureDrop Client.
- Source Code Analysis:
    - Unfortunately, the provided PROJECT FILES do not include the source code for `securedrop-sdk`. Therefore, I cannot perform a detailed source code analysis to pinpoint the vulnerable code section. However, based on the changelog and vulnerability description, the vulnerability likely resided in the file extraction logic within the SDK, specifically in how filenames from the archive were handled and processed during extraction. The fix likely involves sanitizing or validating filenames to remove or neutralize directory traversal sequences before file extraction occurs.
- Security Test Case:
    1. Create a malicious submission archive (e.g., tar.gz) containing a file with a path traversal filename, such as "../../evil.sh". This file should contain malicious code, for example, `#!/bin/bash\n touch /tmp/pwned`.
    2. As an attacker, submit this malicious archive through the SecureDrop source interface.
    3. As a journalist, log in to the SecureDrop Client and download the submission containing the malicious archive.
    4. Attempt to export or open the downloaded submission in a disposable VM.
    5. After the export/open operation, check if the file "/tmp/pwned" exists in the disposable VM.
    6. If the file "/tmp/pwned" exists, the vulnerability is present. If the vulnerability is mitigated, the file should not be created, and the export/open operation should ideally fail or handle the malicious filename safely.