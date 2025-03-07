- Vulnerability Name: Path Manipulation/Traversal in SDK (CVE-2025-24888)
- Description: The SecureDrop SDK was vulnerable to path manipulation/traversal attacks when handling file paths. This vulnerability could potentially allow an attacker to access or write files outside of the intended directories if exploited through malicious file handling in the client.
- Impact: Code execution or information disclosure within the journalist's Qubes OS virtual machine if a source manages to inject malicious filenames in submissions that are processed by the SecureDrop Client using the vulnerable SDK code.
- Vulnerability Rank: High
- Currently Implemented Mitigations: This vulnerability has been addressed and fixed in version 0.14.1 of the `securedrop-client` project. The specific code fix would be located within the `securedrop-sdk` component, which is used by the `securedrop-client`. The changelog in `/code/changelog.md` mentions this fix.
- Missing Mitigations: No further mitigations are needed as the vulnerability is already patched in the mentioned version.
- Preconditions: The vulnerability could be triggered if a source is able to craft and submit filenames within submissions that contain path traversal characters, and these filenames are processed by the vulnerable SDK code in the SecureDrop Client.
- Source Code Analysis: Source code for the vulnerable code and the fix is not available in the provided PROJECT FILES. Further analysis in the `securedrop-sdk` codebase would be needed to pinpoint the exact location and nature of the vulnerability.
- Security Test Case:
  1. Set up a SecureDrop development environment with a version of `securedrop-client` prior to version 0.14.1 (if possible) or simulate the vulnerable code behavior.
  2. As a source, create a submission containing a file with a malicious filename designed to exploit path traversal (e.g., "../../malicious_file").
  3. Submit the malicious file to the SecureDrop server.
  4. As a journalist, use the vulnerable SecureDrop Client version to download and process the submission containing the malicious file.
  5. Observe if the client attempts to access or write files outside of the intended directories based on the crafted filename (e.g., by checking logs or file system access).
  6. In a mitigated version (0.14.1 or later), repeat steps 1-5 and verify that the path traversal is prevented, and the malicious filename is handled safely without accessing unintended locations.