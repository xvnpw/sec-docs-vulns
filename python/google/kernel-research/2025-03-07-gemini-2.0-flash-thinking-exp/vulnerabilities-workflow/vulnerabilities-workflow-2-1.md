### Vulnerability List

- Vulnerability Name: Malicious Code Injection in Scripts and Tools
- Description:
    - A malicious actor can create a clone of this repository and inject arbitrary code into the shell and Python scripts.
    - A security researcher, believing they are using the legitimate tools, clones the malicious repository.
    - When the researcher executes any script (e.g., `run.sh`, `download_release.sh`, `kpwn_db.py`, etc.) from the malicious clone, the injected code will be executed on their host system.
    - This injected code can perform any action the researcher's user account has permissions for, potentially leading to full system compromise.
    - For example, a compromised `run.sh` script could download and execute a rootkit, steal credentials, or exfiltrate sensitive data from the researcher's machine.
- Impact:
    - Arbitrary code execution on the security researcher's system.
    - Potential for complete compromise of the researcher's system, including:
        - Data theft (research data, credentials, personal files).
        - Installation of malware (rootkits, spyware, ransomware).
        - Denial of service or disruption of the researcher's work.
        - Lateral movement to other systems if the researcher's system is part of a network.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None. The project does not include any technical mitigations to prevent the use of a malicious clone or to verify the integrity of the scripts.
    - The "Disclaimer" in the `README.md` file mentions that it is "not an officially supported Google product," but this is not a security mitigation.
- Missing Mitigations:
    - **Code Signing:** Implement code signing for all scripts (shell and Python). This would allow researchers to cryptographically verify that the scripts they are using are from a trusted source and have not been tampered with.
    - **Checksum Verification:** Provide checksums (e.g., SHA256 hashes) for all scripts and tools in a separate, trusted location (e.g., project website, official documentation). Researchers could then verify the integrity of their cloned repository by comparing the checksums of their local files against the trusted checksums.
    - **Repository Authenticity Verification Guide:** Include clear instructions in the `README.md` on how to verify the authenticity of the Git repository itself. This could involve:
        - Verifying Git commit signatures using GPG keys from trusted project maintainers.
        - Checking the repository's URL to ensure it matches the official project URL.
- Preconditions:
    - An attacker successfully social engineers a security researcher into cloning a malicious clone of this repository.
    - The researcher, unaware of the malicious nature of the clone, executes any of the scripts or tools within the cloned repository on their system.
- Source Code Analysis:
    - **Attack Vector:** All executable scripts within the repository are potential injection points. Both shell scripts (`.sh`) and Python scripts (`.py`) can be modified to execute arbitrary commands.
    - **Example - `run.sh` script:**
        - File: `/code/kernel-image-runner/run.sh`
        - Vulnerable Code Location: Beginning of the script.
        - Step-by-step analysis:
            1. An attacker modifies `run.sh` by inserting a malicious command at the very beginning of the script, before any legitimate code execution:
            ```bash
            #!/bin/bash
            # Injected malicious code:
            bash -c 'echo "You have been PWNED!" && mkdir /tmp/pwned_by_malicious_clone' &

            set -e

            SCRIPT_DIR=$(dirname $(realpath "$0"))
            ... (rest of the original script)
            ```
            2. When a researcher executes `./run.sh ubuntu <release-name>`, the Bash interpreter first executes the injected command `bash -c 'echo "You have been PWNED!" && mkdir /tmp/pwned_by_malicious_clone' &`.
            3. This injected command will:
                - Print "You have been PWNED!" to the console.
                - Create a directory named `/tmp/pwned_by_malicious_clone` on the researcher's system. The `&` at the end ensures this command runs in the background, so it does not block the execution of the rest of the script.
            4. After the injected code is executed, the script continues to execute the intended functionality of `run.sh`, potentially masking the malicious activity if the injected code is designed to be subtle.
    - **Example - `kpwn_db/kpwn_db.py` script:**
        - File: `/code/kpwn_db/kpwn_db.py`
        - Vulnerable Code Location: Beginning of the script.
        - Step-by-step analysis:
            1. An attacker modifies `kpwn_db.py` by inserting malicious Python code at the beginning:
            ```python
            #!/usr/bin/env python3
            # Injected malicious code:
            import os
            import subprocess
            subprocess.run(['mkdir', '/tmp/pwned_by_malicious_clone_python'])

            import argparse
            import glob
            import logging
            ... (rest of the original script)
            ```
            2. When a researcher executes `./kpwn_db/kpwn_db.py`, the Python interpreter first executes the injected code: `subprocess.run(['mkdir', '/tmp/pwned_by_malicious_clone_python'])`.
            3. This injected code will create a directory named `/tmp/pwned_by_malicious_clone_python` on the researcher's system.
            4. The script then proceeds to execute its intended functionality of building or converting the kpwn database.

- Security Test Case:
    1. **Setup:**
        - Create a controlled test environment (e.g., a virtual machine) to avoid harming the host system.
        - Create a malicious clone of the repository in the test environment.
        - Modify the `code/kernel-image-runner/run.sh` script in the malicious clone by adding the line `bash -c 'touch /tmp/vulnerable_test_file' &` at the beginning of the script.
    2. **Preconditions:**
        - Researcher (in the test environment) is assumed to have cloned the malicious repository.
        - Researcher is in the `code/kernel-image-runner/` directory of the malicious clone.
    3. **Steps to trigger vulnerability:**
        - Execute the command: `./run.sh ubuntu 5.4.0-26.30`
    4. **Expected outcome:**
        - The `run.sh` script executes.
        - The injected malicious code `bash -c 'touch /tmp/vulnerable_test_file' &` is executed on the researcher's test system in the background.
        - A file named `/tmp/vulnerable_test_file` is created on the researcher's test system, indicating successful arbitrary code execution.
        - The kernel runner might start and execute as intended afterwards, depending on the attacker's modifications.
    5. **Verification:**
        - Check for the existence of the `/tmp/vulnerable_test_file` file on the test system using the command `ls /tmp/vulnerable_test_file`.
        - If the file exists, the vulnerability is confirmed.

This test case demonstrates that a simple modification to a script can lead to arbitrary code execution upon execution by a researcher who is tricked into using a malicious clone.