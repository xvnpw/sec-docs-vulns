### Vulnerability List

- Vulnerability Name: Malicious Dependency Installation via `install-deps.sh`
- Description:
    - A threat actor could create a forked repository and modify the `install-deps.sh` script to include malicious commands.
    - The attacker could then socially engineer a user into downloading and executing this compromised `install-deps.sh` script.
    - Since the script is intended to be run with root privileges (as documented), the malicious commands within the script will also be executed with root privileges.
    - This could involve installing backdoors, malware, or altering system configurations to compromise the EC2 instance.
- Impact:
    - Full compromise of the EC2 instance.
    - The attacker gains arbitrary command execution with root privileges, allowing them to steal credentials, access sensitive data, disrupt services, or use the instance for further malicious activities.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None. The project does not currently implement any specific mitigations against running a compromised `install-deps.sh` script.
- Missing Mitigations:
    - **Code Signing/Verification:** Implement code signing for the `install-deps.sh` script and provide a mechanism for users to verify the script's integrity before execution. This could involve using GPG signatures and providing public keys for verification.
    - **Checksums:** Provide checksums (e.g., SHA256) for the `install-deps.sh` script on the official project page or in a secure location. This allows users to manually verify the integrity of the downloaded script before execution.
    - **Warning in README and documentation:** Add a prominent warning in the README and any installation documentation, explicitly advising users to:
        - Only download scripts from the official repository.
        - Carefully review the contents of `install-deps.sh` before executing it, even from the official repository, especially if there have been recent updates.
        - Avoid running scripts from untrusted sources or forked repositories without thorough inspection.
- Preconditions:
    - The user must be socially engineered into downloading and executing a modified `install-deps.sh` script from a malicious source (e.g., a forked repository controlled by the attacker).
    - The user must execute the script with root privileges using `sudo bash install-deps.sh` or similar, as instructed in the documentation.
- Source Code Analysis:
    - The `install-deps.sh` script (File: `/code/install-deps.sh`) is designed to automate the installation of BCC (BPF Compiler Collection) and its dependencies on various Linux distributions.
    - The script starts with a check to ensure it is run with root privileges:
      ```bash
      if [ "$EUID" -ne 0 ]; then
          echo "[ERROR] Please run as root (sudo)" >&2
          exit 1
      fi
      ```
    - It then proceeds to install packages using package managers like `apt-get`, `yum`, `dnf`, and `zypper` based on the detected operating system. For example, on Ubuntu, it installs a range of development tools and libraries:
      ```bash
      apt install -y bison build-essential cmake flex git libedit-dev "libllvm${llvm_version}" ...
      ```
    - Critically, the script also clones the BCC repository from GitHub:
      ```bash
      git clone https://github.com/iovisor/bcc.git
      ```
      and then builds and installs BCC from source using `cmake`, `make`, and `make install`:
      ```bash
      cmake ..
      make && make install
      cmake -DPYTHON_CMD=python3 ..
      cd src/python
      make && make install
      ```
    - **Vulnerability Trigger:** A compromised `install-deps.sh` script could:
        1.  Replace the legitimate `git clone` command with a clone from a malicious repository containing backdoored BCC source code.
        2.  Modify the `cmake` or `make` commands or associated build files within the cloned repository to inject malicious code during the build process.
        3.  Add malicious commands directly within the `install-deps.sh` script itself, to be executed before, during, or after the dependency installations.
    - Because the script runs with root privileges, any malicious code injected through these methods will also execute with root privileges, leading to system compromise.
- Security Test Case:
    1.  **Setup Attacker Repository:**
        - Fork the official repository on a GitHub account controlled by the attacker.
        - Clone the forked repository to the attacker's local machine.
    2.  **Modify `install-deps.sh`:**
        - Edit the `install-deps.sh` script in the forked repository.
        - Insert malicious commands. For example, to create a backdoor user, add the following lines before the OS detection `case` statement:
          ```bash
          echo "[INFO] Adding backdoor user..."
          useradd -m -p 'backdoorpassword' backdooruser
          echo "backdooruser:backdoorpassword" | chpasswd
          ```
        - Commit and push the changes to the attacker's forked repository.
    3.  **Social Engineering (Simulated):**
        - Create a scenario to trick a test user into using the malicious script. For example, instruct the user to download the `install-deps.sh` script from the attacker's forked repository.
    4.  **Victim Execution:**
        - On a test EC2 instance, the victim user executes the modified `install-deps.sh` script as root:
          ```bash
          sudo bash install-deps.sh
          ```
    5.  **Verification of Exploit:**
        - After the script execution completes, attempt to log in to the EC2 instance using the backdoor user created in the modified script:
          ```bash
          ssh backdooruser@<EC2_INSTANCE_IP>
          ```
          using the password 'backdoorpassword'.
        - If login is successful, the vulnerability is confirmed. The backdoor user has been created with root privileges (due to useradd -m).
        - Additionally, check for other malicious effects depending on the payload injected in step 2.

- Vulnerability Name: Potential for Privilege Escalation via Service Modification (`activate-tracer-service.sh`)
- Description:
    - A threat actor could modify the `activate-tracer-service.sh` script in a forked repository to alter the systemd service definition it creates.
    - By tricking a user into running this modified script, the attacker can change the command executed by the `imds_tracer_tool.service`.
    - This could lead to arbitrary commands being executed with root privileges when the service is started, achieving privilege escalation.
- Impact:
    - Privilege escalation to root on the EC2 instance.
    - The attacker can gain persistent root access by modifying the service to execute malicious code on system startup.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The project does not implement any specific mitigations against running a compromised `activate-tracer-service.sh` script.
- Missing Mitigations:
    - **Code Signing/Verification:** Implement code signing for the `activate-tracer-service.sh` script and provide a verification mechanism.
    - **Checksums:** Provide checksums for `activate-tracer-service.sh` for manual verification.
    - **Warning in README and documentation:** Include a warning similar to that for `install-deps.sh`, advising users to scrutinize the script before execution and only use scripts from trusted sources.
- Preconditions:
    - The user must be socially engineered into downloading and executing a modified `activate-tracer-service.sh` script from a malicious source.
    - The user must execute the script with root privileges using `sudo bash activate-tracer-service.sh` or similar, as instructed in the documentation to activate the service.
- Source Code Analysis:
    - The `activate-tracer-service.sh` script (File: `/code/activate-tracer-service.sh`) is used to configure the `imds_snoop.py` tool to run as a systemd service.
    - It creates a service file at `/etc/systemd/system/imds_tracer_tool.service` with the following content (in the original script):
      ```bash
      cat << EOF > "$BPF_TRACE_SYSTEMD_PATH"
      [Unit]
      Description=ImdsPacketAnalyzer IMDS detection tooling from AWS
      Before=network-online.target

      [Service]
      Type=simple
      Restart=always
      WorkingDirectory=$BPF_TRACE_PATH
      ExecStart=$(command -v python3) $BPF_TRACE_PATH/src/imds_snoop.py

      [Install]
      WantedBy=multi-user.target
      EOF
      ```
    - The critical part is the `ExecStart` line, which defines the command executed when the service starts:
      ```
      ExecStart=$(command -v python3) $BPF_TRACE_PATH/src/imds_snoop.py
      ```
    - **Vulnerability Trigger:** A compromised `activate-tracer-service.sh` script could modify the `ExecStart` line to execute any arbitrary command instead of the intended `imds_snoop.py` script. For example, it could be changed to:
      ```
      ExecStart=/bin/bash -c "touch /tmp/pwned && /path/to/malicious/script.sh"
      ```
    - When the user runs the modified `activate-tracer-service.sh` and then starts or reboots the system, the systemd service will execute the attacker's specified command with root privileges, leading to privilege escalation.
- Security Test Case:
    1.  **Setup Attacker Repository:**
        - Fork the official repository on a GitHub account controlled by the attacker.
        - Clone the forked repository to the attacker's local machine.
    2.  **Modify `activate-tracer-service.sh`:**
        - Edit the `activate-tracer-service.sh` script in the forked repository.
        - Modify the `create_service_file()` function to change the `ExecStart` line in the created service file. For example, replace the original `ExecStart` line with:
          ```bash
          ExecStart=/bin/bash -c "touch /tmp/pwned_by_service"
          ```
        - Commit and push the changes to the attacker's forked repository.
    3.  **Social Engineering (Simulated):**
        - Create a scenario to trick a test user into using the malicious script. For example, instruct the user to download the `activate-tracer-service.sh` script from the attacker's forked repository.
    4.  **Victim Execution:**
        - On a test EC2 instance, the victim user executes the modified `activate-tracer-service.sh` script as root:
          ```bash
          sudo bash activate-tracer-service.sh
          ```
        - Then, start the service:
          ```bash
          sudo systemctl start imds_tracer_tool.service
          ```
    5.  **Verification of Exploit:**
        - Check if the file `/tmp/pwned_by_service` exists on the EC2 instance:
          ```bash
          ls /tmp/pwned_by_service
          ```
        - If the file exists, it confirms that the modified `ExecStart` command in the service file was executed with root privileges when the service started. This demonstrates successful privilege escalation.