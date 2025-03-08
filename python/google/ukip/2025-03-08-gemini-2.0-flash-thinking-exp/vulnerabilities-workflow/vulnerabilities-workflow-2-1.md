- Vulnerability Name: Command Injection in setup.sh via Environment Variables
- Description:
    1. An attacker can control the installation process by modifying environment variables before executing the `setup.sh` script. Specifically, variables `NEW_KEYSTROKE_WINDOW`, `NEW_ABNORMAL_TYPING`, `RUN_MODE`, `DEBIAN`, and `VENV_PATH` are read by the script.
    2. The `setup.sh` script utilizes the `sed -i` command to modify the `src/ukip.py` file, injecting the values of these environment variables directly into the `sed` command string without proper sanitization.
    3. By injecting malicious code into these environment variables, an attacker can manipulate the `sed` command to execute arbitrary shell commands.
    4. When `setup.sh` is run, the injected commands will be executed with the same privileges as the user running the script, which is likely root during the installation process, leading to privilege escalation.
- Impact:
    - Successful exploitation allows an attacker to execute arbitrary commands on the system with root privileges if `setup.sh` is run as root, which is common for installation scripts.
    - This can lead to complete system compromise, including but not limited to: unauthorized data access, modification, or deletion; installation of malware; creation of backdoors; and denial of service.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations: None
- Missing Mitigations:
    - Input sanitization: The `setup.sh` script should sanitize all environment variables before using them in shell commands, especially in `sed` commands. This can be achieved by using safer parameter expansion techniques in bash or by validating and escaping the input.
    - Avoid `sed` for configuration: Instead of using `sed` to modify configuration files or source code based on user-controlled input, consider using safer configuration methods such as dedicated configuration files that are parsed by the application itself, or using configuration management tools.
    - Principle of least privilege: If possible, the `setup.sh` script should be designed to run with minimal privileges. Operations requiring root privileges should be isolated and performed only when necessary, ideally using `sudo` for specific commands rather than running the entire script as root.
- Preconditions:
    - The attacker must have the ability to set environment variables on the system where `setup.sh` is to be executed. This is a standard capability in most operating environments.
    - The user must download and execute the `setup.sh` script, typically with root privileges to complete the installation of the daemon.
- Source Code Analysis:
    - The `setup.sh` script defines several variables at the beginning, such as `NEW_KEYSTROKE_WINDOW`, `NEW_ABNORMAL_TYPING`, `RUN_MODE`, and `DEBIAN`.
    - These variables are directly incorporated into `sed -i` commands to modify the `src/ukip.py` file. For example, the script uses:
        ```bash
        sed -i 's/ABNORMAL_TYPING = [^0-9]*\([0-9]\+\)/ABNORMAL_TYPING = '$NEW_ABNORMAL_TYPING'/g' src/ukip.py
        sed -i 's/KEYSTROKE_WINDOW = [^0-9]*\([0-9]\+\)/KEYSTROKE_WINDOW = '$NEW_KEYSTROKE_WINDOW'/g' src/ukip.py
        sed -i 's/_UKIP_RUN_MODE = UKIP_AVAILABLE_MODES\.\(MONITOR\|HARDENING\)/_UKIP_RUN_MODE = UKIP_AVAILABLE_MODES\.'$RUN_MODE'/g' src/ukip.py
        ```
    - In these commands, the variables `$NEW_ABNORMAL_TYPING`, `$NEW_KEYSTROKE_WINDOW`, and `$RUN_MODE` are directly inserted into the `sed` command string. If an attacker sets, for example, `RUN_MODE='MONITOR'; touch /tmp/pwned`, the third `sed` command becomes:
        ```bash
        sed -i 's/_UKIP_RUN_MODE = UKIP_AVAILABLE_MODES\.\(MONITOR\|HARDENING\)/_UKIP_RUN_MODE = UKIP_AVAILABLE_MODES\.'MONITOR'; touch /tmp/pwned'/g' src/ukip.py
        ```
    - Due to the way `sed -i` and shell command execution work, this will first perform the intended substitution, and then execute `touch /tmp/pwned` as a separate command injection, because the injected part is outside of the `sed` substitution command and is interpreted by the shell after variable expansion.
- Security Test Case:
    1. Open a terminal on a Linux system where you have permissions to create files in `/tmp`.
    2. Set the `RUN_MODE` environment variable with a command injection payload:
        ```bash
        export RUN_MODE='MONITOR'\'; touch /tmp/pwned #'
        ```
        This payload attempts to set the `RUN_MODE` to `MONITOR` and injects a command `touch /tmp/pwned` after it, commenting out the rest of the intended `sed` command with `#`.
    3. Navigate to the directory where the `setup.sh` script is located within the cloned project repository.
    4. Make the `setup.sh` script executable:
        ```bash
        chmod +x setup.sh
        ```
    5. Execute the `setup.sh` script:
        ```bash
        ./setup.sh
        ```
    6. After the script has finished running, check if the file `/tmp/pwned` has been created:
        ```bash
        ls /tmp/pwned
        ```
    7. If the file `/tmp/pwned` exists, it confirms that the command injection was successful, and the vulnerability is valid.