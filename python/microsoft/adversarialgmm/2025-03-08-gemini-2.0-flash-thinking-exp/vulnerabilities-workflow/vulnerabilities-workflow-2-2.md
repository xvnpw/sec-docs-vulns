### Vulnerability List

- **Vulnerability Name:** Command Injection via Configuration File Name

- **Description:**
    A command injection vulnerability exists in the `local_script.sh`, `local_script_linux.sh`, and `local_script_osx.sh` scripts. This vulnerability can be triggered when a user executes one of these scripts with a maliciously crafted configuration file name as an argument. The scripts use the provided configuration file name in a `cp` command without proper sanitization. Specifically, the scripts execute the following steps:
    1. The script takes a configuration file name as the first argument, storing it in the `CONFIG` variable.
    2. It creates a temporary directory named `temp`.
    3. It attempts to copy the configuration file using the command `cp ${CONFIG}.py ${tmpdir}/${tmpfile}.py`. Due to the lack of sanitization of the `CONFIG` variable, if a malicious user provides a configuration file name containing shell command substitution (e.g., using backticks `` ` `` or `$(...)`), these commands will be executed during the shell's expansion of the `${CONFIG}` variable in the `cp` command.
    4. The rest of the script execution will proceed with the potentially modified temporary file.

- **Impact:**
    Successful exploitation of this vulnerability allows an attacker to execute arbitrary shell commands on the user's system with the privileges of the user running the script. This can lead to a complete compromise of the user's system, including data theft, malware installation, or denial of service.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    No mitigations are currently implemented in the project to prevent this vulnerability. The scripts directly use the user-supplied configuration file name in a shell command without any sanitization or validation.

- **Missing Mitigations:**
    The project lacks input sanitization and validation for the configuration file name argument passed to the shell scripts. To mitigate this vulnerability, the following mitigations should be implemented:
    - **Input Sanitization:** Sanitize the configuration file name to remove or escape any characters that could be interpreted as shell metacharacters. A safer approach would be to disallow special characters entirely and only allow alphanumeric characters, underscores, and hyphens.
    - **Secure File Handling:** Avoid using shell commands like `cp` to handle file operations where user-controlled input is involved. Use Python's built-in file handling functionalities instead, which do not involve shell expansion.
    - **Input Validation:** Validate that the configuration file name conforms to expected patterns before using it in any shell commands.

- **Preconditions:**
    To trigger this vulnerability, the following preconditions must be met:
    - The user must have the project installed and be able to execute the `local_script.sh`, `local_script_linux.sh`, or `local_script_osx.sh` scripts.
    - The user must be tricked into executing one of these scripts with a maliciously crafted configuration file name as a command-line argument.

- **Source Code Analysis:**
    1. **File:** `/code/montecarlo/local_script.sh` (and `/code/montecarlo/local_script_linux.sh`, `/code/montecarlo/local_script_osx.sh`)
    2. **Vulnerable Line:** `cp ${CONFIG}.py ${tmpdir}/${tmpfile}.py`
    3. **Analysis:**
        - The script takes the first command-line argument and assigns it to the variable `CONFIG`.
        - This `CONFIG` variable is then used directly within the `cp` command without any sanitization.
        - When the shell expands `${CONFIG}.py`, if `CONFIG` contains shell command substitution syntax like `$(command)` or backticks `` `command` ``, the shell will execute the embedded command.
        - For example, if a user executes: `local_script.sh "config_$(touch /tmp/pwned)"`, the shell will interpret `$(touch /tmp/pwned)` as a command to be executed, resulting in the creation of an empty file named `/tmp/pwned` before the `cp` command is executed.

- **Security Test Case:**
    1. **Step 1:** Open a terminal and navigate to the `/code/montecarlo` directory of the project.
    2. **Step 2:** Execute the `local_script.sh` script with a malicious configuration file name designed to inject a command. For example:
    ```bash
    ./local_script.sh "config_$(touch /tmp/mliv_pwned)"
    ```
    3. **Step 3:** After executing the command, check if the file `/tmp/mliv_pwned` has been created. You can use the following command to check:
    ```bash
    ls /tmp/mliv_pwned
    ```
    If the file `/tmp/mliv_pwned` exists, it confirms that the command injection vulnerability is present, and arbitrary commands can be executed via the configuration file name argument.