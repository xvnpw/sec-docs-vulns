### Vulnerability Name: Command Injection via Hostname/IP Address in Target Argument

-   **Description:**
    1. The `mssh` script takes user input for the target hostname or IP address without proper sanitization.
    2. This target argument is passed through the `input_parser.py` and `EC2InstanceConnectCommand.py` to construct the final SSH command.
    3. The `EC2InstanceConnectCLI.py` then executes this command using `subprocess.Popen` with `shell=True`.
    4. By providing a malicious hostname or IP address containing shell metacharacters, an attacker can inject arbitrary commands into the executed shell command.
    5. For example, a user can provide a target like ``; touch /tmp/pwned;`` which will be interpreted by the shell, executing the `touch /tmp/pwned` command in addition to the intended SSH command.
-   **Impact:**
    - High: Successful command injection allows an attacker to execute arbitrary commands on the system running the `mssh` script with the privileges of the user running the script. This can lead to full system compromise, data exfiltration, or denial of service.
-   **Vulnerability Rank:** High
-   **Currently Implemented Mitigations:**
    - None: The code does not implement any input sanitization or validation for the target hostname or IP address to prevent command injection.
-   **Missing Mitigations:**
    - Input Sanitization: Implement sanitization of the target hostname/IP address to remove or escape shell metacharacters before passing it to `subprocess.Popen`. Consider using a safe function for shell command construction, such as `shlex.quote` or avoid `shell=True` and pass commands as list to `subprocess.Popen`.
    - Input Validation: Validate the target hostname/IP address against a strict whitelist or regular expression to ensure it conforms to expected formats and does not contain malicious characters.
-   **Preconditions:**
    - The attacker must be able to execute the `mssh` script.
    - The attacker must be able to provide arguments to the `mssh` script, specifically the target hostname or IP address.
-   **Source Code Analysis:**
    1. `bin/mssh`: This script is the entry point. It calls `ec2instanceconnectcli.mops.main('ssh', 'ssh')`.
    2. `ec2instanceconnectcli/mops.py`: The `main` function parses arguments using `argparse` and `input_parser.parseargs(args, mode)`. The target is extracted in `input_parser.py`.
    3. `ec2instanceconnectcli/input_parser.py`:
        - `parseargs(args, mode)` function processes command line arguments.
        - `_parse_command_flags(custom_flags, instance_bundles, is_ssh=(mode=='ssh'))` parses flags and target from raw command.
        - `_parse_instance_bundles(instance_bundles)` further processes the target, but does not sanitize it. It only validates format like IP address or DNS name using regex and socket functions, not for shell injection.
    4. `ec2instanceconnectcli/EC2InstanceConnectCommand.py`:
        - `EC2InstanceConnectCommand` class takes the program, instance bundles, key file, flags, and program command as input.
        - `get_command()` method constructs the final command string using string formatting:
          ```python
          command = '{0} -o "IdentitiesOnly=yes" -i {1}'.format(self.program, self.key_file)
          if len(self.flags) > 0:
              command = "{0} {1}".format(command, self.flags)
          command = "{0} {1}".format(command, self._get_target(self.instance_bundles[0]))
          if len(self.program_command) > 0:
              command = "{0} {1}".format(command, self.program_command)
          if len(self.instance_bundles) > 1:
              command = "{0} {1}".format(command, self._get_target(self.instance_bundles[1]))
          ```
        - `_get_target(instance_bundle)` method constructs the target string from `instance_bundle['username']` and `instance_bundle['host_info']`:
          ```python
          target = "{0}@{1}".format(instance_bundle['username'], instance_bundle['host_info'])
          ```
        - `instance_bundle['host_info']` comes directly from user input (`target` in `input_parser.py`) or `ec2_util.get_instance_data()`. If target is provided by user it is not sanitized.
    5. `ec2instanceconnectcli/EC2InstanceConnectCLI.py`:
        - `EC2InstanceConnectCLI` class takes instance bundles, public key, CLI command, and logger as input.
        - `invoke_command()` calls `self.run_command(self.cli_command.get_command())`.
        - `run_command(self, command=None)` executes the command using `subprocess.Popen(command, shell=True)`. **Here, `shell=True` is used, which makes the system vulnerable to command injection.** The `command` variable is constructed from user-controlled `target` argument without sanitization.
-   **Security Test Case:**
    1. Setup: Ensure you have the `ec2instanceconnectcli` tool installed and configured to connect to AWS. You don't need a valid AWS instance for this test to demonstrate local command injection vulnerability.
    2. Execution: Run the `mssh` command with a malicious target hostname:
        ```bash
        ./bin/mssh ''; touch /tmp/pwned;'@localhost -u default
        ```
        or
        ```bash
        ./bin/mssh ``; touch /tmp/pwned;``@localhost -u default
        ```
        or
        ```bash
        ./bin/mssh "-o ProxyCommand=``touch /tmp/pwned``" dummy@localhost -u default
        ```
        Replace `localhost` with any valid hostname or IP if needed to bypass input validation (though validation is weak and might not prevent this). `-u default` assumes you have a default AWS profile configured, but it's not strictly necessary for local command injection demonstration as the vulnerability is in command construction and execution, not AWS interaction itself in this context.
    3. Verification: Check if the file `/tmp/pwned` has been created. If it exists, the command injection was successful.
        ```bash
        ls /tmp/pwned
        ```
        If the file `/tmp/pwned` exists, the vulnerability is confirmed.

### Vulnerability Name: Command Injection via Flags Argument

-   **Description:**
    1. Similar to the Hostname/IP vulnerability, the `mssh` script allows users to provide arbitrary flags.
    2. These flags are passed directly to the `EC2InstanceConnectCommand` and are incorporated into the final command string without sanitization.
    3. An attacker can inject malicious flags that contain shell metacharacters, leading to command injection when `subprocess.Popen` executes the command with `shell=True`.
    4. For example, a user might provide a flag like `-o ProxyCommand="; touch /tmp/pwned;"`, which, if not properly handled, can lead to execution of `touch /tmp/pwned`.
-   **Impact:**
    - High:  Same as above, arbitrary command execution on the system.
-   **Vulnerability Rank:** High
-   **Currently Implemented Mitigations:**
    - None: No sanitization or validation of flags is performed.
-   **Missing Mitigations:**
    - Input Sanitization: Sanitize the flags argument to escape or remove shell metacharacters.
    - Input Validation: While flags are intended for SSH, validating them against a known safe set or format could mitigate some injection attempts. However, sanitization is more crucial here.
-   **Preconditions:**
    - Same as above, attacker can execute `mssh` and provide flags.
-   **Source Code Analysis:**
    1. Follows the same path as the previous vulnerability analysis, up to `EC2InstanceConnectCommand.py`.
    2. In `EC2InstanceConnectCommand.py`, the `flags` argument is directly inserted into the command string in `get_command()`:
        ```python
        if len(self.flags) > 0:
            command = "{0} {1}".format(command, self.flags)
        ```
    3. The `flags` variable comes directly from user input via `input_parser.parseargs()` and is not sanitized before being used in the shell command executed by `subprocess.Popen` in `EC2InstanceConnectCLI.py`.
-   **Security Test Case:**
    1. Setup: Same as above.
    2. Execution: Run `mssh` with a malicious flag:
        ```bash
        ./bin/mssh -u default -f '-o ProxyCommand=touch /tmp/pwned' localhost
        ```
        or
        ```bash
        ./bin/mssh -u default -f '-o ProxyCommand="; touch /tmp/pwned;"' localhost
        ```
    3. Verification: Check if `/tmp/pwned` is created:
        ```bash
        ls /tmp/pwned
        ```
        If the file `/tmp/pwned` exists, command injection via flags is confirmed.

### Vulnerability Name: Command Injection via Program Command Argument

-   **Description:**
    1. The `mssh` script allows users to specify an arbitrary command to be executed on the remote instance after SSH connection.
    2. This `program_command` argument is passed to `EC2InstanceConnectCommand` and is appended to the SSH command string without sanitization.
    3. If the `program_command` contains shell metacharacters, it can lead to command injection when `subprocess.Popen` executes the command with `shell=True`.
    4. For example, providing a `program_command` like `; touch /tmp/pwned;` can result in local command execution.
-   **Impact:**
    - High: Arbitrary command execution on the system.
-   **Vulnerability Rank:** High
-   **Currently Implemented Mitigations:**
    - None: No sanitization or validation for the program command argument.
-   **Missing Mitigations:**
    - Input Sanitization: Sanitize the `program_command` argument to escape or remove shell metacharacters.
    - Input Validation: Validate the `program_command` against a whitelist of allowed commands or characters, although sanitization is more practical for general command arguments.
-   **Preconditions:**
    - Attacker can execute `mssh` and provide a program command argument.
-   **Source Code Analysis:**
    1. Follows the same path.
    2. In `EC2InstanceConnectCommand.py`, `program_command` is appended to the command string in `get_command()`:
        ```python
        if len(self.program_command) > 0:
            command = "{0} {1}".format(command, self.program_command)
        ```
    3. `program_command` originates from user input in `input_parser.parseargs()` and is not sanitized before execution via `subprocess.Popen` in `EC2InstanceConnectCLI.py`.
-   **Security Test Case:**
    1. Setup: Same as above.
    2. Execution: Run `mssh` with a malicious program command:
        ```bash
        ./bin/mssh -u default localhost '; touch /tmp/pwned;'
        ```
        or
        ```bash
        ./bin/mssh -u default localhost  `; touch /tmp/pwned;`
        ```
    3. Verification: Check for `/tmp/pwned`:
        ```bash
        ls /tmp/pwned
        ```
        If `/tmp/pwned` exists, command injection via program command is confirmed.