### Vulnerability List

- Vulnerability Name: Command Injection in `run_command` via `cli_command`
- Description: The `run_command` function in `EC2InstanceConnectCLI.py` executes shell commands using `subprocess.Popen(command, shell=True)`. The `command` argument for this function is constructed in `EC2InstanceConnectCommand.py` based on user-provided inputs like `flags` and `program_command` which are parsed from command line arguments. If these inputs are not properly sanitized, an attacker can inject malicious shell commands. Specifically, by crafting a malicious `program_command` or `flags` argument, an attacker could execute arbitrary commands on the system running `mssh`.
- Impact: Arbitrary command execution on the machine running the `mssh` client. An attacker could potentially gain full control of the system, steal credentials, or use it as a stepping stone to further attacks.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations: None. The code directly uses `shell=True` in `subprocess.Popen` without any sanitization of the command string.
- Missing Mitigations:
    - Input sanitization: User-provided inputs like `flags` and `program_command` should be strictly validated and sanitized to prevent command injection. For example, using a whitelist of allowed characters or escaping shell metacharacters.
    - Avoid `shell=True`: The use of `shell=True` in `subprocess.Popen` should be avoided whenever possible, especially when dealing with user-provided input. Instead, commands should be executed as lists of arguments, which bypasses the shell and prevents most command injection vulnerabilities.
- Preconditions:
    - The attacker needs to be able to execute the `mssh`, `msftp`, `mssh-putty`, or `msftp-putty` scripts with crafted arguments. This is typically possible for any user who has access to the tool.
- Source Code Analysis:
    1. **`EC2InstanceConnectCLI.py` - `run_command` function:**
       ```python
       def run_command(self, command=None):
           ...
           invocation_proc = Popen(command, shell=True)
           ...
       ```
       This function directly executes the `command` string using `shell=True` in `Popen`, which is known to be vulnerable to command injection if the `command` string is not carefully constructed.

    2. **`EC2InstanceConnectCommand.py` - `get_command` function:**
       ```python
       def get_command(self):
           ...
           command = '{0} -o "IdentitiesOnly=yes" -i {1}'.format(self.program, self.key_file)
           ...
           if len(self.flags) > 0:
               command = "{0} {1}".format(command, self.flags)
           ...
           if len(self.program_command) > 0:
               command = "{0} {1}".format(command, self.program_command)
           ...
           return command
       ```
       This function constructs the command string by directly concatenating `self.flags` and `self.program_command`, which are derived from user inputs, into the final command. No sanitization or escaping is performed on these variables before including them in the command that is passed to `run_command`.

    3. **`mops.py` - `main` function:**
       ```python
       def main(program, mode):
           ...
           args = parser.parse_known_args()
           ...
           instance_bundles, flags, program_command = input_parser.parseargs(args, mode)
           ...
           cli_command = EC2InstanceConnectCommand(program, instance_bundles, cli_key.get_priv_key_file(), flags, program_command, logger.get_logger())
           ...
           cli = EC2InstanceConnectCLI(instance_bundles, cli_key.get_pub_key(), cli_command, logger.get_logger())
           return cli.invoke_command()
           ...
       ```
       The `main` function in `mops.py` (which is called by `mssh` and `msftp` scripts) receives command-line arguments, parses them using `input_parser.parseargs`, and then passes the `flags` and `program_command` directly to `EC2InstanceConnectCommand`.

    4. **`input_parser.py` - `parseargs` function:**
        The `input_parser.py` is responsible for parsing command line arguments. While it does some validation (e.g., for username, IP address, DNS name, region, zone), it does not perform any sanitization or escaping of the `flags` and `command` which are later used to construct the shell command. The `_parse_command_flags` function extracts flags and command but does not sanitize them.

       ```python
       def _parse_command_flags(raw_command, instance_bundles, is_ssh=False):
           ...
           while command_index < len(raw_command) - 1:
               if raw_command[command_index][0] != '-' and not is_flagged:
                   break
               used += 1
               flags = '{0} {1}'.format(flags, raw_command[command_index])
               ...
           flags = flags.strip()
           ...
           instance_bundles[0]['target'] = raw_command[command_index]
           command_index += 1
           command_end = len(raw_command)
           command = ' '.join(raw_command[command_index:command_end])
           return flags, command, instance_bundles
       ```
       As seen above, the flags and command are extracted and joined as strings without any sanitization.

- Security Test Case:
    1. Open a terminal.
    2. Navigate to the `bin` directory of the project.
    3. Execute the `mssh` script with a malicious `program_command` argument designed to inject a command. For example, to execute `touch /tmp/pwned`:
       ```bash
       ./mssh <instance-id> -- '; touch /tmp/pwned; '
       ```
       Replace `<instance-id>` with a valid EC2 instance ID (or any string as instance id is not validated in command construction part). The `--` is important to separate options from arguments to be passed to the ssh command. The malicious command `; touch /tmp/pwned; ` is injected as part of the ssh command.
    4. Check if the file `/tmp/pwned` has been created on the local system where `mssh` was executed. If the file exists, the command injection is successful.

    **Expected Result:** The file `/tmp/pwned` should be created, demonstrating that the injected command was executed. This confirms the command injection vulnerability.

This vulnerability allows for arbitrary command execution on the local machine running the `mssh` client, posing a significant security risk.