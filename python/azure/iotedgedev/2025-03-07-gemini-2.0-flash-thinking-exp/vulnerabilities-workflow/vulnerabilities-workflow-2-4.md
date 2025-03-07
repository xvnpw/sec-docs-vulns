#### 2. Vulnerability Name: Potential Command Injection in `docker log` command via `LOGS_CMD`

- Description:
    1. The `iotedgedev docker log --show` command opens new terminal windows to display logs for EdgeAgent, EdgeHub, and modules.
    2. The command used to open these terminal windows is defined by the `LOGS_CMD` environment variable in the `.env` file.
    3. The default value of `LOGS_CMD` is `start /B start cmd.exe @cmd /k docker logs {0} -f` (for Cmd.exe) or a similar command for ConEmu or other terminals.
    4. The `{0}` placeholder in `LOGS_CMD` is replaced with the module name (e.g., edgeAgent, edgeHub, filtermodule) when the command is executed.
    5. If an attacker can control the `LOGS_CMD` environment variable or the module names, they might be able to inject arbitrary commands into the `os.system` call within the `iotedgedev docker log --show` functionality.
    6. For example, if a module name or `LOGS_CMD` is manipulated to include backticks or shell command separators, it could lead to command injection when `os.system(command.format(module_name))` is executed.

- Impact:
    - Local command execution on the developer's machine.
    - An attacker could execute arbitrary commands with the privileges of the user running `iotedgedev`.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None. The `LOGS_CMD` is directly used in `os.system` without sanitization of module names or the command itself.

- Missing Mitigations:
    - Sanitize or validate module names to ensure they do not contain shell- Metacharacters before using them in the `LOGS_CMD`.
    - Avoid using `os.system` with user-controlled or partially user-controlled strings. Use `subprocess.run` with proper argument lists to prevent shell injection.
    - Ideally, parameterize the command execution so that module names are passed as arguments rather than being interpolated into the command string.

- Preconditions:
    1. An attacker needs to be able to influence either the `LOGS_CMD` environment variable or the module names that are being processed by the `iotedgedev docker log --show` command.
    2. For `LOGS_CMD` environment variable, attacker would need to modify `.env` file or system environment variables if the tool respects system environment variables over `.env`. For module names, attacker would need to control the deployment configuration or module definitions.

- Source Code Analysis:
    1. **File: /code/iotedgedev/dockercls.py**
    2. Look for the function responsible for handling `docker log --show` command, which is `Docker.handle_logs_cmd`.
    3. Inside `handle_logs_cmd`, the code iterates through modules and constructs the command using `self.envvars.LOGS_CMD.format(module)`.
    4. **Line 270-274 in `/code/iotedgedev/dockercls.py`:**
    ```python
    if show:
        try:
            command = self.envvars.LOGS_CMD.format(module)
            os.system(command)
        except Exception as ex:
            self.output.error(
                "Error while trying to open module log '{0}' with command '{1}'. Try `iotedgedev docker log --save` instead.".format(module, command))
            self.output.error(str(ex))
    ```
    5. The code directly uses `os.system(command)` which is vulnerable to command injection if `command` variable is not properly sanitized.
    6. The `command` variable is constructed by formatting `self.envvars.LOGS_CMD` with `module`. `self.envvars.LOGS_CMD` comes from environment variables, potentially controlled by the user via `.env` or system environment. The `module` variable comes from `modules_in_config`, which is derived from the deployment manifest.
    7. **Attack vector 1: Malicious Module Name:** If a deployment manifest is crafted to include a module name containing malicious characters, this could lead to command injection. However, module names are validated during module creation (`Modules.add`), limiting this vector. Validation in `Modules.add` prevents names starting or ending with `_` and only allows alphanumeric characters and `_`. This vector is less likely but worth noting if validation is bypassed or changed in future.
    8. **Attack vector 2: Malicious `LOGS_CMD`:** A more direct attack vector is modifying the `LOGS_CMD` environment variable. If a developer is tricked into setting `LOGS_CMD` to a malicious command, running `iotedgedev docker log --show` would execute this malicious command. This is a user configuration risk, but the default configuration is also unsafe if module names are not sanitized.

- Security Test Case:
    1. **Modify `.env` file to set a malicious `LOGS_CMD`:**
    ```ini
    LOGS_CMD='touch /tmp/pwned_docker_log_cmd_{0}'
    ```
    2. Run the `docker log --show` command:
    ```sh
    iotedgedev docker log --show
    ```
    3. Check if the file `/tmp/pwned_docker_log_cmd_edgeAgent`, `/tmp/pwned_docker_log_cmd_edgeHub`, and `/tmp/pwned_docker_log_cmd_filtermodule` are created.
    4. If these files are created, it confirms command injection vulnerability via `LOGS_CMD`.