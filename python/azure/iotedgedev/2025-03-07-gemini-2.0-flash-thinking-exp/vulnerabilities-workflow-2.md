## Combined Vulnerability List

### 1. Command Injection Vulnerability in `docker log` command

- **Vulnerability Name:** Command Injection in `docker log` command via Module Name and `LOGS_CMD`

- **Description:**
    - Step 1: An attacker crafts a malicious module name containing shell commands or modifies the `LOGS_CMD` environment variable to include malicious commands.
    - Step 2: For Module Name Injection: The attacker creates or modifies a deployment manifest (e.g., `deployment.template.json`) to include this malicious module name. For example, a module could be named `backdoor; id > /tmp/pwnd.txt`.
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
    - Step 3: For `LOGS_CMD` Injection: The attacker modifies the `.env` file or system environment variables to set a malicious `LOGS_CMD`. For example:
    ```ini
    LOGS_CMD='touch /tmp/pwned_docker_log_cmd_{0}'
    ```
    - Step 4: The attacker executes the `iotedgedev docker log --show` or `iotedgedev docker log --save` command.
    - Step 5: The `iotedgedev docker log` command iterates through the modules listed in the deployment manifest.
    - Step 6: If exploiting Module Name: The malicious module name `backdoor; id > /tmp/pwnd.txt` is directly inserted into the `LOGS_CMD` environment variable's format string without proper sanitization.
    - Step 7: If exploiting `LOGS_CMD`: The predefined `LOGS_CMD` itself is malicious, e.g., `LOGS_CMD='touch /tmp/pwned_docker_log_cmd_{0}'`.
    - Step 8: The `os.system(command)` call in `handle_logs_cmd` function executes the crafted command, leading to command injection. In the Module Name injection example, this would execute `start /B start cmd.exe @cmd /k docker logs backdoor; id > /tmp/pwnd.txt -f` (or similar). In the `LOGS_CMD` injection example, it would execute `touch /tmp/pwned_docker_log_cmd_edgeAgent` and similar commands for other modules.

- **Impact:**
    - High. Successful command injection allows the attacker to execute arbitrary commands on the machine where `iotedgedev` tool is run. This can lead to full system compromise, data exfiltration, installation of malware, or further attacks on connected systems. In the context of IoT Edge development, this could compromise the developer's machine and potentially the development environment.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - None. The code directly formats the module name into a shell command and uses `os.system` without any sanitization or validation. The `LOGS_CMD` environment variable is also used directly without validation.

- **Missing Mitigations:**
    - Input Sanitization: Module names should be strictly validated to allow only alphanumeric characters and underscores, preventing the injection of shell metacharacters. Validate `LOGS_CMD` to ensure it does not contain dangerous commands or shell metacharacters if it must be user-configurable.
    - Secure Command Execution: Instead of using `os.system` which invokes a shell, use `subprocess.Popen` with a list of arguments, which avoids shell interpretation and command injection vulnerabilities. When using `subprocess.Popen`, ensure that user-provided data is passed as arguments and not embedded directly into the command string.
    - Parameterized Queries: If possible, avoid constructing commands from strings. Utilize libraries or APIs that support parameterized queries or commands to separate code from data.

- **Preconditions:**
    - For Module Name Injection: The attacker needs to be able to modify or create a deployment manifest file used by the `iotedgedev` tool. This could be achieved if the attacker has write access to the project directory or can influence the deployment manifest used by the developer.
    - For `LOGS_CMD` Injection: The attacker needs to be able to modify the `.env` file in the project or set system-wide environment variables that override the `.env` settings.
    - In both cases, the `iotedgedev docker log --show` or `iotedgedev docker log --save` command must be executed by the developer or user.

- **Source Code Analysis:**
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
        5. It uses `os.system(command)` to execute the formatted command. `os.system` executes the command in a subshell, making it vulnerable to command injection if `module` or `LOGS_CMD` contains malicious shell commands.
        6. In the `save` branch, it uses `utility.exe_proc` which uses `subprocess.Popen` but still passes the command with shell=True for redirection `>`. While the docker command itself is passed as arguments, the redirection part could still be potentially manipulated if the module name is crafted to interfere with shell redirection syntax.

- **Security Test Case:**
    - **Test Case 1: Module Name Injection (`docker log --show`)**
        - Step 1: Create a new IoT Edge solution (e.g., `iotedgedev new test_exploit_module`).
        - Step 2: Navigate to the `modules` directory (`cd test_exploit_module/modules`).
        - Step 3: Create a file named `pwned_module.json` with the following content:
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
        - Step 4: Rename the module directory `filtermodule` to `backdoor; touch /tmp/pwned_docker_log_show_module` to create a malicious module name: `mv modules/filtermodule modules/'backdoor; touch /tmp/pwned_docker_log_show_module'`.
        - Step 5: Modify `deployment.template.json` to reflect the new module directory name. Change the module name in the `modules` section to `"backdoor; touch /tmp/pwned_docker_log_show_module"` and update the image placeholder accordingly.
        ```json
        "backdoor; touch /tmp/pwned_docker_log_show_module": {
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
        - Step 7: Check if the file `/tmp/pwned_docker_log_show_module` exists. If it exists, the command injection was successful. You can check by running `ls /tmp/pwned_docker_log_show_module`.

    - **Test Case 2: `LOGS_CMD` Injection (`docker log --show`)**
        - Step 1: Create a new IoT Edge solution (e.g., `iotedgedev new test_exploit_logscmd`).
        - Step 2: Navigate to the solution directory: `cd test_exploit_logscmd`.
        - Step 3: Modify `.env` file to set a malicious `LOGS_CMD`:
        ```ini
        LOGS_CMD='touch /tmp/pwned_docker_log_cmd_{0}'
        ```
        - Step 4: Run the `docker log --show` command:
        ```sh
        iotedgedev docker log --show
        ```
        - Step 5: Check if the files `/tmp/pwned_docker_log_cmd_edgeAgent`, `/tmp/pwned_docker_log_cmd_edgeHub`, and `/tmp/pwned_docker_log_cmd_filtermodule` are created. If these files are created, it confirms command injection vulnerability via `LOGS_CMD`.

### 2. Command Injection Vulnerability in Docker Build and Push Scripts

- **Vulnerability Name:** Command Injection in Docker Build and Push Scripts via Image Name and Version

- **Description:**
    - Step 1: The `build-docker.sh` and `push-docker.sh` scripts use environment variables or script arguments like `IMAGE_NAME` and `VERSION` to construct Docker commands.
    - Step 2: An attacker sets malicious environment variables or provides malicious script arguments. For example, setting `IMAGE_NAME` to `"; touch vulnerable_build_docker_command_injection"` or `VERSION` to `"; touch vulnerable_push_docker_command_injection"`.
    - Step 3: The attacker navigates to the `/code/docker/tool/` directory and executes `build-docker.sh` or `push-docker.sh` with the crafted malicious input as arguments.
    - Step 4: The scripts directly use these variables in shell commands without proper sanitization or escaping. For instance, in `build-docker.sh`, the `IMAGE_NAME` is used in the `-t $IMAGE_NAME:$VERSION-amd64` part of the `docker build` command.
    - Step 5: The shell interprets the injected commands, leading to arbitrary command execution.

- **Impact:**
    - Arbitrary command execution on the developer's machine.
    - An attacker could gain complete control over the developer's environment, steal credentials, or plant malware.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - None. The scripts directly use environment variables and script arguments in command execution without sanitization.

- **Missing Mitigations:**
    - Input sanitization and validation: Sanitize and validate the `IMAGE_NAME` and `VERSION` environment variables and script arguments before using them in shell commands.
    - Use safe command construction methods: Instead of directly embedding variables in shell commands, use safer methods like parameterization or shell escaping to prevent command injection.

- **Preconditions:**
    - The attacker needs to be able to control the environment variables used by the `iotedgedev` tool or provide malicious arguments to the scripts. This could be achieved if the tool is used in an automated CI/CD pipeline where environment variables are dynamically set, or if a developer is tricked into running the scripts with malicious environment variables set or arguments.

- **Source Code Analysis:**
    - File: `/code/docker/tool/build-docker.sh`
        ```sh
        export VERSION=$(cat ../../iotedgedev/__init__.py | grep '__version__' | awk '{print $3}' | sed "s;';;g")
        IMAGE_NAME="$1"
        PLATFORM="$2"
        ...
        docker build \
            -f Dockerfile \
            --build-arg IOTEDGEDEV_VERSION=$VERSION \
            -t $IMAGE_NAME:$VERSION-amd64 \ # Vulnerable line: $IMAGE_NAME and $VERSION are directly used
            ...
        ```
        - The `IMAGE_NAME` variable is directly taken from the first argument `$1` passed to the script. If this argument is influenced by an environment variable controlled by the attacker, it can lead to command injection.
        - The `VERSION` variable, while derived from `__init__.py`, is still used in command construction and could be indirectly influenced if the attacker can modify `__init__.py` or control the script execution environment.
    - File: `/code/docker/tool/push-docker.sh`
        ```sh
        IMAGE_NAME="iotedgedev"
        VERSION="$1"
        ...
        docker push $ACR_LOGIN_SERVER/public/iotedge/$IMAGE_NAME:$VERSION-amd64 # Vulnerable line: $IMAGE_NAME and $VERSION are directly used
        ```
        - Similar to `build-docker.sh`, the `VERSION` variable taken from the first argument `$1` and `IMAGE_NAME` are directly used in `docker push` command, making it vulnerable to command injection if these values are attacker-controlled.

- **Security Test Case:**
    - **Test Case 1: `build-docker.sh` - `IMAGE_NAME` injection**
        - Step 1: Set the environment variable `IMAGE_NAME` to `"; touch vulnerable_build_docker_command_injection"`
        - Step 2: Navigate to the `/code/docker/tool/` directory in the project.
        - Step 3: Run the script: `build-docker.sh injected_image_name linux`
        - Step 4: Check if a file named `vulnerable_build_docker_command_injection` is created in the `/code/docker/tool/` directory. If the file is created, it indicates successful command injection.

    - **Test Case 2: `push-docker.sh` - `VERSION` injection**
        - Step 1: Set the environment variable `VERSION` to `"; touch vulnerable_push_docker_command_injection"`
        - Step 2: Navigate to the `/code/docker/tool/` directory in the project.
        - Step 3: Run the script: `push-docker.sh injected_version`
        - Step 4: Check if a file named `vulnerable_push_docker_command_injection` is created in the `/code/docker/tool/` directory. If the file is created, it indicates successful command injection.