## Combined Vulnerability List

### Vulnerability: Command Injection in `StartTask.sh` via `runPath`

- **Description:**
    - A malicious actor, having compromised a Windows HPC server or the task submission process, can inject arbitrary commands into the `runPath` parameter of a task request. This parameter, intended to specify the path to the task's run script, is sent from the Windows HPC server to the Linux Node Agent when scheduling a task. The `StartTask.sh` script on the Linux node receives this `runPath` argument as input without any sanitization or validation. Depending on the task type (Docker or non-Docker), the script executes commands involving this unsanitized `runPath`. For Docker tasks, it executes `docker exec -u $userName ... /bin/bash $runPath`. For non-Docker tasks, it executes commands like `/bin/bash $runPath`, `su $userName -m -c "/bin/bash $runPath"`, or `sudo -H -E -u $userName env "PATH=$PATH" /bin/bash /opt/hpcnodemanager/RunInCGroup.sh $procsFile $runPath`. Because `runPath` is not validated, an attacker can inject shell commands within it. These injected commands are then executed by `bash` on the Linux node with the privileges of the specified user (or potentially root in certain code paths).

- **Impact:**
    - **High**
    - **Remote Code Execution:** Successful exploitation allows an attacker to execute arbitrary commands on the Linux node.
    - **Full System Compromise:** This can lead to a complete compromise of the Linux node, enabling attackers to perform actions such as data exfiltration, installation of malware, establishing persistent access, and launching further attacks within the HPC cluster environment. The command execution context depends on the code path within `StartTask.sh`, potentially running as the task user or even root in some scenarios.

- **Vulnerability Rank:**
    - **Critical**

- **Currently Implemented Mitigations:**
    - None. The `StartTask.sh` script directly utilizes the `$runPath` argument in command execution without any input sanitization or validation.

- **Missing Mitigations:**
    - **Input Validation and Sanitization:** Implement robust input validation and sanitization for the `runPath` argument within the `StartTask.sh` script. This should ensure that `runPath` only contains a valid path to an executable script and does not include any malicious commands or shell metacharacters.
    - **Safer Execution Methods:** Instead of directly using `runPath` in shell execution, explore safer alternatives to execute the intended script. This could involve:
        - Validating that `runPath` points to a file within the designated task folder and verifying it is an executable script.
        - Utilizing `execve` to execute the script directly, bypassing shell interpretation of the path and arguments.
        - If shell execution is unavoidable, rigorously sanitize the input to escape or remove any shell metacharacters.
    - **Principle of Least Privilege:** Ensure that tasks are executed with the minimum necessary privileges to limit the impact of successful command injection.
    - **Sandboxing/Isolation:** Consider running tasks in more isolated environments, such as containers with restricted capabilities, to contain the potential damage from command injection vulnerabilities. While cgroups are used for resource management, they are not sufficient to prevent command injection exploits.

- **Preconditions:**
    - An attacker must be able to control or influence the task submission process from the Windows HPC system. This could be achieved by compromising the Windows HPC server itself or by manipulating the task submission mechanism.
    - The Linux Node Agent must be configured to accept and process task requests originating from the potentially compromised HPC server.

- **Source Code Analysis:**
    - **File:** `/code/nodemanager/scripts/StartTask.sh`
    - **Line 20:** `runPath=$2` - The `runPath` variable is directly assigned the value of the second command-line argument (`$2`) without any validation or sanitization.
    - **Docker Task Code Path (lines 40-42):**
        ```bash
        if $isDockerTask; then
            containerId=$(GetContainerId $taskFolder)
            docker exec $containerId /bin/bash -c "$taskFolder/TestMutualTrust.sh $taskId $taskFolder $userName" &&\
            docker exec -u $userName -e CCP_MPI_HOSTFILE=$taskFolder/mpi_hostfile $containerId /bin/bash $runPath
            exit
        fi
        ```
        - In the second `docker exec` command, `$runPath` is directly appended to `/bin/bash`, creating a command injection vulnerability.
    - **Non-Docker Task Code Path (lines 50-74):**
        ```bash
        if ! $CGroupV1 && ! $cgDisabled; then
            ...
            if [ "$CCP_SWITCH_USER" == "1" ]; then
                su $userName -m -c "/bin/bash /opt/hpcnodemanager/RunInCGroup.sh $procsFile $runPath"
            else
                sudo -H -E -u $userName env "PATH=$PATH" /bin/bash /opt/hpcnodemanager/RunInCGroup.sh $procsFile $runPath"
            fi
        elif $CGInstalled && ! $cgDisabled; then
            ...
            if [ "$CCP_SWITCH_USER" == "1" ]; then
                cgexec -g "$group" su $userName -m -c "/bin/bash $runPath"
            else
                cgexec -g "$group" sudo -H -E -u $userName env "PATH=$PATH" /bin/bash $runPath"
            fi
        else
            ...
            if [ "$CCP_SWITCH_USER" == "1" ]; then
                su $userName -m -c "/bin/bash $runPath"
            else
                sudo -H -E -u $userName env "PATH=$PATH" /bin/bash $runPath"
            fi
        fi
        ```
        - In all non-Docker task code paths, the `$runPath` variable is directly incorporated into commands executed via `/bin/bash $runPath` or similar constructions using `su` or `sudo`, without any validation, leading to command injection.

- **Security Test Case:**
    1. Set up a testing environment that includes a Linux node agent and a controllable or simulated Windows HPC server (or a real HPC server within a secure test environment).
    2. As an attacker, craft a malicious `runPath` string containing a command injection payload. For example: `"; touch /tmp/pwned_starttask; echo vulnerable > /tmp/vuln_starttask.txt &"`
    3. Initiate a task start request from the HPC server to the Linux Node Agent. Within this request, specify the crafted malicious `runPath` as the task's run script path. For simplicity, initially target a non-Docker task.
    4. After the task is processed by the Linux node, access the node and check for the presence of the files `/tmp/pwned_starttask` and `/tmp/vuln_starttask.txt`.
    5. If these files are successfully created, it confirms that the command injection was successful, and arbitrary commands injected via the `runPath` were executed on the Linux node.
    6. To test the Docker task code path, ensure the task is configured as a Docker task and repeat steps 2-5, adapting the expected file names accordingly (e.g., `/tmp/pwned_docker_starttask`).

### Vulnerability: Command Injection in `shim.sh` via Unvalidated Arguments

- **Description:**
    - The `shim.sh` script serves as the primary entry point for the HPC Pack Linux NodeAgent extension. Upon execution, it determines the Python interpreter to use and subsequently executes the `hpcnodemanager.py` script. Critically, `shim.sh` directly passes all command-line arguments it receives to `hpcnodemanager.py` without performing any validation or sanitization. This lack of input validation creates a command injection vulnerability. An attacker capable of influencing the arguments passed to `shim.sh`, typically through interaction with the Azure extension management framework or other means of controlling the extension's execution environment, could inject malicious commands. For instance, arguments like `--operation="enable ; touch /tmp/pwned_shim ;"` could be crafted to inject shell commands. These injected commands would be executed in the security context of the user running `shim.sh`, which is often root or a highly privileged user.

- **Impact:**
    - **Critical**
    - **Remote Command Execution:** Successful exploitation allows an attacker to execute arbitrary commands on the Linux node with root privileges.
    - **Full System Compromise:** Gaining root-level command execution grants the attacker complete control over the compromised Linux node. This enables a wide range of malicious activities, including but not limited to data theft, malware installation, privilege escalation, lateral movement within the network, and denial of service.

- **Vulnerability Rank:**
    - **Critical**

- **Currently Implemented Mitigations:**
    - None. The `shim.sh` script directly forwards all received arguments to `hpcnodemanager.py` without any form of input validation or sanitization.

- **Missing Mitigations:**
    - **Input Validation and Sanitization:** Implement comprehensive input validation within the `shim.sh` script. This should involve sanitizing or rejecting any arguments that could potentially contain malicious commands before they are passed to `hpcnodemanager.py`. Validation rules should be based on the expected format and content of each argument.
    - **Parameterized Execution:** Explore alternative methods for passing arguments to `hpcnodemanager.py` that minimize the risk of command injection. Parameterized execution techniques, where arguments are treated as data rather than code, should be considered if feasible.
    - **Principle of Least Privilege:** While primarily addressing a different aspect of security, ensuring that the `shim.sh` script and `hpcnodemanager.py` operate with the minimum necessary privileges can limit the potential damage from a successful command injection.

- **Preconditions:**
    - An attacker must possess the ability to influence the command-line arguments passed to the `shim.sh` script. In the context of Azure environments, this could be achieved through malicious extension configuration updates or other interactions with the Azure extension management framework. In other deployment scenarios, other methods of controlling script arguments would need to be exploited.

- **Source Code Analysis:**
    - **File:** `/code/VMExtension/shim.sh`
    ```bash
    #!/usr/bin/env bash
    # ... [Other script code] ...
    ARG="$@"
    # ... [Other script code] ...
    ${PYTHON} ${COMMAND} ${ARG}
    ```
    - **`ARG="$@"`:** This line captures all command-line arguments passed to `shim.sh` and stores them in the variable `ARG`.
    - **`${PYTHON} ${COMMAND} ${ARG}`:** This line executes the Python script `hpcnodemanager.py` (referenced by `${COMMAND}`) using the Python interpreter `${PYTHON}`, passing the contents of the `ARG` variable as command-line arguments.
    - **Absence of Input Validation:** There is no code within `shim.sh` that validates or sanitizes the arguments before they are passed to the Python script. This direct and unvalidated passing of arguments creates a command injection vulnerability, as any malicious commands embedded within the arguments will be processed by `hpcnodemanager.py` or its subprocesses.

- **Security Test Case:**
    1. Set up a test environment where you can deploy or execute the HPC Linux Node Agent Azure VM extension. This might involve deploying a test VM in Azure or simulating the extension execution environment.
    2. Craft a malicious payload designed to be passed as a command-line argument to `shim.sh`. For example, when triggering an "enable" operation (or any other operation that invokes `shim.sh`), attempt to inject a command using an argument like `--operation="enable" --malicious_arg="; touch /tmp/pwned_shim ;"`. The specific argument name (`malicious_arg` in this example) is illustrative and might need to be adjusted based on the actual argument parsing logic of `hpcnodemanager.py` or scripts it calls.
    3. Deploy or update the extension on a test Linux VM, including the crafted malicious payload as part of the extension settings or operation parameters. The method for injecting arguments will depend on the Azure extension framework and how it interacts with `shim.sh`.
    4. After deploying or triggering the extension operation, access the Linux VM and check if the file `/tmp/pwned_shim` has been created.
    5. If the file `/tmp/pwned_shim` exists, it confirms the command injection vulnerability. The injected `touch /tmp/pwned_shim` command, passed through the arguments to `shim.sh` and subsequently processed, was successfully executed by the system.
    6. For further testing, attempt to execute more impactful commands, such as establishing a reverse shell or exfiltrating data, to fully assess the severity and exploitability of the vulnerability.