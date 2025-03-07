### Vulnerability List:

- Vulnerability Name: Command Injection in `resume_program.sh`, `suspend_program.sh` and `resume_fail_program.sh` scripts via `node_list` parameter
- Description:
    1. An attacker can gain access to the Slurm scheduler node.
    2. The attacker executes `resume_program.sh`, `suspend_program.sh` or `resume_fail_program.sh` script, providing a malicious `node_list` as a command line argument.
    3. The `node_list` argument is passed unsanitized to the `azslurm resume`, `azslurm suspend` or `azslurm suspend` commands respectively within these scripts.
    4. The `azslurm` command, in turn, uses shell=True in subprocess calls, making it vulnerable to command injection.
    5. By crafting a malicious `node_list` containing shell metacharacters, the attacker can inject and execute arbitrary commands on the Slurm scheduler node.
- Impact:
    - **High**: Successful command injection can allow an attacker to execute arbitrary commands as root on the Slurm scheduler node. This can lead to complete compromise of the Slurm cluster, including data exfiltration, malware installation, and denial of service.
- Vulnerability Rank: **Critical**
- Currently Implemented Mitigations:
    - None. The code directly passes unsanitized input to shell commands.
- Missing Mitigations:
    - **Input Sanitization**: The `node_list` parameter in `resume_program.sh`, `suspend_program.sh` and `resume_fail_program.sh` scripts must be sanitized to remove or escape shell metacharacters before being passed to the `azslurm` command.
    - **Secure Coding Practices**: Avoid using `shell=True` in subprocess calls, especially when handling user-provided input. Use array format for subprocess arguments to prevent shell injection.
- Preconditions:
    - Attacker has access to execute scripts on the Slurm scheduler node (e.g., via SSH access or by exploiting another vulnerability to gain code execution).
- Source Code Analysis:
    - File: `/code/sbin/resume_program.sh`
    ```bash
    #!/usr/bin/env bash
    node_list=$(echo $@ | sed "s/ /,/g")
    source /opt/azurehpc/slurm/venv/bin/activate
    azslurm resume --node-list $node_list
    exit $?
    ```
    - File: `/code/sbin/suspend_program.sh`
    ```bash
    #!/usr/bin/env bash
    node_list=$(echo $@ | sed "s/ /,/g")
    source /opt/azurehpc/slurm/venv/bin/activate
    azslurm suspend --node-list $node_list
    exit $?
    ```
    - File: `/code/sbin/resume_fail_program.sh`
    ```bash
    #!/usr/bin/env bash
    node_list=$(echo $@ | sed "s/ /,/g")
    source /opt/azurehpc/slurm/venv/bin/activate
    azslurm suspend --node-list $node_list
    exit $?
    ```
    - In these scripts, the `node_list` variable is constructed directly from the command-line arguments `$@` without proper sanitization.
    - This `node_list` variable is then directly passed as an argument to the `azslurm resume` or `azslurm suspend` command.
    - If an attacker provides a malicious `node_list` containing shell metacharacters (e.g., backticks, semicolons, command substitution), these characters will be interpreted by the shell when `azslurm` command is executed, leading to command injection.

- Security Test Case:
    1. Gain access to the Slurm scheduler node as root (assuming attacker has compromised the scheduler node).
    2. Execute the `resume_program.sh` script with a malicious `node_list`:
    ```bash
    /opt/azurehpc/slurm/sbin/resume_program.sh "htc-1; touch /tmp/pwned; #"
    ```
    3. Check if the file `/tmp/pwned` is created on the Slurm scheduler node.
    ```bash
    ls -l /tmp/pwned
    ```
    4. If the file `/tmp/pwned` exists, it confirms that the command injection vulnerability is successfully exploited, and arbitrary commands can be executed.
    5. Repeat steps 2-4 for `suspend_program.sh` and `resume_fail_program.sh` to confirm vulnerability in these scripts as well.