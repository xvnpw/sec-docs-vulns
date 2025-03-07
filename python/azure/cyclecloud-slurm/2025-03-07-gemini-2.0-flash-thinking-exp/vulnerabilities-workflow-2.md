## Combined Vulnerability List

The following vulnerabilities have been identified in the provided lists.

### 1. Command Injection via Slurm Dynamic Config
- **Description:**
    1. A malicious user with control over the CycleCloud cluster template can modify the `slurm.dynamic_config` parameter within a nodearray's configuration.
    2. They can inject arbitrary shell commands into this parameter, which is intended to be used for setting Slurm dynamic partition configurations.
    3. When an administrator executes `azslurm scale` on the Slurm scheduler node to update the cluster configuration, the `azslurm` script processes the template and uses the potentially malicious `slurm.dynamic_config` value in an `scontrol create partition` command.
    4. Due to insufficient sanitization, the injected commands are executed as part of the `scontrol` command, leading to arbitrary command execution on the Slurm scheduler node with root privileges.
- **Impact:**
    - Critical. An attacker can achieve arbitrary command execution on the Slurm scheduler node with root privileges. This allows them to take complete control of the Slurm cluster, potentially exfiltrate sensitive data, disrupt operations, or use the cluster for further malicious activities.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    - None. The project does not implement any sanitization or validation of the `slurm.dynamic_config` parameter.
- **Missing Mitigations:**
    - Input sanitization and validation for `slurm.dynamic_config` in `azslurm scale` script to prevent command injection. Specifically, any shell metacharacters or command separators should be escaped or rejected.
    - Principle of least privilege: Avoid running `azslurm scale` as root if possible, or minimize the privileges required. However, given the need to reconfigure Slurm services, root privileges might be necessary, making input sanitization the more critical mitigation in this case.
- **Preconditions:**
    - An attacker needs to have the ability to modify the CycleCloud cluster template, which typically requires administrative access to the CycleCloud UI or API.
    - The administrator must execute `azslurm scale` after the malicious template modification.
- **Source Code Analysis:**
    1. **File: `/code/slurm/src/slurmcc/cli.py`**: The `scale` function in `SlurmCLI` class is responsible for generating and applying the Slurm configuration.
    2. **File: `/code/slurm/src/slurmcc/partition.py`**: The `fetch_partitions` function reads the cluster configuration, including the `slurm.dynamic_config` parameter from the template.
    3. **File: `/code/slurm/src/slurmcc/cli.py`**: Inside `scale` function, the `_partitions` function is called, which in turn calls `_dynamic_partition` to generate dynamic partition configuration.
    4. **File: `/code/slurm/src/slurmcc/cli.py`**: Inside `_dynamic_partition` function, the `partition.dynamic_config` value is directly used within the `writer.write` call to construct Slurm configuration lines.
    5. **File: `/code/slurm/src/slurmcc/util.py`**: The `scontrol` function executes Slurm commands, including the potentially malicious configuration generated in `_dynamic_partition`.

    ```python
    # Visualization of vulnerable code path in _dynamic_partition function within /code/slurm/src/slurmcc/cli.py

    _dynamic_partition(partition: partitionlib.Partition, writer: TextIO) -> None:
        assert partition.dynamic_feature # dynamic_feature is derived from slurm.dynamic_config

        writer.write(
            "# Creating dynamic nodeset and partition using slurm.dynamic_feature=%s\n"
            % partition.dynamic_feature # No sanitization here, directly using user input
        )
        if not partition.features:
            logging.error(...)
            return

        writer.write(f"Nodeset={partition.name}ns Feature={partition.features[0]}\n") # Part of generated config, but no direct injection here
        writer.write(f"PartitionName={partition.name} Nodes={partition.name}ns") # Part of generated config, but no direct injection here
        if partition.is_default:
            writer.write(" Default=YES") # Part of generated config, but no direct injection here
        writer.write("\n") # Part of generated config, but no direct injection here
    ```
    The vulnerability lies in the fact that `partition.dynamic_feature`, which originates from user-controlled `slurm.dynamic_config`, is directly embedded into the generated Slurm configuration without any sanitization before being processed by `scontrol`. This allows command injection when `scontrol create partition` or similar commands process this configuration.

- **Security Test Case:**
    1. As an attacker, modify the CycleCloud cluster template. Locate a nodearray configuration section (e.g., `[[nodearray htc]]`).
    2. Within the `[[[configuration]]]` subsection of the nodearray, add or modify the `slurm.dynamic_config` parameter to inject a malicious command. For example:
        ```ini
        [[[configuration]]]
        slurm.autoscale = true
        slurm.dynamic_config := "-Z --conf \\"Feature=mydyn; touch /tmp/pwned;\\""
        ```
        This payload attempts to create a file `/tmp/pwned` on the scheduler node when `azslurm scale` is run.
    3. Save the modified template.
    4. As an administrator, SSH into the Slurm scheduler node.
    5. Execute the command `sudo azslurm scale`.
    6. Check if the file `/tmp/pwned` exists on the scheduler node. If the file exists, it confirms successful command injection.

### 2. Command Injection in `resume_program.sh`, `suspend_program.sh` and `resume_fail_program.sh` scripts via `node_list` parameter
- **Description:**
    1. An attacker can gain access to the Slurm scheduler node.
    2. The attacker executes `resume_program.sh`, `suspend_program.sh` or `resume_fail_program.sh` script, providing a malicious `node_list` as a command line argument.
    3. The `node_list` argument is passed unsanitized to the `azslurm resume`, `azslurm suspend` or `azslurm suspend` commands respectively within these scripts.
    4. The `azslurm` command, in turn, uses shell=True in subprocess calls, making it vulnerable to command injection.
    5. By crafting a malicious `node_list` containing shell metacharacters, the attacker can inject and execute arbitrary commands on the Slurm scheduler node.
- **Impact:**
    - **High**: Successful command injection can allow an attacker to execute arbitrary commands as root on the Slurm scheduler node. This can lead to complete compromise of the Slurm cluster, including data exfiltration, malware installation, and denial of service.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    - None. The code directly passes unsanitized input to shell commands.
- **Missing Mitigations:**
    - **Input Sanitization**: The `node_list` parameter in `resume_program.sh`, `suspend_program.sh` and `resume_fail_program.sh` scripts must be sanitized to remove or escape shell metacharacters before being passed to the `azslurm` command.
    - **Secure Coding Practices**: Avoid using `shell=True` in subprocess calls, especially when handling user-provided input. Use array format for subprocess arguments to prevent shell injection.
- **Preconditions:**
    - Attacker has access to execute scripts on the Slurm scheduler node (e.g., via SSH access or by exploiting another vulnerability to gain code execution).
- **Source Code Analysis:**
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

- **Security Test Case:**
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