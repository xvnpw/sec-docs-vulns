- Vulnerability Name: Command Injection in `StartTask.sh` via `runPath`

- Description:
    1. A malicious or compromised Windows HPC server sends a request to the Linux Node Agent to start a task.
    2. This request includes a crafted `runPath` argument, which is intended to be the path to the task's run script.
    3. The `StartTask.sh` script receives this `runPath` argument without any sanitization or validation.
    4. If the task is a Docker task, the script executes `docker exec -u $userName ... /bin/bash $runPath`.
    5. If the task is a non-Docker task, the script executes `/bin/bash $runPath` or `su $userName -m -c "/bin/bash $runPath"` or `sudo -H -E -u $userName env "PATH=$PATH" /bin/bash /opt/hpcnodemanager/RunInCGroup.sh $procsFile $runPath`.
    6. Because `runPath` is not sanitized, an attacker can inject arbitrary shell commands into the `runPath` argument.
    7. These injected commands will be executed by `bash` with the privileges of the specified user (or root if no user switching is involved in certain code paths).

- Impact:
    - **High**
    - Arbitrary command execution on the Linux node with the privileges of the user specified in the task request, or potentially root if no user switching is enforced.
    - This can lead to complete compromise of the Linux node, including data exfiltration, installation of malware, and further attacks on the HPC cluster environment.

- Vulnerability Rank:
    - **Critical**

- Currently Implemented Mitigations:
    - None. The code directly uses the `$runPath` argument in command execution without any sanitization or validation.

- Missing Mitigations:
    - Input validation and sanitization for the `runPath` argument in `StartTask.sh`.
    - Instead of directly using `runPath` in shell execution, consider using a safer method to execute the intended script, such as:
        - Validating that `runPath` points to an existing file within the task folder.
        - Using `execve` to execute the script directly, avoiding shell interpretation of the path.
        - If shell execution is necessary, sanitize the input to remove or escape any shell metacharacters.

- Preconditions:
    - A compromised or malicious Windows HPC server capable of sending task requests to the Linux Node Agent.
    - The Linux Node Agent is configured to accept and process task requests from the HPC server.

- Source Code Analysis:
    - File: `/code/nodemanager/scripts/StartTask.sh`
    - Line 20: `runPath=$2` - The `runPath` variable is assigned directly from the second command-line argument `$2` without any validation.
    - Docker Task Code Path (lines 40-42):
        ```bash
        if $isDockerTask; then
            containerId=$(GetContainerId $taskFolder)
            docker exec $containerId /bin/bash -c "$taskFolder/TestMutualTrust.sh $taskId $taskFolder $userName" &&\
            docker exec -u $userName -e CCP_MPI_HOSTFILE=$taskFolder/mpi_hostfile $containerId /bin/bash $runPath
            exit
        fi
        ```
        - The `$runPath` variable is used directly in the `docker exec` command: `docker exec -u $userName ... /bin/bash $runPath`. The `-c` option in the first `docker exec` mitigates injection there, but the second `docker exec` directly executes `$runPath` in a shell.
    - Non-Docker Task Code Path (lines 50-74):
        ```bash
        if ! $CGroupV1 && ! $cgDisabled; then
            ...
            if [ "$CCP_SWITCH_USER" == "1" ]; then
                su $userName -m -c "/bin/bash /opt/hpcnodemanager/RunInCGroup.sh $procsFile $runPath"
            else
                sudo -H -E -u $userName env "PATH=$PATH" /bin/bash /opt/hpcnodemanager/RunInCGroup.sh $procsFile $runPath
            fi
        elif $CGInstalled && ! $cgDisabled; then
            ...
            if [ "$CCP_SWITCH_USER" == "1" ]; then
                cgexec -g "$group" su $userName -m -c "/bin/bash $runPath"
            else
                cgexec -g "$group" sudo -H -E -u $userName env "PATH=$PATH" /bin/bash $runPath
            fi
        else
            ...
            if [ "$CCP_SWITCH_USER" == "1" ]; then
                su $userName -m -c "/bin/bash $runPath"
            else
                sudo -H -E -u $userName env "PATH=$PATH" /bin/bash $runPath
            fi
        fi
        ```
        - In all non-Docker task code paths, `$runPath` is directly used in `/bin/bash $runPath` or similar commands executed via `su` or `sudo`.

- Security Test Case:
    1. Set up a test environment with a Linux node agent and a simulated Windows HPC server (or use a real HPC server if available in a test environment).
    2. As an attacker, craft a malicious `runPath` string containing a command injection payload. For example: `"; touch /tmp/pwned; echo vulnerable > /tmp/vuln.txt &"`
    3. Send a task start request to the Linux Node Agent from the HPC server, including the crafted `runPath` as the task's run script path. Assume a non-docker task for simplicity.
    4. On the Linux node, check if the files `/tmp/pwned` and `/tmp/vuln.txt` have been created.
    5. If these files are created, it confirms that the command injection was successful, and arbitrary commands were executed on the Linux node.