- Vulnerability Name: Command Injection in StartTask.sh via runPath

- Description:
    1. An attacker compromises the Windows HPC system.
    2. The attacker crafts a malicious task submission to the Windows HPC system.
    3. As part of the task submission, the attacker injects a malicious command into the `runPath` parameter, which is intended to specify the path to the task's run script.
    4. The Windows HPC system, without proper validation, sends this malicious `runPath` to the Linux Node Manager when scheduling the task.
    5. The `StartTask.sh` script on the Linux node receives the malicious `runPath` as the second argument (`$2`).
    6. The script executes the command `/bin/bash $runPath` directly, without sanitizing or validating the `runPath`.
    7. The injected malicious command in `$runPath` is executed on the Linux node with the privileges of the user specified in the task context.

- Impact:
    - Remote Code Execution: An attacker can execute arbitrary commands on the Linux node with the privileges of the task execution user. This can lead to full compromise of the Linux node, data exfiltration, installation of malware, or further attacks on the HPC cluster environment.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - None: The code directly executes the `$runPath` without any validation or sanitization.

- Missing Mitigations:
    - Input Validation: The `StartTask.sh` script should validate the `runPath` parameter to ensure it only contains a valid path to an executable script and does not contain any malicious commands or shell metacharacters.
    - Sandboxing/Least Privilege: While cgroups are used for resource management, they do not prevent command injection. Running tasks in more isolated environments (e.g., containers with restricted capabilities) could limit the impact of command injection.
    - Principle of Least Privilege: Ensure the user under which tasks are run has only the minimum necessary privileges.

- Preconditions:
    - Attacker must be able to compromise or control the task submission process in the Windows HPC system to inject malicious `runPath`.
    - The Linux Node Manager must be configured to accept and execute tasks from the compromised Windows HPC system.

- Source Code Analysis:
    - File: `/code/nodemanager/scripts/StartTask.sh`
    - Line: `41`: `/bin/bash $runPath`
    - Code Flow:
        ```bash
        #!/bin/bash

        . common.sh

        [ -z "$1" ] && echo "task id not specified" && exit 202
        [ -z "$2" ] && echo "run.sh not specified" && exit 202 # $2 becomes runPath
        [ -z "$3" ] && echo "username not specified" && exit 202
        [ -z "$4" ] && echo "task folder not specified" && exit 202

        taskId=$1
        runPath=$2 # runPath is directly taken from script argument $2
        userName=$3
        taskFolder=$4

        ...

        isDockerTask=$(CheckDockerEnvFileExist $taskFolder)
        if $isDockerTask; then
        	containerId=$(GetContainerId $taskFolder)
        	docker exec $containerId /bin/bash -c "$taskFolder/TestMutualTrust.sh $taskId $taskFolder $userName" &&\
        	docker exec -u $userName -e CCP_MPI_HOSTFILE=$taskFolder/mpi_hostfile $containerId /bin/bash $runPath # runPath is used here inside docker exec
        	exit
        fi

        cgDisabled=$(CheckCgroupDisabledInFlagFile $taskFolder)
        if ! $CGroupV1 && ! $cgDisabled; then
        	groupName=$(GetCGroupName "$taskId")
        	procsFile=$(GetCpusetTasksFileV2 "$groupName")
        	echo $$ > "$procsFile"
        	/bin/bash $taskFolder/TestMutualTrust.sh "$taskId" "$taskFolder" "$userName" || exit
        	if [ "$CCP_SWITCH_USER" == "1" ]; then
        		su $userName -m -c "/bin/bash /opt/hpcnodemanager/RunInCGroup.sh $procsFile $runPath" # runPath is used here inside RunInCGroup.sh
        	else
        		sudo -H -E -u $userName env "PATH=$PATH" /bin/bash /opt/hpcnodemanager/RunInCGroup.sh $procsFile $runPath" # runPath is used here inside RunInCGroup.sh
        	fi
        elif $CGInstalled && ! $cgDisabled; then
        	groupName=$(GetCGroupName "$taskId")
        	group=$CGroupSubSys:$groupName
        	cgexec -g "$group" /bin/bash $taskFolder/TestMutualTrust.sh "$taskId" "$taskFolder" "$userName" || exit
        	if [ "$CCP_SWITCH_USER" == "1" ]; then
        		cgexec -g "$group" su $userName -m -c "/bin/bash $runPath" # runPath is used directly
        	else
        		cgexec -g "$group" sudo -H -E -u $userName env "PATH=$PATH" /bin/bash $runPath" # runPath is used directly
        	fi
        else
        	/bin/bash $taskFolder/TestMutualTrust.sh "$taskId" "$taskFolder" "$userName" || exit
        	if [ "$CCP_SWITCH_USER" == "1" ]; then
        		su $userName -m -c "/bin/bash $runPath" # runPath is used directly
        	else
        		sudo -H -E -u $userName env "PATH=$PATH" /bin/bash $runPath" # runPath is used directly
        	fi
        fi
        ```
    - The script directly uses `$runPath` in `/bin/bash $runPath` and similar commands without any validation. This allows for command injection if `$runPath` is attacker-controlled.

- Security Test Case:
    1. Setup a test environment with a Linux Node Manager and a simulated Windows HPC system (or access to a real one if possible and permitted).
    2. As an attacker, craft a malicious task submission that targets the Linux Node Manager.
    3. In the task submission, set the `runPath` parameter to a malicious command, for example: `/bin/bash -c "touch /tmp/pwned; whoami > /tmp/whoami.txt"`.
    4. Submit the task to the Windows HPC system, targeting the Linux node.
    5. Observe the Linux node after the task is scheduled and supposedly executed.
    6. Check if the file `/tmp/pwned` exists and if `/tmp/whoami.txt` contains the output of the `whoami` command. If these files are created, it confirms command injection vulnerability.
    7. Further, check if the command was executed with the expected user privileges (content of `/tmp/whoami.txt`).
    8. For Docker tasks, adapt the test case to inject commands into the Docker execution path within `StartTask.sh`. For non-Docker tasks, test the direct execution path.

This vulnerability is present because the `runPath` parameter, which is likely provided by the Windows HPC system (and potentially attacker-influenced), is directly used in command execution without any validation or sanitization in `StartTask.sh`. This allows for command injection and remote code execution on the Linux node.