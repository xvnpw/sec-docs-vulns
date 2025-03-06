## Vulnerability List for aws-parallelcluster-node

### - Vulnerability Name: Command Injection in Slurm Node Management Scripts

- Description:
  The `aws-parallelcluster-node` package uses subprocess calls to execute Slurm commands for node management. Improper validation of arguments passed to these subprocess calls could lead to command injection vulnerabilities. An attacker might be able to manipulate cluster configuration parameters or user-provided input (if any) in a way that leads to the execution of arbitrary commands on the EC2 instance when the node package processes this data.

  1. An attacker could potentially manipulate cluster configuration (e.g., through a compromised configuration file or man-in-the-middle attack during configuration retrieval).
  2. This manipulated configuration could contain malicious commands embedded within parameters that are later used as arguments in subprocess calls within the `aws-parallelcluster-node` package.
  3. When the node package processes this configuration, specifically in scripts or daemons responsible for node management (like `clustermgtd`, `computemgtd`, `slurm_resume`, `slurm_suspend`), the malicious commands could be injected into the subprocess calls.
  4. Due to the command injection vulnerability, these malicious commands would be executed on the EC2 instance with the privileges of the user running the `aws-parallelcluster-node` processes (typically root or a cluster admin user).

- Impact:
  Successful command injection can allow an attacker to execute arbitrary commands on the EC2 instance. This can lead to:
    - Full control of the compute node.
    - Data exfiltration from the compute node or the cluster's shared storage.
    - Modification or deletion of critical system files.
    - Use of the compute node as a pivot point for further attacks within the AWS environment.
    - Denial of service by disrupting the compute node's functionality.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
  - The changelog for version 3.5.0 mentions "Add validators to prevent malicious string injection while calling the subprocess module." This indicates that mitigations have been implemented in version 3.5.0 and later to address command injection vulnerabilities. However, the specific locations and effectiveness of these mitigations require further source code analysis.

- Missing Mitigations:
  - While validators have been added, it's crucial to ensure comprehensive and consistent input validation across all subprocess calls within the `aws-parallelcluster-node` package. Further analysis is needed to confirm if all potential injection points are properly secured.
  - Consider using safer alternatives to `subprocess.run` where possible, such as direct function calls or libraries that avoid shell execution when dealing with external commands.
  - Implement principle of least privilege, ensuring that the `aws-parallelcluster-node` processes run with the minimum necessary privileges to reduce the impact of potential command injection exploits.

- Preconditions:
  - An attacker needs to be able to manipulate cluster configuration parameters or influence input processed by the `aws-parallelcluster-node` package. This could be achieved through:
    - Compromising the cluster's configuration storage or delivery mechanisms.
    - Man-in-the-middle attacks during configuration retrieval.
    - Exploiting other vulnerabilities to inject malicious input into the system.

- Source Code Analysis:
  The `CHANGELOG.md` file for version 3.5.0 states: "Add validators to prevent malicious string injection while calling the subprocess module." This enhancement suggests that previous versions were potentially vulnerable to command injection.

  To analyze the mitigation, we would need to examine the source code changes introduced in version 3.5.0. Specifically, we would look for:
    - Code modifications related to subprocess calls within `src/slurm_plugin` directory, especially in files like `clustermgtd.py`, `computemgtd.py`, `resume.py`, `suspend.py`, and potentially within `common/schedulers/slurm_commands.py`.
    - Implementation of validation functions in `common/utils.py` or similar modules, such as `validate_subprocess_argument` and `validate_absolute_path` mentioned in `tests/common/test_utils.py`.
    - Usage of these validation functions before making subprocess calls to sanitize potentially malicious input.

  Without access to the exact source code diff from version 3.4.1 to 3.5.0, a precise code walkthrough is not possible. However, the presence of tests like `tests/common/test_utils.py` and the changelog entry strongly suggest that the developers have addressed command injection risks by implementing input validation for subprocess arguments.

- Security Test Case:
  To create a security test case, we would need to identify specific locations in the code where subprocess calls are made with arguments derived from configuration or input.  Assuming a hypothetical vulnerable code path in an older version (prior to 3.5.0) within `clustermgtd.py` that constructs a Slurm command using a configuration parameter, the test steps would be:

  1. Set up a vulnerable environment: Deploy an older version of `aws-parallelcluster-node` (prior to 3.5.0) in a test ParallelCluster.
  2. Manipulate cluster configuration: Modify the cluster configuration (e.g., using `pcluster configure`) to include a malicious payload in a configuration parameter that is known to be used in subprocess calls. For example, if a queue name parameter is used in a subprocess call, set the queue name to: `test_queue; touch /tmp/pwned`.
  3. Trigger the vulnerable code path: Initiate a cluster management action that triggers the execution of the vulnerable code path in `clustermgtd.py` (e.g., starting or stopping the compute fleet).
  4. Observe the exploit: Check for the execution of the injected command on the head node. In this example, verify if the file `/tmp/pwned` is created on the head node, indicating successful command injection.
  5. Verify mitigation in newer versions: Repeat steps 1-4 with the latest version of `aws-parallelcluster-node` (3.5.0 or later). Verify that the vulnerability is no longer exploitable and the malicious command is not executed due to implemented input validation.

  **Note:** This test case is theoretical and needs to be adapted based on the actual vulnerable code paths identified through source code analysis of versions prior to 3.5.0. Due to the project files provided being the latest version, this test case serves as a general guideline to verify command injection vulnerabilities and their mitigations if older versions of the code were available.

### - Vulnerability Name: Command Injection in `upload-node.sh` via `--scope` parameter

- Description:
    1. The `upload-node.sh` script is used to upload the `aws-parallelcluster-node` package to an S3 bucket.
    2. The script takes a `--scope` parameter, which is intended to disambiguate the S3 path and avoid collisions.
    3. The value of the `--scope` parameter is directly incorporated into the `_key_path` variable without proper sanitization.
    4. This `_key_path` variable is then used in `aws s3 cp` commands.
    5. An attacker could inject malicious commands through the `--scope` parameter, leading to command injection when the script executes the `aws s3 cp` commands.
    6. For example, an attacker could provide a `--scope` value like `"test; touch /tmp/pwned"` or `"test\`touch /tmp/pwned\`"`.
    7. When the script executes `aws s3 cp aws-parallelcluster-node-${_version}.tgz s3://${_bucket}/${_key_path}/aws-parallelcluster-node-${_version}.tgz`, the injected command would be executed.
- Impact:
    - **Critical**. Successful command injection allows an attacker to execute arbitrary commands on the system where `upload-node.sh` is being run. In a CI/CD pipeline or developer's machine, this could lead to compromised credentials, data exfiltration, or further malicious activities.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None identified in the provided files.
- Missing Mitigations:
    - **Input Sanitization**: Sanitize the `--scope` parameter to prevent command injection. This could involve:
        - **Allowlisting**: Only allow alphanumeric characters and hyphens in the scope string.
        - **Input validation**: Validate the `--scope` parameter against a regular expression to ensure it conforms to the expected format.
        - **Encoding**: Properly encode the scope value when constructing the S3 key to prevent shell interpretation of special characters.
    - **Secure Coding Practices**: Avoid directly incorporating user-provided input into shell commands. Use parameterized commands or safer alternatives to shell execution when possible.
- Preconditions:
    - The attacker needs to be able to execute the `upload-node.sh` script and control the `--scope` parameter. This is likely in a development or CI/CD environment where the script is used to package and upload the node package.
- Source Code Analysis:
    1. **File**: `/code/util/upload-node.sh`
    2. **Line**: `_scope="$2"; shift;;` and `_scope="${1#*=}";;` inside the `case` statement for `--scope`. This part reads the `--scope` parameter directly into the `_scope` variable.
    3. **Line**: `_key_path="parallelcluster/${_version}/node"` and `_key_path="${_key_path}/${_scope}"` constructs the S3 key path by directly concatenating the `_scope` variable.
    4. **Line**: `aws ${_profile} --region "${_region}" s3 cp aws-parallelcluster-node-${_version}.tgz s3://${_bucket}/${_key_path}/aws-parallelcluster-node-${_version}.tgz` and similar lines use the `_key_path` variable in the `aws s3 cp` command, which is executed using `bash`. This allows command injection via the unsanitized `_scope` variable.
    ```sh
    _key_path="parallelcluster/${_version}/node"
    if [ -n "${_scope}" ]; then
        _key_path="${_key_path}/${_scope}" # Unsanitized _scope is concatenated into _key_path
    fi
    aws ${_profile} --region "${_region}" s3 cp aws-parallelcluster-node-${_version}.tgz s3://${_bucket}/${_key_path}/aws-parallelcluster-node-${_version}.tgz # _key_path used in command
    ```
- Security Test Case:
    1. **Environment**: Set up a test environment where `upload-node.sh` can be executed. This could be a local machine with AWS CLI configured or a CI/CD pipeline environment.
    2. **Malicious Scope**: Prepare a malicious scope value designed for command injection, for example: `test\`touch /tmp/pwned\``.
    3. **Execute Script**: Execute the `upload-node.sh` script with the malicious scope value and other required parameters like `--bucket`, `--srcdir`. For example:
       ```bash
       ./upload-node.sh --bucket your-s3-bucket --srcdir /path/to/aws-parallelcluster-node --scope "test\`touch /tmp/pwned\`"
       ```
    4. **Verify Exploit**: Check if the injected command `touch /tmp/pwned` was executed. In this case, verify if the file `/tmp/pwned` was created.
    5. **Expected Result**: If the vulnerability exists, the file `/tmp/pwned` should be created, demonstrating successful command injection.

### - Vulnerability Name: Command Injection in Slurm Node Update Commands

- Description:
    1. An attacker could potentially inject arbitrary commands into the `nodes` parameter of the `update_nodes` function in `src/common/schedulers/slurm_commands.py`.
    2. This function is used to update Slurm node configurations using the `scontrol update` command.
    3. If the `nodes` parameter is constructed using unsanitized input, an attacker could inject additional shell commands.
    4. For instance, if the `nodes` parameter is crafted as "node1 & malicious_command", the `scontrol update` command executed via `run_command` might execute the injected `malicious_command`.
- Impact:
    - High. Successful command injection can allow an attacker to execute arbitrary commands on the EC2 instances running `aws-parallelcluster-node`.
    - This could lead to complete compromise of the compute nodes, data exfiltration, or denial of service.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - Input validation is implemented in `common/utils.py` using `validate_subprocess_argument` function and applied in `src/common/utils.py` and `src/common/schedulers/slurm_commands.py`.
    - Specifically, `validate_subprocess_argument` is used in the `update_nodes` function in `src/common/schedulers/slurm_commands.py` to sanitize the `nodes`, `nodeaddrs`, and `nodehostnames` parameters.
- Missing Mitigations:
    - While input validation is present, it's crucial to ensure that it is consistently and correctly applied across all functions that construct and execute shell commands, especially when dealing with external data or user-provided input. Regular reviews and testing are needed to confirm the effectiveness of the current validation and identify any bypasses or missed areas.
- Preconditions:
    - An attacker needs to be able to influence the `nodes` parameter in calls to the `update_nodes` function. This may be possible through other vulnerabilities or misconfigurations in the broader AWS ParallelCluster environment that allow control over node management operations.
- Source Code Analysis:
    1. In `/code/src/common/schedulers/slurm_commands.py`, the `update_nodes` function is defined.
    2. This function takes `nodes`, `nodeaddrs`, and `nodehostnames` as parameters and uses them to construct an `scontrol update` command.
    3. The code iterates through batches of node information using `_batch_node_info`.
    4. Inside the loop, the command is constructed by concatenating strings with parameters like `nodename`, `nodeaddr`, and `nodehostname`.
    5. The `run_command` function is called to execute the constructed command with `shell=True`.
    6. Although `validate_subprocess_argument` is used to sanitize `nodenames`, `addrs`, and `hostnames`, a vulnerability could still exist if this validation is bypassed or insufficient, or if other parts of the command string are vulnerable to injection.
    ```python
    def update_nodes(
        nodes,
        nodeaddrs=None,
        nodehostnames=None,
        state=None,
        reason=None,
        raise_on_error=True,
        command_timeout=DEFAULT_UPDATE_COMMAND_TIMEOUT,
    ):
        ...
        for nodenames, addrs, hostnames in batched_node_info:
            validate_subprocess_argument(nodenames) # Input validation
            node_info = f"nodename={nodenames}"
            if addrs:
                validate_subprocess_argument(addrs) # Input validation
                node_info += f" nodeaddr={addrs}"
            if hostnames:
                validate_subprocess_argument(hostnames) # Input validation
                node_info += f" nodehostname={hostnames}"
            run_command(  # nosec B604
                f"{update_cmd} {node_info}", raise_on_error=raise_on_error, timeout=command_timeout, shell=True # Command execution
            )
    ```
- Security Test Case:
    1. Precondition: An attacker needs to be able to trigger a call to `update_nodes` function with a controllable `nodes` parameter within the `aws-parallelcluster-node` package. For the purpose of this test case, let's assume there is an internal mechanism or API call that allows for node updates and is exploitable.
    2. Attacker crafts a malicious input for the `nodes` parameter. For example: `"queue1-st-c5xlarge-1 & touch /tmp/pcluster_vulnerable"`
    3. Attacker triggers the node update operation using the malicious input.
    4. If the command injection is successful, the command `touch /tmp/pcluster_vulnerable` will be executed on the target EC2 instance.
    5. After the test, the attacker checks for the existence of the file `/tmp/pcluster_vulnerable` on the EC2 instance. If the file exists, it confirms the command injection vulnerability.