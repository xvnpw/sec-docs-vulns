- vulnerability name: Command Injection in Slurm Node Update Commands
- description:
    1. An attacker could potentially inject arbitrary commands into the `nodes` parameter of the `update_nodes` function in `src/common/schedulers/slurm_commands.py`.
    2. This function is used to update Slurm node configurations using the `scontrol update` command.
    3. If the `nodes` parameter is constructed using unsanitized input, an attacker could inject additional shell commands.
    4. For instance, if the `nodes` parameter is crafted as "node1 & malicious_command", the `scontrol update` command executed via `run_command` might execute the injected `malicious_command`.
- impact:
    - High. Successful command injection can allow an attacker to execute arbitrary commands on the EC2 instances running `aws-parallelcluster-node`.
    - This could lead to complete compromise of the compute nodes, data exfiltration, or denial of service.
- vulnerability rank: High
- currently implemented mitigations:
    - Input validation is implemented in `common/utils.py` using `validate_subprocess_argument` function and applied in `src/common/utils.py` and `src/common/schedulers/slurm_commands.py`.
    - Specifically, `validate_subprocess_argument` is used in the `update_nodes` function in `src/common/schedulers/slurm_commands.py` to sanitize the `nodes`, `nodeaddrs`, and `nodehostnames` parameters.
- missing mitigations:
    - While input validation is present, it's crucial to ensure that it is consistently and correctly applied across all functions that construct and execute shell commands, especially when dealing with external data or user-provided input. Regular reviews and testing are needed to confirm the effectiveness of the current validation and identify any bypasses or missed areas.
- preconditions:
    - An attacker needs to be able to influence the `nodes` parameter in calls to the `update_nodes` function. This may be possible through other vulnerabilities or misconfigurations in the broader AWS ParallelCluster environment that allow control over node management operations.
- source code analysis:
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
- security test case:
    1. Precondition: An attacker needs to be able to trigger a call to `update_nodes` function with a controllable `nodes` parameter within the `aws-parallelcluster-node` package. For the purpose of this test case, let's assume there is an internal mechanism or API call that allows for node updates and is exploitable.
    2. Attacker crafts a malicious input for the `nodes` parameter. For example: `"queue1-st-c5xlarge-1 & touch /tmp/pcluster_vulnerable"`
    3. Attacker triggers the node update operation using the malicious input.
    4. If the command injection is successful, the command `touch /tmp/pcluster_vulnerable` will be executed on the target EC2 instance.
    5. After the test, the attacker checks for the existence of the file `/tmp/pcluster_vulnerable` on the EC2 instance. If the file exists, it confirms the command injection vulnerability.