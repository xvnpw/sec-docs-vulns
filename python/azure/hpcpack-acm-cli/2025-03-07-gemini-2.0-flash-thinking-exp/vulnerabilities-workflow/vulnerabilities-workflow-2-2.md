- Vulnerability name: Command Injection in `clusrun new` command
- Description:
  - The `clusrun new` command allows users to execute commands on HPC cluster nodes.
  - The command to be executed is specified by the `command_line` argument.
  - The `clusrun` command-line tool does not sanitize or validate the `command_line` argument before passing it to the HPC Pack ACM API.
  - An attacker can inject malicious shell commands into the `command_line` argument.
  - When the `clusrun new` command is executed, the injected malicious commands are sent to the HPC Pack ACM API.
  - The HPC Pack ACM API then executes these commands on the target HPC cluster nodes.
  - As a result, the attacker-injected commands are executed with the privileges of the HPC Pack ACM agent on the cluster nodes.
- Impact:
  - An attacker can execute arbitrary commands on all nodes in the HPC cluster.
  - This can lead to a complete compromise of the HPC cluster.
  - Potential impacts include:
    - Data theft: Attackers can access and exfiltrate sensitive data stored on the cluster nodes.
    - Malware installation: Attackers can install malware, such as ransomware or botnets, on the cluster nodes.
    - Denial of service: Attackers can disrupt the operation of the cluster, making it unavailable to legitimate users.
    - Privilege escalation: Attackers may be able to escalate their privileges within the cluster environment.
- Vulnerability rank: Critical
- Currently implemented mitigations:
  - None. The code does not perform any sanitization or validation of the `command_line` argument in the `clusrun new` command.
- Missing mitigations:
  - Input sanitization and validation for the `command_line` argument in the `clusrun new` command.
  - Implement proper input validation to prevent the injection of malicious commands.
  - Consider using parameterized commands or a safer command execution method that avoids direct shell interpretation of user inputs.
- Preconditions:
  - The attacker must have access to the `clusrun` command-line tool.
  - The attacker must have network connectivity to the HPC Pack ACM API endpoint.
  - The attacker must have valid credentials (or be able to bypass authentication if there are other vulnerabilities) to use the `clusrun` command against the target HPC Pack cluster.
- Source code analysis:
  - File: `/code/hpc_acm_cli/clus.py`
  - Function: `Clusrun.new(self)`
  - Step 1: The `new` function is called when the `clusrun new` subcommand is executed.
  - Step 2: The command line arguments are parsed, and `self.args.command_line` is populated with the user-provided command.
  - Step 3: A dictionary `job` is created to represent the clusrun job.
  - Step 4: The `commandLine` key in the `job` dictionary is directly assigned the value of `self.args.command_line` without any sanitization or validation:
    ```python
    job = {
        "name": "Command@%s" % datetime.datetime.now().isoformat(),
        "targetNodes": nodes,
        "commandLine": self.args.command_line, # Vulnerable line: User input directly used
    }
    ```
  - Step 5: The `job` dictionary is then passed to the `create_clusrun_job` method of the API client:
    ```python
    job = self.api.create_clusrun_job(job = job)
    ```
  - Step 6: The `create_clusrun_job` method sends an API request to the HPC Pack ACM server with the unsanitized `commandLine`.
  - Step 7: The HPC Pack ACM server, upon receiving the request, executes the provided `commandLine` on the specified cluster nodes.
  - Visualization:
    ```
    User Input (command_line) --> clusrun CLI (clus.py - Clusrun.new) --> HPC Pack ACM API (hpc_acm_cli.api) --> HPC Pack ACM Server --> Cluster Nodes (Command Execution)
    ```
    The user input flows directly into command execution on cluster nodes without sanitization in `clusrun CLI`.
- Security test case:
  - Precondition:
    - Have a running HPC Pack cluster and the `hpc-acm-cli` tool configured to communicate with it.
    - Ensure you have the `clusrun` command available in your environment after installing `hpc-acm-cli`.
  - Step 1: Open a terminal and execute the following command, replacing `<your_hpc_acm_host>` with the actual hostname or IP address of your HPC Pack ACM server if needed, and ensuring the tool is configured to connect to it:
    ```bash
    clusrun new --host <your_hpc_acm_host> --pattern "*" "echo vulnerable > /tmp/vuln.txt"
    ```
    - This command instructs `clusrun` to execute the command `echo vulnerable > /tmp/vuln.txt` on all nodes (`--pattern "*"`) of the HPC cluster.
    - The injected command `echo vulnerable > /tmp/vuln.txt` is designed to create a file named `vuln.txt` in the `/tmp` directory of each node and write the word "vulnerable" into it.
  - Step 2: Wait for the `clusrun` command to complete. You might see output related to job submission and task execution.
  - Step 3: Access one or more of the HPC cluster nodes targeted by the `clusrun` command. You can use SSH or any other method to access the file system of these nodes.
  - Step 4: Check for the existence of the `/tmp/vuln.txt` file on the accessed nodes.
  - Step 5: If the file `/tmp/vuln.txt` exists, open it and verify its content. If the file contains the word "vulnerable", it confirms that the injected command was successfully executed on the cluster nodes, demonstrating the command injection vulnerability.
  - Expected result:
    - The command `clusrun new --host <your_hpc_acm_host> --pattern "*" "echo vulnerable > /tmp/vuln.txt"` executes successfully without errors from `clusrun`.
    - A file named `/tmp/vuln.txt` is created on each node of the HPC cluster.
    - The content of `/tmp/vuln.txt` on each node is "vulnerable".
    - This confirms successful command injection.