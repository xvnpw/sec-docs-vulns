- Vulnerability Name: Command Injection in `clusrun` command

- Description:
    1. An attacker can use the `clusrun new` command to execute arbitrary commands on HPC cluster nodes.
    2. The `clusrun new` command takes a `command_line` argument, which specifies the command to be executed on the target nodes.
    3. This `command_line` argument is passed directly to the HPC Pack ACM API through the `hpc-acm-cli` tool without sanitization or validation.
    4. If the HPC Pack ACM API is vulnerable and executes the provided command without proper sanitization, it leads to command injection.
    5. An attacker can inject malicious commands by crafting a `command_line` argument that includes command separators (like `&&`, `;`, `||`, `|`) or shell metacharacters, allowing them to execute arbitrary code on the cluster nodes.

- Impact:
    - **Arbitrary command execution:** Successful exploitation allows an attacker to execute arbitrary commands on all nodes within the HPC cluster targeted by the `clusrun` command.
    - **Full node compromise:** Attackers can gain complete control over compromised nodes, potentially leading to:
        - **Data theft:** Accessing and exfiltrating sensitive data stored or processed on the cluster.
        - **Malware installation:** Installing malware, backdoors, or ransomware on the cluster nodes.
        - **Privilege escalation:** Escalating privileges within the compromised nodes and potentially the entire cluster.
        - **Denial of Service (DoS):** Disrupting cluster operations or rendering nodes unavailable.
        - **Lateral movement:** Using compromised nodes to further penetrate the network and access other resources.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - None. The provided code does not include any input sanitization or validation for the `command_line` argument in the `clusrun new` command. The command is directly passed to the underlying HPC Pack ACM API.

- Missing Mitigations:
    - **Input Sanitization on API side:** The HPC Pack ACM API needs to sanitize the `commandLine` input to prevent command injection. This could involve:
        - **Input validation:** Restricting allowed characters and command structures.
        - **Parameterization:** Using parameterized commands or prepared statements to separate commands from arguments.
        - **Sandboxing or containerization:** Executing commands in a restricted environment to limit the impact of successful injection.
    - **Input Validation on CLI side:** The `hpc-acm-cli` could implement client-side validation to warn users about potentially unsafe commands or suggest safer alternatives. However, client-side validation is not a sufficient mitigation on its own, as it can be bypassed.

- Preconditions:
    - **Access to `hpc-acm-cli` tool:** The attacker needs to have access to the `hpc-acm-cli` command-line tool.
    - **Valid HPC Pack ACM API credentials:** The attacker must have valid credentials (username/password or Azure Active Directory credentials) to authenticate and connect to the HPC Pack ACM API endpoint.
    - **Network connectivity:** The attacker's machine running `hpc-acm-cli` must be able to connect to the HPC Pack ACM API endpoint.

- Source Code Analysis:
    1. **`hpc_acm_cli/clus.py` - `Clusrun.new(self)` function:**
        ```python
        def new(self):
            if self.args.nodes:
                nodes = self.args.nodes.split()
            elif self.args.pattern:
                all = self.api.get_nodes(count=1000000)
                names = [n.name for n in all]
                nodes = match_names(names, self.args.pattern)
            else:
                raise ValueError('Either nodes or pattern parameter must be provided!')

            job = {
                "name": "Command@%s" % datetime.datetime.now().isoformat(),
                "targetNodes": nodes,
                "commandLine": self.args.command_line, # [CRITICAL]: User-provided command is directly used
            }
            job = self.api.create_clusrun_job(job = job) # API call with the command
            if self.args.short:
                self.show_in_short(job)
            else:
                self.show_progressing(job)
        ```
        - This function is responsible for handling the `clusrun new` subcommand.
        - It retrieves the `command_line` argument directly from `self.args.command_line`.
        - **Vulnerability:** The `command_line` argument, which is directly provided by the user, is included in the `job` dictionary without any sanitization. This `job` dictionary is then passed to the `create_clusrun_job` function of the API client (`self.api.create_clusrun_job(job = job)`).
        - The code does not perform any checks or sanitization on the `command_line` input before sending it to the API.

    2. **`hpc_acm_cli/command.py` - Argument Parsing:**
        ```python
        # ... in Clusrun.subcommands() ...
        {
            'name': 'new',
            'options': {
                'help': 'create a new clusrun job',
            },
            'params': [
                # ... other params ...
                {
                    'name': 'command_line',
                    'options': { 'help': 'command to run on nodes', 'metavar': 'command' }
                },
                # ... other params ...
            ],
        },
        ```
        - The `command_line` parameter is defined as a simple string argument using `argparse`.
        - `argparse` itself does not provide any built-in sanitization or command injection prevention mechanisms. It simply parses the command-line input as a string.

    **Visualization:**

    ```
    User Input (clusrun new --pattern "*" "malicious command")
        --> hpc_acm_cli (clus.py - Clusrun.new)
            --> Constructs job dictionary with unsanitized commandLine
                --> hpc_acm_api_client (API call create_clusrun_job)
                    --> HPC Pack ACM API Endpoint
                        --> [VULNERABILITY: Command Execution if API unsafely handles commandLine]
                            --> Cluster Nodes (malicious command executed)
    ```

- Security Test Case:
    1. **Prerequisites:**
        - Ensure you have `hpc-acm-cli` installed and configured to connect to a test HPC cluster where you have administrative rights or permission to run commands.
        - Have access to the cluster nodes to verify command execution (e.g., SSH access or shared file system).

    2. **Execute Malicious `clusrun` Command:**
        - Open a terminal and execute the following `clusrun` command, replacing `<your_hpc_acm_host>`, `<your_user>`, and `<your_password>` with your actual HPC ACM API endpoint and credentials.
        ```bash
        clusrun new --host <your_hpc_acm_host> --user <your_user> --password <your_password> --pattern "*" "mkdir /tmp/pwned_dir && touch /tmp/pwned_dir/pwned_file"
        ```
        - **Explanation of the malicious command:**
            - `mkdir /tmp/pwned_dir`: This command attempts to create a directory named `pwned_dir` in the `/tmp` directory on each target node.
            - `touch /tmp/pwned_dir/pwned_file`: This command attempts to create an empty file named `pwned_file` inside the newly created `pwned_dir` directory on each target node.
            - `&&`: This is a command separator. If the first command (`mkdir`) is successful, the second command (`touch`) will be executed.

    3. **Verify Command Execution on Cluster Nodes:**
        - Connect to one or more of the cluster nodes targeted by the `clusrun` command (e.g., via SSH).
        - Check if the directory `/tmp/pwned_dir` and the file `/tmp/pwned_dir/pwned_file` have been created.
        ```bash
        ls /tmp/pwned_dir/
        ```
        - If you see `pwned_file` listed, it indicates that the commands injected through `clusrun` were successfully executed on the cluster node, confirming the command injection vulnerability.

    4. **Expected Result:**
        - If the vulnerability exists, the commands will be executed on the cluster nodes, and you will find the `/tmp/pwned_dir` directory and `/tmp/pwned_dir/pwned_file` file on the targeted nodes.
        - If the vulnerability is mitigated (e.g., by proper input sanitization in the API), the commands might fail to execute, or the malicious parts of the command might be neutralized, and you will not find the created directory and file.

This test case demonstrates how an attacker can inject arbitrary commands using the `clusrun new` command, confirming the command injection vulnerability.