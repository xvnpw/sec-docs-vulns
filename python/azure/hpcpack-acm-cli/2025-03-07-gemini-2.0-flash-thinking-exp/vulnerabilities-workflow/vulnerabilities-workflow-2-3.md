- Vulnerability Name: Command Injection in `clusrun new` command
- Description:
    1. An attacker can use the `clusrun new` command to execute arbitrary commands on the HPC cluster nodes.
    2. The vulnerability occurs because the `command_line` argument, provided by the user, is directly passed to the HPC Pack ACM API without proper sanitization or validation.
    3. To trigger the vulnerability, an attacker can craft a malicious command and pass it as the `command_line` argument to the `clusrun new` command.
    4. For example, an attacker can use backticks, semicolons, or command chaining operators like `&&` or `||` to inject and execute arbitrary commands alongside the intended command.
    5. When the `clusrun new` command is executed, the HPC Pack ACM API will run the provided command on the target nodes.
    6. If the attacker-provided command includes malicious instructions, these instructions will be executed on the HPC cluster nodes with the privileges of the HPC Pack ACM agent.
- Impact:
    - **High**: Successful command injection can lead to complete compromise of the HPC cluster nodes.
    - An attacker could gain unauthorized access to sensitive data, modify system configurations, install malware, or disrupt cluster operations.
    - The impact is critical because HPC clusters often process highly sensitive and computationally intensive workloads, making them attractive targets for malicious actors.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None: The code does not implement any input sanitization, validation, or encoding on the `command_line` argument before passing it to the HPC Pack ACM API.
- Missing Mitigations:
    - **Input Sanitization**: Sanitize the `command_line` input to remove or escape potentially dangerous characters and command separators before passing it to the HPC Pack ACM API. Consider using parameterized commands or escaping shell metacharacters.
    - **Input Validation**: Validate the `command_line` input to ensure it conforms to expected patterns and lengths, and reject inputs that contain suspicious characters or command sequences.
    - **Principle of Least Privilege**: Ensure that the HPC Pack ACM agent running commands on the cluster nodes operates with the minimum necessary privileges to reduce the potential impact of command injection.
- Preconditions:
    - The attacker must have access to the `clusrun` command of the `hpc-acm-cli` application. This typically means the attacker needs to be a user who has installed and configured the `hpc-acm-cli` tool to connect to an HPC Pack cluster.
    - The HPC Pack ACM API endpoint must be accessible to the attacker's `hpc-acm-cli` instance.
- Source Code Analysis:
    1. File: `/code/hpc_acm_cli/clus.py`
    2. Function: `new(self)`
    3. Code snippet:
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
               "commandLine": self.args.command_line, # Vulnerable line
           }
           job = self.api.create_clusrun_job(job = job)
           # ...
       ```
    4. **Analysis:**
        - The `new` function in the `Clusrun` class handles the `clusrun new` subcommand.
        - It retrieves the target nodes based on either `--nodes` or `--pattern` arguments.
        - The crucial part is how it handles the `command_line` argument: `self.args.command_line`.
        - The value of `self.args.command_line` is directly taken from user input without any sanitization or validation.
        - This user-provided `command_line` is then directly embedded into the `job` dictionary under the key `"commandLine"`.
        - This `job` dictionary is then passed to `self.api.create_clusrun_job(job = job)`.
        - The `create_clusrun_job` function from the `hpc_acm_api` (which is not part of the provided code but assumed to be used) will eventually execute this `commandLine` on the target nodes.
        - **Vulnerability:** Since there is no sanitization of `self.args.command_line`, an attacker can inject arbitrary commands by including shell metacharacters in the `command_line` argument. For instance, using `&&`, `;`, `|`, or backticks.

- Security Test Case:
    1. **Precondition:** Ensure you have `hpc-acm-cli` installed and configured to connect to a test HPC Pack cluster. You should have valid credentials to execute `clusrun` commands.
    2. **Step 1:** Open a terminal where `hpc-acm-cli` is accessible in your PATH.
    3. **Step 2:** Execute the `clusrun new` command with a command injection payload. For example, to execute `whoami` and `hostname` commands on the cluster nodes, use the following command:
       ```bash
       clusrun new --pattern "*" "hostname && whoami"
       ```
       or
       ```bash
       clusrun new --pattern "*" "`whoami`"
       ```
    4. **Step 3:** Observe the output of the command.
    5. **Expected Result:**
        - The output should show the results of both `hostname` and `whoami` commands executed on each target node.
        - If the command injection is successful, you will see the output of the injected `whoami` command, which will typically be the user account under which the HPC Pack ACM agent is running on the cluster nodes.
        - This confirms that the attacker can execute arbitrary commands on the HPC cluster nodes by injecting commands into the `command_line` argument of the `clusrun new` command.