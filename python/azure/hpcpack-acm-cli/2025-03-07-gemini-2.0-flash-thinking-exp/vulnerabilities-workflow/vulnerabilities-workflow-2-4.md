- **Vulnerability Name:** Command Injection in `clusrun new` command

- **Description:**
    - An attacker can inject arbitrary commands into the `clusrun new` command via the `command_line` parameter.
    - Step 1: An attacker uses the `clusrun new` command with the `--pattern` parameter to specify target nodes and provides a malicious command in the `command_line` parameter. For example: `clusrun new --pattern "*" "vulnerable_command; malicious_command"`.
    - Step 2: The `hpc-acm-cli` tool constructs a job request and sends it to the HPC Pack ACM API without sanitizing the `command_line` input.
    - Step 3: The HPC Pack ACM API receives the request and executes the provided `command_line` on the target nodes.
    - Step 4: Due to the lack of input sanitization, the HPC Pack ACM API executes both the intended command (`vulnerable_command`) and the attacker-injected malicious command (`malicious_command`) on the cluster nodes.

- **Impact:**
    - **High:** Successful command injection allows an attacker to execute arbitrary commands on all nodes within the HPC cluster targeted by the `clusrun` command.
    - This can lead to:
        - **Confidentiality breach:** Access to sensitive data stored on the cluster nodes.
        - **Integrity violation:** Modification or deletion of critical system files or data.
        - **Availability disruption:** Denial of service by crashing nodes or disrupting cluster operations.
        - **Lateral movement:** Further exploitation of the cluster infrastructure from compromised nodes.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - None: The code does not implement any input sanitization or validation for the `command_line` parameter in the `clusrun new` command within the `hpc-acm-cli` tool itself. The code directly passes the user-supplied `command_line` to the HPC Pack ACM API.

- **Missing Mitigations:**
    - **Input Sanitization:** The `hpc-acm-cli` tool should sanitize the `command_line` input to prevent command injection. This could involve:
        - **Whitelisting safe characters:** Allowing only alphanumeric characters and a limited set of safe symbols.
        - **Blacklisting dangerous characters/commands:**  Filtering out characters and command sequences commonly used in command injection attacks (e.g., `;`, `&`, `|`, `$()`, backticks, `>` , `<` , etc.).
        - **Parameterization:** If possible, the underlying API should support parameterized commands to separate commands from arguments, preventing injection. However, based on the code, it seems the API takes the command as a string. In this case, robust sanitization on the client side is crucial.
    - **Input Validation:** Validate the `command_line` input to ensure it conforms to expected patterns or formats.
    - **Principle of Least Privilege:** Ensure that the account under which the `hpc-acm-cli` tool and the HPC Pack ACM API run has the minimum necessary privileges to perform their functions. This can limit the impact of a successful command injection.

- **Preconditions:**
    - The attacker needs to have access to the `hpc-acm-cli` tool and be able to execute commands. This typically means having valid credentials to interact with the HPC Pack cluster's ACM API, or exploiting a different vulnerability to gain access to a system where `hpc-acm-cli` is configured.
    - The HPC Pack ACM API must be vulnerable to command execution based on the `commandLine` parameter it receives from the client. This analysis assumes that the API itself does not perform sufficient sanitization and directly executes the provided command.

- **Source Code Analysis:**
    - **File:** `/code/hpc_acm_cli/clus.py`
    - **Function:** `Clusrun.new(self)`
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
            "commandLine": self.args.command_line, # User-controlled input is directly used here
        }
        job = self.api.create_clusrun_job(job = job) # Job is sent to API
        if self.args.short:
            self.show_in_short(job)
        else:
            self.show_progressing(job)
    ```
    - **Flow:**
        1. The `Clusrun.new()` function is called when the `clusrun new` subcommand is executed.
        2. It retrieves the target nodes based on either `--nodes` or `--pattern` arguments.
        3. **Vulnerability Point:** It directly uses `self.args.command_line`, which is directly taken from user input, and assigns it to the `"commandLine"` key in the `job` dictionary.
        4. This `job` dictionary is then passed to `self.api.create_clusrun_job(job = job)`.
        5. The `create_clusrun_job` function (part of the `hpc_acm_cli` library interacting with the API) sends this job request to the HPC Pack ACM API.
        6. **No sanitization or validation** is performed on `self.args.command_line` within the `hpc-acm-cli` code before sending it to the API.
    - **Visualization:**
    ```
    [User Input: clusrun new --pattern "*" "malicious_command"] --> clus.py (Clusrun.new) --> job = {"commandLine": "malicious_command", ...} --> hpc_acm_cli API Client --> HPC Pack ACM API --> Command Execution on Cluster Nodes
    ```

- **Security Test Case:**
    - **Step 1:** Install the `hpc-acm-cli` tool and configure it to connect to a test HPC Pack cluster. Ensure you have necessary credentials to execute `clusrun` commands.
    - **Step 2:** Execute the following command to attempt command injection through the `command_line` parameter:
        ```bash
        clusrun new --pattern "*" "hostname && touch /tmp/pwned_clusrun_cmd_injection"
        ```
        - This command is intended to execute `hostname` (to verify command execution) and then create a file named `pwned_clusrun_cmd_injection` in the `/tmp` directory on each target node.
    - **Step 3:** Check the output of the `clusrun` command. It should execute successfully without errors related to command syntax.
    - **Step 4:** Access one or more of the target nodes (specified by `--pattern "*"`, which should be all nodes) and check if the file `/tmp/pwned_clusrun_cmd_injection` exists.
    - **Step 5:** If the file `/tmp/pwned_clusrun_cmd_injection` exists on the target nodes, it confirms that the injected command (`touch /tmp/pwned_clusrun_cmd_injection`) was successfully executed, demonstrating a command injection vulnerability.
    - **Expected Result:** The file `/tmp/pwned_clusrun_cmd_injection` should be created in the `/tmp` directory on the cluster nodes, proving successful command injection.

This vulnerability allows for arbitrary command execution on HPC cluster nodes, posing a significant security risk. Immediate mitigation through input sanitization is strongly recommended.