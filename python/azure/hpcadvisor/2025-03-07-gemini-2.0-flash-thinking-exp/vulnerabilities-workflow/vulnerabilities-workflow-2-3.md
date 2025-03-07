### Vulnerability List

* Vulnerability Name: Command Injection in Task Setup Script URL

* Description:
An attacker can inject arbitrary commands into the Azure Batch compute node by providing a malicious URL for the application setup script (`appsetupurl`) in the user input configuration file (`ui_defaults.yaml`).

    1. The HPC Advisor tool reads the user input configuration file, which can be provided via the `-u` flag in the CLI or through the GUI.
    2. The `appsetupurl` value from the user input is used in the `create_setup_task` function in `batch_handler.py` to construct a shell command.
    3. This shell command, which includes a `curl` command to download the script from the provided URL and `source` command to execute it, is then executed within an Azure Batch task on a compute node.
    4. If an attacker provides a malicious URL containing command injection payloads, these payloads will be executed by the shell on the compute node during the task setup phase.

* Impact:
    * **High**: Successful command injection allows the attacker to execute arbitrary shell commands with the privileges of the Azure Batch task user (which, by default, is an administrator).
    * This can lead to:
        * **Data Breaches**: Stealing sensitive data stored on or accessible to the compute node.
        * **System Compromise**: Modifying system configurations, installing backdoors, or further compromising the Azure Batch environment.
        * **Denial of Service (DoS)**: Disrupting the availability of the compute node or the entire Azure Batch pool by executing resource-intensive commands or crashing the system.
        * **Lateral Movement**: Potentially using the compromised compute node as a stepping stone to attack other resources within the Azure environment.

* Vulnerability Rank: Critical

* Currently Implemented Mitigations:
    * None: There is no input validation or sanitization implemented for the `appsetupurl` in the provided source code. The URL is directly used to construct shell commands in `batch_handler.py`.

* Missing Mitigations:
    * **Input Validation**: Implement strict validation for the `appsetupurl` in `utils.get_userinput_from_file` or earlier in the processing flow.  The validation should check for allowed URL schemes (e.g., `https://` for trusted sources) and potentially block or sanitize special characters and command injection sequences within the URL.
    * **Command Sanitization/Parameterization**: Instead of directly embedding the `appsetupurl` into the shell command string, use parameterized commands or safer command construction techniques to prevent interpretation of malicious characters as shell commands. For example, download the script to a fixed, safe location first, and then execute it separately.
    * **Principle of Least Privilege**:  While not directly mitigating command injection, running Batch tasks with the least necessary privileges can limit the impact of a successful exploit. However, the current code elevates task privileges to admin.

* Preconditions:
    * The attacker needs to be able to provide a malicious user input configuration file (`ui_defaults.yaml`) to the HPC Advisor tool. This could be achieved if:
        * The attacker has control over the user input file if the tool is used locally.
        * In a web-based deployment (GUI), if user input fields are not properly secured and allow injection of malicious URLs. Although no GUI code is provided in PROJECT FILES, the README.md indicates a web-based GUI exists.

* Source Code Analysis:
    1. **File: `/code/src/hpcadvisor/batch_handler.py`**:
    2. **Function: `create_setup_task(jobid, appsetupurl)`**:
    3. The `appsetupurl` parameter, directly derived from user input, is used to construct the `curl` command:
       ```python
       task_commands = [
           f"/bin/bash -c 'set ; cd {anfmountdir} ; curl -sLO {app_setup_url} ; source {script_name} ; {HPCADVISOR_FUNCTION_SETUP}'"
       ]
       ```
    4. The `curl -sLO {app_setup_url}` part of the command directly uses the user-provided URL.
    5. The `task_commands` list is then used to create a `batchmodels.TaskAddParameter` object:
       ```python
       task = batchmodels.TaskAddParameter(
           id=task_id,
           user_identity=user,
           command_line=task_commands[0], # User input directly embedded here
       )
       ```
    6. This task is added to the Azure Batch job, and the `command_line` is executed on the compute node.
    7. **Visualization:**
       ```
       UserInput (ui_defaults.yaml) --> appsetupurl --> create_setup_task() --> command_line (shell command with appsetupurl) --> Azure Batch Task Execution --> Command Injection
       ```

* Security Test Case:
    1. **Setup HPC Advisor**: Ensure the HPC Advisor tool is set up and runnable, either via CLI or GUI (if accessible).
    2. **Create Malicious User Input File**: Create a file named `malicious_ui_defaults.yaml` with the following content, replacing `<YOUR_SUBSCRIPTION_ID>` and `<YOUR_REGION>` with your Azure details:
       ```yaml
       subscription: <YOUR_SUBSCRIPTION_ID>
       skus: [Standard_HC44rs]
       rgprefix: vuln-test
       appsetupurl: "https://raw.githubusercontent.com/Azure/hpcadvisor/main/examples/matrixmult/appsetup_matrix.sh; touch /tmp/pwned" # Malicious URL with command injection
       nnodes: [1]
       appname: matrixmult
       tags:
         appname: matrixmult
         version: v1
       region: <YOUR_REGION>
       createjumpbox: false
       taskselector:
         policy: sequential
         paralleltasks: 1
       ppr: 100
       appinputs:
         appinteractions: 1
         appmatrixsize: [100]
       ```
       **Note**: The `appsetupurl` is modified to append `; touch /tmp/pwned` to the legitimate URL. This will attempt to execute the `touch /tmp/pwned` command after downloading and (attempting to) execute the legitimate script.
    3. **Run Deployment and Data Collection**: Execute the following commands in the HPC Advisor CLI:
       ```bash
       ./hpcadvisor deploy create -u malicious_ui_defaults.yaml
       DEPLOYMENT_NAME=$(./hpcadvisor deploy list | grep vuln-test) # Capture deployment name, may need adjustment based on output
       ./hpcadvisor collect -n $DEPLOYMENT_NAME -u malicious_ui_defaults.yaml
       ```
    4. **Access Compute Node (Optional - for verification)**: To definitively confirm command injection, you would ideally need to access one of the Azure Batch compute nodes.  Direct SSH access might not be enabled by default. If a jumpbox or similar access is set up, you can attempt to SSH into a compute node.
    5. **Check for File Creation**: If you can access a compute node, check for the existence of the file `/tmp/pwned`. If the file exists, the command injection was successful. Alternatively, observe the task logs (stdout/stderr) in Azure Batch for any signs of the `touch` command execution or errors that might indicate successful command injection.
    6. **Expected Result**: If the vulnerability is present, the `touch /tmp/pwned` command will be executed on the Azure Batch compute node, and the `/tmp/pwned` file will be created (if you have access to verify). Even without direct access, errors in task execution or unexpected behavior could indicate successful command injection.

This test case demonstrates how an attacker can leverage a malicious `appsetupurl` to inject and execute commands on the Azure Batch compute node.