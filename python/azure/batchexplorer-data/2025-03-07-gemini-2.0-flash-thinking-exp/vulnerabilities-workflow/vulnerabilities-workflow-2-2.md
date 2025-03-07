- Vulnerability Name: Command Injection via Template Parameters in Task Commands

- Description:
    An attacker can inject arbitrary commands into the Azure Batch tasks executed by Azure Batch Explorer. This vulnerability arises because the application uses template parameters to construct command lines for tasks without sufficient sanitization. Specifically, the `OPTIONAL_PARAMS` environment variable, which is derived from user-provided template parameters, is directly incorporated into the command line executed by Blender tasks. By manipulating the `OPTIONAL_PARAMS` value within a job template, an attacker can insert malicious commands that will be executed on the compute nodes within the Azure Batch pool.

    Steps to trigger the vulnerability:
    1. An attacker accesses the Azure Batch Explorer application.
    2. The attacker navigates to the template gallery and selects a template that utilizes task commands, for example, the Blender "Render movie on Windows Server" template.
    3. When submitting a job using this template, the attacker modifies the "Optional Parameters" field in the job submission form.
    4. The attacker injects a malicious command into the "Optional Parameters" field. For example, they could insert a command like `; touch /tmp/pwned` for Linux-based pools or `& echo pwned > C:\pwned.txt` for Windows-based pools.
    5. The attacker submits the job.
    6. When the Azure Batch Explorer processes the job template and creates tasks, it incorporates the attacker-supplied "Optional Parameters" directly into the command line for the Blender task.
    7. The Azure Batch service executes the task on a compute node, and the injected malicious command is executed along with the intended Blender command.

- Impact:
    Successful command injection allows an attacker to execute arbitrary code on the Azure Batch compute nodes. This could lead to:
    - **Confidentiality breach:** Access to sensitive data stored on the compute nodes or within the Azure Batch account.
    - **Integrity violation:** Modification or deletion of data, including job outputs, logs, or system files.
    - **Availability disruption:** Denial of service by crashing compute nodes, disrupting job execution, or consuming resources.
    - **Lateral movement:** Potential to pivot from compromised compute nodes to other Azure services or resources within the same environment.
    - **Resource hijacking:** Use of compute resources for cryptocurrency mining or other malicious activities.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    No mitigations are currently implemented in the provided code. The application directly incorporates user-provided parameters into command lines without any sanitization or validation.

- Missing Mitigations:
    - **Input sanitization:** Implement robust input sanitization and validation for all template parameters, especially those used in command construction.  Specifically, escape or remove characters that could be used for command injection (e.g., `;`, `&`, `|`, `$`, `` ` ``, `\`, `>` ,`<`).
    - **Principle of least privilege:** Ensure that the Azure Batch tasks and compute nodes operate with the minimum necessary privileges to limit the impact of a successful command injection.
    - **Secure command construction:** Avoid directly concatenating user inputs into command strings. Use parameterized command execution or command builders that handle input escaping automatically.
    - **Content Security Policy (CSP):** If Azure Batch Explorer has a web interface, implement a strong CSP to mitigate potential cross-site scripting (XSS) vulnerabilities, which could be chained with command injection. While not directly related to command injection in backend, it's a good practice to secure the overall application.
    - **Regular security audits and penetration testing:** Conduct regular security assessments to identify and address potential vulnerabilities proactively.

- Preconditions:
    - The attacker needs to be able to interact with the Azure Batch Explorer application and submit jobs using templates. In a typical scenario, this implies the attacker is a user of the Batch Explorer application, potentially with access to an Azure Batch account. For the provided context of public templates, the attacker needs to be able to use an instance of Azure Batch Explorer that consumes these templates.

- Source Code Analysis:

    1. **`File: /code/ncj/blender/scripts/python-task-manager.py`**: This script is executed within the Blender task on the compute node.
    2. **`command_line = blender_command(blend_file, optionalParams)` in `File: /code/ncj/blender/scripts/python-frame-splitter.py`**: This line constructs the Blender command. The `optionalParams` variable is passed to the `blender_command` function.
    3. **`optionalParams = os.environ["OPTIONAL_PARAMS"]` in `File: /code/ncj/blender/scripts/python-frame-splitter.py`**: This line retrieves the `OPTIONAL_PARAMS` environment variable. This environment variable is set based on the "Optional Parameters" field in the job template.
    4. **`def blender_command(blend_file, optionalParams):` in `File: /code/ncj/blender/scripts/python-frame-splitter.py`**: This function constructs the Blender command.  Crucially, the `optionalParams` argument is directly embedded into the command string without any sanitization:
        ```python
        def blender_command(blend_file, optionalParams):
            """
            Gets the operating system specific blender exe.
            """
            if os.environ["TEMPLATE_OS"].lower() == "linux":
                command = "blender -b \"{}/{}\" -P \"{}/scripts/python-task-manager.py\" -y -t 0 {}" # <--- optionalParams here
            else:
                command = "\"%BLENDER_2018_EXEC%\" -b \"{}\\{}\" -P \"{}\\scripts\\python-task-manager.py\" -y -t 0 {}" # <--- optionalParams here

            return command.format(
                os_specific_env("AZ_BATCH_JOB_PREP_WORKING_DIR"),
                blend_file,
                os_specific_env("AZ_BATCH_TASK_WORKING_DIR"),
                optionalParams # <--- User controlled input is directly inserted
            )
        ```
    5. **`File: /code/runner/custom_template_factory.py`, `File: /code/runner/job_manager.py`, `File: /code/runner/runner.py`**: These runner scripts are responsible for processing the templates and submitting jobs to Azure Batch. While they handle template loading and parameter setting, they do not include any input sanitization for the "Optional Parameters" or other relevant fields. The parameters from the template are directly passed to the Azure Batch service, which in turn sets environment variables that are then read by the task scripts.

    **Visualization:**

    ```
    User Input (Optional Parameters in Template) --> Azure Batch Explorer (Job Submission) --> Azure Batch Service (Task Creation) --> Compute Node (Task Execution) --> python-frame-splitter.py --> blender_command() --> Command Construction with unsanitized optionalParams --> Command Execution in Shell
    ```

- Security Test Case:

    1. **Prerequisites:**
        - Access to an instance of Azure Batch Explorer that uses the provided templates.
        - An Azure Batch account configured in Azure Batch Explorer.
        - Select the Blender "Render movie on Windows Server" template (or similar template that uses `OPTIONAL_PARAMS`).

    2. **Steps:**
        a. Open Azure Batch Explorer and navigate to the "Gallery".
        b. Select the "Blender" application.
        c. Choose "Render movie on Windows Server" (or similar).
        d. Select "Run job with auto-pool" (or "Run job with pre-existing pool").
        e. Fill in the required fields like "Pool Name", "Job Name", "Input Data", "Blend File", "Outputs" as described in the `blender/readme.md`.
        f. In the "Optional Parameters" field, inject the following malicious command for Windows pool: `& echo pwned > C:\pwned.txt`. For Linux pool use: `; touch /tmp/pwned`.
        g. Click "Submit" to submit the job.
        h. Wait for the job to complete.
        i. **Verification (Windows Pool):** Connect to the compute node (if possible, or check output logs if they reveal file system changes). Check if the file `C:\pwned.txt` exists on the compute node. If the file exists and contains "pwned", the command injection is successful.
        j. **Verification (Linux Pool):** Connect to the compute node (if possible, or check output logs if they reveal file system changes). Check if the file `/tmp/pwned` exists on the compute node. If the file exists, the command injection is successful.
        k. **Alternative Verification (If direct node access is restricted):** Modify the injected command to output the result to stdout or stderr and check the task logs in Azure Batch Explorer for the command output. For example, in "Optional Parameters" use: `& cmd /c whoami > output.txt & type output.txt` (Windows) or `; whoami > output.txt; cat output.txt` (Linux). Check the task's `stdout.txt` log for the output of the `whoami` command.