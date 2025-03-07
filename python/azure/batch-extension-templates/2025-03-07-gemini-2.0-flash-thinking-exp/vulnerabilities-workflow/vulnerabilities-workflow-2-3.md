## Vulnerability List

### 1. Command Injection via Unsanitized Job Task Command Line Parameters

*   **Description:**
    1.  An attacker crafts a malicious JSON job template.
    2.  This template includes a parameter (e.g., `blendFile`, `optionalParams` in Blender templates, or similar in other templates) that is directly incorporated into the command line of a job task.
    3.  The attacker injects malicious commands within the parameter value (e.g., using backticks, semicolons, or command separators like `&` or `|`).
    4.  When a victim uses this template through Batch Explorer or Azure Batch CLI extensions, the malicious JSON template is parsed.
    5.  The injected malicious commands are embedded into the task command line without proper sanitization.
    6.  The Azure Batch service executes the task on a compute node.
    7.  Due to the command injection, the malicious commands are executed on the compute node with the privileges of the Batch task.

*   **Impact:**
    *   **High/Critical:** Arbitrary command execution on Azure Batch compute nodes. An attacker can gain full control of the compute node, potentially leading to data exfiltration, malware installation, denial of service, or further attacks on the Azure Batch environment or other connected systems. The impact is critical as it allows for complete compromise of the compute resource.

*   **Vulnerability Rank:** Critical

*   **Currently Implemented Mitigations:**
    *   None identified in the provided project files. The templates are designed to be parameterized, but there is no evidence of input sanitization or validation within the templates or the runner code to prevent command injection.

*   **Missing Mitigations:**
    *   **Input Sanitization:** Implement robust input sanitization for all template parameters that are used in command lines. This should include escaping or removing shell-sensitive characters and sequences to prevent command injection.
    *   **Parameter Validation:** Validate the format and content of user-provided parameters against expected patterns. For example, validate file paths, frame ranges, and other parameters to ensure they conform to expected values and do not contain malicious payloads.
    *   **Principle of Least Privilege:** Ensure that Batch tasks run with the minimum necessary privileges to limit the impact of a successful command injection. However, this is a general security best practice and not a direct mitigation for command injection itself.
    *   **Security Auditing:** Implement logging and auditing of template usage and parameter values to detect and respond to potential malicious activities.

*   **Preconditions:**
    *   An attacker needs to be able to create or modify JSON templates used by Batch Explorer or Azure Batch CLI extensions. This could be achieved by compromising a template repository, contributing a malicious template to a public gallery, or tricking a victim into using a locally crafted malicious template.
    *   The victim needs to use Batch Explorer or Azure Batch CLI extensions to process and execute the malicious template.

*   **Source Code Analysis:**

    1.  **Template Parameterization:** The project heavily relies on JSON templates with parameters. Files like `/code/templates/blender/job.template.json` (and similar templates for other applications) demonstrate the use of parameters within task command lines. For example, in `/code/templates/blender/scripts/python-frame-splitter.py`, the `blender_command` function constructs a command line using parameters like `blend_file` and `optionalParams` from environment variables, which are in turn derived from template parameters.

        ```python
        def blender_command(blend_file, optionalParams):
            """
            Gets the operating system specific blender exe.
            """
            if os.environ["TEMPLATE_OS"].lower() == "linux":
                command = "blender -b \"{}/{}\" -P \"{}/scripts/python-task-manager.py\" -y -t 0 {}"
            else:
                command = "\"%BLENDER_2018_EXEC%\" -b \"{}\\{}\" -P \"{}\\scripts\\python-task-manager.py\" -y -t 0 {}"

            return command.format(
                os_specific_env("AZ_BATCH_JOB_PREP_WORKING_DIR"),
                blend_file,
                os_specific_env("AZ_BATCH_TASK_WORKING_DIR"),
                optionalParams
            )
        ```

    2.  **Parameter Propagation to Environment Variables:** Scripts like `/code/templates/blender/scripts/python-task-manager.py` and `/code/templates/blender/scripts/python-frame-splitter.py` use `os.environ` to access parameters. These environment variables are set based on the template parameters during task creation, as seen in `/code/templates/blender/scripts/python-frame-splitter.py` in the `create_task` function:

        ```python
        def create_task(frame, task_id, job_id, tile_num, current_x, current_y):
            # ...
            environment_settings=[
                models.EnvironmentSetting("X_TILES", os.environ["X_TILES"]),
                models.EnvironmentSetting("Y_TILES", os.environ["Y_TILES"]),
                models.EnvironmentSetting("CROP_TO_BORDER", os.environ["CROP_TO_BORDER"]),
                models.EnvironmentSetting("OUTPUT_FORMAT", os.environ["OUTPUT_FORMAT"]),
                models.EnvironmentSetting("BLEND_FILE", os.environ["BLEND_FILE"]), # Parameter from template
                models.EnvironmentSetting("CURRENT_FRAME", str(frame)),
                models.EnvironmentSetting("CURRENT_TILE", str(tile_num)),
                models.EnvironmentSetting("CURRENT_X", str(current_x)),
                models.EnvironmentSetting("CURRENT_Y", str(current_y))
            ],
            # ...
        ```
        The `BLEND_FILE` environment variable, derived from a template parameter, is used in the `blender_command`. If the value of `BLEND_FILE` or `optionalParams` is not sanitized, it can lead to command injection.

    3.  **No Sanitization in Code:** Reviewing the provided code, there is no explicit sanitization or validation of template parameter values before they are incorporated into command lines. The code focuses on template loading, parameter substitution, and task creation, but lacks security measures to prevent command injection. The `custom_template_factory.py` focuses on template manipulation but not sanitization. The `runner.py` and `test_manager.py` handle test execution but do not introduce sanitization steps.

*   **Security Test Case:**

    1.  **Craft a Malicious JSON Job Template:** Create a modified `job.template.json` (e.g., for Blender) or use an existing one. In the `parameters` section, locate a parameter that is used in the task command line (e.g., `blendFile` or `optionalParams`).
    2.  **Inject Malicious Command:** Modify the default value or provide a malicious value for the chosen parameter. For example, if targeting `optionalParams` in a Blender template, set its value to:
        ```json
        "; touch /tmp/pwned ;"
        ```
        or
        ```json
        "`touch /tmp/pwned`"
        ```
        or for Windows:
        ```json
        "& echo pwned > C:\\\\Windows\\\\Temp\\\\pwned.txt &"
        ```
        The exact injection syntax might need to be adjusted based on the shell and command being executed on the compute node (Linux `bash` or Windows `cmd`).
    3.  **Use Batch Explorer or Azure Batch CLI Extensions:** Use Batch Explorer or Azure Batch CLI extensions to submit a job using the modified malicious template. Configure other necessary parameters (e.g., pool, input data) as needed for the template to be processed.
    4.  **Monitor Task Execution:** After submitting the job, monitor the task execution in the Azure Batch account.
    5.  **Verify Command Injection:** After the task completes (or potentially while it is running if you can access node files during task execution), check if the injected command was executed on the compute node. For the example above, check if the file `/tmp/pwned` (on Linux) or `C:\Windows\Temp\pwned.txt` (on Windows) was created on the compute node. You might need to use Batch Explorer or Azure CLI to access task files or remotely connect to the compute node (if allowed and configured) to verify the file creation. Alternatively, you can modify the injected command to exfiltrate data to an external attacker-controlled server to confirm execution if direct node access is restricted.