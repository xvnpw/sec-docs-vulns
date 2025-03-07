### Vulnerability: Command Injection via Malicious Templates and Parameters

*   **Vulnerability Name:** Command Injection via Malicious Templates and Parameters
*   **Description:**
    1.  An attacker gains write access to the `Azure/BatchLabs-data` repository or can manipulate template parameters during job submission.
    2.  The attacker modifies template files (e.g., `job.template.json`, `pool.template.json`) within the repository or crafts malicious input for template parameters when submitting a job through Azure Batch Explorer.
    3.  The malicious modifications can include injecting arbitrary commands into template parameters, task command lines, or scripts executed during job or task creation. This can be achieved through various methods, including:
        *   Modifying template files in the repository to include malicious commands directly in `commandLine` properties, scripts, or parameter default values.
        *   Crafting malicious input for "Optional Parameters" or other template parameters exposed in the Azure Batch Explorer UI during job submission.
        *   Exploiting vulnerabilities in the template expansion mechanism (e.g., `expand_template` function) to inject commands through specially crafted parameter values that are processed during template expansion.
    4.  A legitimate Azure Batch Explorer user uses the application, which fetches templates from the potentially compromised repository or accepts user-provided parameters.
    5.  When a job or pool is created using a malicious template or with malicious parameters, the injected commands are executed on the Azure Batch compute nodes within the user's Azure subscription. This execution occurs when Azure Batch service processes the job and tasks, running the commands defined in the template on the allocated compute nodes.
*   **Impact:**
    *   **Arbitrary Code Execution:** Successful command injection allows the attacker to execute arbitrary code on Azure Batch compute nodes.
    *   **Confidentiality Breach:** Access to sensitive data stored on the compute nodes, within the Azure Batch account, or in connected Azure services.
    *   **Integrity Violation:** Modification or deletion of data, including job outputs, logs, system files, and potentially data in connected storage accounts.
    *   **Availability Disruption:** Denial of service by crashing compute nodes, disrupting job execution, or consuming resources within the Azure subscription, leading to unexpected costs.
    *   **Lateral Movement:** Potential to pivot from compromised compute nodes to other Azure services or resources within the same environment, depending on the permissions of the Batch pool's identity.
    *   **Resource Hijacking:** Use of compute resources for malicious activities like cryptocurrency mining.
    *   **Reputational Damage:** Loss of trust in Azure Batch Explorer and related services due to security breaches.
*   **Vulnerability Rank:** Critical
*   **Currently Implemented Mitigations:**
    *   None within the provided project files. The repository serves as a data source and lacks input validation or sanitization. The code and scripts within the templates directly use user-controlled parameters in command construction without any security measures.
*   **Missing Mitigations:**
    *   **Input Sanitization and Validation:** Implement robust input sanitization and validation for all template parameters and configurations before using them to create Batch resources. This is crucial for parameters used in command construction, scripts, and any dynamically executed content. Sanitize or escape special characters and command injection sequences (e.g., `;`, `&`, `|`, `$`, `` ` ``, `\`, `>`, `<`).
    *   **Secure Command Construction:** Avoid directly concatenating user inputs into command strings. Use parameterized command execution or command builders that handle input escaping automatically. Employ secure coding practices to prevent command injection vulnerabilities during template processing and job submission.
    *   **Template Integrity Verification:** Implement a mechanism to verify the integrity and authenticity of templates fetched from the repository. This could involve digital signatures, checksums, or a trusted template registry to ensure that templates have not been tampered with.
    *   **Principle of Least Privilege:** Configure Azure Batch tasks and compute nodes to operate with the minimum necessary privileges. Restrict access to sensitive credentials and resources to limit the impact of successful command injection.
    *   **Secure Template Processing Engine:** Ensure that the template expansion mechanism used by functions like `expand_template` is secure and designed to prevent command injection. Consider using templating engines in a safe mode or with features to disable code execution within templates, or thoroughly sanitize inputs before template expansion.
    *   **Regular Security Audits and Penetration Testing:** Conduct regular security assessments, code reviews, and penetration testing to proactively identify and address potential vulnerabilities in template processing, job submission, and overall Azure Batch Explorer security.
*   **Preconditions:**
    *   **Attacker Access:** The attacker needs to gain write access to the `Azure/BatchLabs-data` GitHub repository or be able to manipulate template parameters during job submission through Azure Batch Explorer. Repository access could be through compromised credentials, insider threat, or vulnerabilities in access control. Parameter manipulation is possible through the Batch Explorer UI or by directly interacting with the API if available.
    *   **Vulnerable Template Usage:** A user must utilize Azure Batch Explorer and select a maliciously modified template from the gallery or submit a job with malicious parameters.
    *   **User Permissions:** The user must have sufficient permissions in their Azure subscription to create and run Batch jobs and pools for the vulnerability to be exploitable within their environment.
*   **Source Code Analysis:**
    *   **Template Processing and Parameter Handling:** The provided code, especially in `/code/runner/`, `/code/runner/custom_template_factory.py`, and `/code/runner/job_manager.py`, demonstrates how templates are loaded, parsed, and used to create Batch jobs. Scripts like `/code/ncj/blender/scripts/python-task-manager.py` and `/code/ncj/blender/scripts/python-frame-splitter.py` show how template parameters, particularly `OPTIONAL_PARAMS`, are incorporated into task command lines.
    *   **Unsanitized Parameter Injection:** The critical vulnerability lies in the direct and unsanitized use of template parameters in command construction. In `/code/ncj/blender/scripts/python-frame-splitter.py`, the `blender_command` function directly embeds the `optionalParams` environment variable (derived from user-controlled template parameters) into the Blender command string without any sanitization.
        ```python
        def blender_command(blend_file, optionalParams):
            # ...
            if os.environ["TEMPLATE_OS"].lower() == "linux":
                command = "blender -b \"{}/{}\" -P \"{}/scripts/python-task-manager.py\" -y -t 0 {}" # <--- optionalParams here
            else:
                command = "\"%BLENDER_2018_EXEC%\" -b \"{}\\{}\" -P \"{}\\scripts\\python-task-manager.py\" -y -t 0 {}" # <--- optionalParams here

            return command.format(
                os_specific_env("AZ_BATCH_JOB_PREP_WORKING_DIR"),
                blend_file,
                os_specific_env("AZ_BATCH_TASK_WORKING_DIR"),
                optionalParams # <--- User controlled input directly inserted
            )
        ```
    *   **Template Expansion Vulnerability:** The use of `batch_service_client.job.expand_template` in `/code/runner/job_manager.py` also presents a potential vulnerability if the `expand_template` function itself is susceptible to command injection. If the template expansion process interprets and executes commands embedded within parameter values, it could be exploited.
    *   **Visualization:**
        ```
        [GitHub Repository: Azure/BatchLabs-data] --(Malicious Template Files)--> [Azure Batch Explorer / User Input Parameters] --(Unsanitized Parameters)--> [Azure Batch Service] --(Job/Task Creation with Malicious Commands)--> [Compute Node] --(Command Execution)
        ```
*   **Security Test Case:**
    1.  **Setup:**
        *   Access to an Azure Batch account and an instance of Azure Batch Explorer that uses templates from the `Azure/BatchLabs-data` repository or a local test environment mimicking this setup.
        *   Choose a template that utilizes parameters in task commands, such as the Blender "Render movie on Windows Server" template.
    2.  **Malicious Modification (Template File):**
        *   Option 1 (Repository Modification): If possible, gain write access to a test branch of the `Azure/BatchLabs-data` repository. Modify a template file (e.g., `/code/ncj/blender/render-default-windows/job.template.json`). Inject a malicious command into the `commandLine` or a parameter used in the `commandLine`. For example, append `; touch /tmp/pwned` to the `commandLine`.
        *   Option 2 (Parameter Injection via UI): Alternatively, when submitting a job through Azure Batch Explorer, select a template and inject a malicious command into a parameter field exposed in the UI, such as "Optional Parameters" in the Blender template. For Windows pool use: `& echo pwned > C:\pwned.txt`. For Linux pool use: `; touch /tmp/pwned`.
    3.  **Job Submission:**
        *   Use Azure Batch Explorer to submit a job using the modified template (Option 1) or with the injected parameters (Option 2). Fill in other required job parameters as necessary.
    4.  **Verification (Command Execution):**
        *   After the job runs and tasks are executed, verify if the injected command was executed on a compute node.
        *   **Direct Node Access (Ideal):** If possible, connect to a compute node of the Batch pool. Check for the presence of the file created by the injected command (e.g., `/tmp/pwned` or `C:\pwned.txt`).
        *   **Task Logs (Alternative):** If direct node access is restricted, check the task logs in Azure Batch Explorer. Modify the injected command to output its result to stdout or stderr (e.g., `& whoami > output.txt & type output.txt` for Windows, or `; whoami > output.txt; cat output.txt` for Linux). Examine the task logs for the output of the injected command.
    5.  **Confirmation:**
        *   If the file created by the injected command exists on the compute node, or if the task logs contain the output of the injected command (e.g., the result of `whoami`), it confirms the successful command injection vulnerability.

This command injection vulnerability poses a critical risk to users of Azure Batch Explorer and their Azure environments. It should be addressed with the highest priority through input sanitization, secure command construction, and other recommended mitigations.