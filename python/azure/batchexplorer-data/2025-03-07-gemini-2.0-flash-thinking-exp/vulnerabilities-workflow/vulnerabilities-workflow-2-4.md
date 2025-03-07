- Vulnerability Name: Command Injection via Template Parameter
- Description:
    1. An attacker modifies a job template file (e.g., `/code/ncj/blender/render-default-windows/job.template.json`) within the repository.
    2. The attacker injects a malicious command into a template parameter value that is used within a command line or script executed by the Azure Batch task. For example, in a `commandLine` property within the `job.template.json`, an attacker could insert a command injection payload like `$(malicious_command)` or backticks `` `malicious_command` ``, hoping that the template expansion mechanism will evaluate and execute it.
    3. When the Azure Batch Explorer application (or the `azext-batch` library used by `runner.py`) processes this modified template using the `expand_template` function, it might interpret and execute the injected command during job or task creation.
    4. This can lead to arbitrary command execution on the Azure Batch compute node when the job is run, potentially allowing the attacker to take control of the compute node or exfiltrate data.
- Impact:
    - Code execution on Azure Batch compute nodes.
    - Unauthorized access to resources within the compute environment.
    - Potential data exfiltration from the compute nodes.
    - Potential compromise of the Azure Batch account or linked resources if the compute node has access to sensitive credentials or permissions.
- Vulnerability Rank: High
- Currently Implemented Mitigations: None identified in the provided project files. The code relies on template expansion without apparent input validation or sanitization of parameters used in commands.
- Missing Mitigations:
    - Input validation and sanitization: Implement strict validation and sanitization of all template parameters, especially those used in command lines or scripts. Sanitize or escape special characters and command injection sequences before template expansion.
    - Secure template processing: Ensure that the template expansion mechanism used by `expand_template` function is secure and designed to prevent command injection. Consider using templating engines in a safe mode or with features to disable code execution within templates.
    - Principle of least privilege: Configure Azure Batch compute nodes with the least privileges necessary. Restrict access to sensitive credentials and resources to minimize the impact of potential compromise.
    - Content Security Policy (CSP): If Azure Batch Explorer has a user interface that renders content from these templates, implement CSP to mitigate potential client-side injection vulnerabilities. However, based on the description the main threat is server-side command execution on compute nodes.
- Preconditions:
    - The attacker must be able to modify the template files within the repository. This could be achieved by compromising a contributor account, exploiting a vulnerability in the repository's access control, or if the repository is inadvertently configured to allow public write access.
    - The Azure Batch Explorer application must be configured to fetch and process templates from this repository.
    - The `expand_template` function (or the underlying templating mechanism in `azext-batch`) must be susceptible to command injection when processing template parameters.
- Source Code Analysis:
    1. File: `/code/runner/job_manager.py`
    2. Function: `submit_job`
    3. Line: `job_json = batch_service_client.job.expand_template(template, parameters)`
    ```python
    def submit_job(self, batch_service_client: batch.BatchExtensionsClient, template: str, parameters: str):
        """
        Submits a Job against the batch service.
        ...
        """
        try:
            job_json = batch_service_client.job.expand_template( # Vulnerable point
                template, parameters)
            job_parameters = batch_service_client.job.jobparameter_from_json(
                job_json)
            batch_service_client.job.add(job_parameters)
        except batchmodels.batch_error.BatchErrorException as err:
            ...
    ```
    - The `expand_template` function from `azext.batch` is used to combine the `template` (loaded from files in `/code/ncj/`) and `parameters` (also potentially influenced by files in `/code/ncj/`).
    - If the `expand_template` function performs string interpolation or uses a templating engine without proper sanitization, it might be vulnerable to command injection.
    - The content of `template` and `parameters` is directly derived from files in the repository, which are potentially modifiable by attackers.
    - The expanded `job_json` is then used to create and submit an Azure Batch job, which will execute tasks on compute nodes. If the injected command is part of a task's `commandLine`, it will be executed on the compute node.
- Security Test Case:
    1. **Clone the repository locally.**
    2. **Navigate to the Blender template directory:** `/code/ncj/blender/render-default-windows/`.
    3. **Modify `job.template.json`:** Edit the `job.template.json` file. Locate the `commandLine` property within the `tasks` definition. For example, find a line like:
       ```json
       "commandLine": "...",
       ```
       Modify it to inject a simple command injection payload. For Linux based pools, you could append `; touch /tmp/pwned` to the existing command. For example, if the original `commandLine` was:
       ```json
       "commandLine": "/bin/bash -c 'blender ... {blendFile} ...'",
       ```
       Change it to:
       ```json
       "commandLine": "/bin/bash -c 'blender ... {blendFile} ... ; touch /tmp/pwned'",
       ```
       Alternatively, if template parameters are used in the command, inject into a parameter. For example, if the template uses a parameter `{optionalParams}` in the `commandLine`:
       ```json
       "commandLine": "/bin/bash -c 'blender ... {blendFile} ... {optionalParams}'",
       ```
       And if `optionalParams` is defined as a parameter. You could try to inject command in the default value of `optionalParams` in `job.template.json` or in a separate parameter file if used.
    4. **Run the `runner.py` script:** Execute the `runner.py` script, providing the modified `job.template.json` and corresponding parameter file (or if you modified `job.template.json` parameters directly, use the original parameter file or a modified one). Ensure you have the required environment variables set as described in `/code/runner/ReadMe.md`. For example:
       ```bash
       python ./code/runner/runner.py "Tests/TestConfiguration.json" "<BatchAccountName>" "<BatchAccountKey>" "<BatchAccountUrl>" "<BatchAccountSub>" "<StorageAccountName>" "<StorageAccountKey>" "<ServicePrincipalCredentialsClientID>" "<ServicePrincipalCredentialsSecret>" "<ServicePrincipalCredentialsTenant>" "<ServicePrincipalCredentialsResouce>"
       ```
       You might need to adjust the `TestConfiguration.json` to point to your modified template. Or you can directly modify the template path in `runner.py` for testing purposes.
    5. **Check for command execution:** After the test job completes (or fails), you need to verify if the injected command `touch /tmp/pwned` was executed on the Azure Batch compute node.
       - **Ideally, access the compute node:** If you have access to the compute node (e.g., through Batch Explorer or Azure portal), check if the file `/tmp/pwned` exists. If it does, the command injection is successful.
       - **Check task logs (less reliable):** Sometimes, the output of injected commands might appear in task logs (stdout or stderr). Check the task logs for any indication that the `touch /tmp/pwned` command or similar injected command was executed. However, this is less reliable as output might be suppressed or not captured in logs.
    6. **Expected result:** If the file `/tmp/pwned` is created on the compute node, or if there is clear evidence in logs of command execution, it confirms the command injection vulnerability.