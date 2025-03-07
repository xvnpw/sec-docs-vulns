- Vulnerability Name: Command Injection in `job.template.json` via `optionalParams`

- Description:
  1. An attacker crafts a malicious `job.template.json` file.
  2. This template defines a parameter, for example, `optionalParameters`, intended for users to provide optional arguments to the Blender command.
  3. The `job.template.json` uses the value of `optionalParameters` to construct the Blender command line within a task definition. This value is passed to the `blender_command` function in `/code/templates/blender/scripts/python-frame-splitter.py` via the environment variable `OPTIONAL_PARAMS`.
  4. The `blender_command` function constructs the command line by directly embedding the `optionalParams` value using Python's string formatting (`.format()`).
  5. An attacker can inject arbitrary shell commands by crafting a malicious value for `optionalParameters` within the `job.template.json`. When a user unknowingly uses this compromised template to run a job, the injected commands will be executed on the Azure Batch compute nodes.

- Impact:
  - Arbitrary command execution on Azure Batch compute nodes.
  - Full control over the compute node by the attacker.
  - Potential for data exfiltration from the compute node.
  - Possibility of malware installation on the compute node.
  - Potential to leverage compromised nodes for further attacks within the Azure environment.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
  - None. The code directly incorporates user-provided input into command execution without any visible sanitization or validation within the provided project files.

- Missing Mitigations:
  - Input Sanitization: Implement input sanitization for the `optionalParameters` parameter in `job.template.json`. Sanitize user-provided values to remove or escape shell-sensitive characters before incorporating them into command lines.
  - Parameter Validation: Validate the format and content of the `optionalParameters` parameter against an expected pattern to prevent unexpected or malicious inputs.
  - Secure Command Construction: Utilize secure command construction methods that avoid direct shell interpretation of user inputs. For instance, use libraries or methods that allow passing command arguments as a list, preventing shell injection vulnerabilities.
  - Principle of Least Privilege: Ensure that the tasks execute with the minimum necessary privileges to limit the impact of potential command injection vulnerabilities.

- Preconditions:
  - An attacker must be able to create or modify a `job.template.json` file, either by directly altering the repository or by distributing a malicious template to potential users.
  - A user with access to an Azure Batch account must use Batch Explorer or Azure Batch CLI extensions and unknowingly select and run a job based on the malicious `job.template.json` template.

- Source Code Analysis:
  1. File: `/code/templates/blender/scripts/python-frame-splitter.py`
  2. Function: `blender_command(blend_file, optionalParams)`
  3. Vulnerable Code Snippet:
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
  4. Analysis: The `optionalParams` variable, sourced from the environment variable `OPTIONAL_PARAMS`, is directly embedded into the shell command string using `.format()`. This method is susceptible to command injection because any shell commands within `optionalParams` will be interpreted and executed by the shell when the command is run on the compute node. There is no input validation or sanitization on `optionalParams` before it is used in the command.

- Security Test Case:
  1. Prepare a malicious `job.template.json` file (or modify an existing one). Locate the parameter definition that corresponds to the `OPTIONAL_PARAMS` environment variable (e.g., a parameter named "optionalParameters").
  2. Set the `defaultValue` of the "optionalParameters" parameter in `job.template.json` to a malicious payload designed to execute a simple command. For Linux-based compute nodes, use:  `; touch /tmp/pwned_template_vuln;`. For Windows-based nodes, use: `; type nul > C:\pwned_template_vuln.txt`.
  3. Using Batch Explorer or Azure Batch CLI extensions, submit a new job based on this crafted `job.template.json`. Choose to run the job on a pool.
  4. After the job has started and at least one task has transitioned to the 'running' and then 'completed' state, attempt to access the compute node's file system. If direct access isn't readily available, configure the task's output file settings to upload all files in the task's working directory upon completion.
  5. Examine the output files uploaded from the task's execution directory or, if node access is possible, directly check the compute node's file system.
  6. Verify the success of the command injection by confirming the creation of the file `/tmp/pwned_template_vuln` on Linux nodes or `C:\pwned_template_vuln.txt` on Windows nodes. The presence of this file confirms that the injected command within `optionalParameters` was successfully executed on the Azure Batch compute node, thus validating the command injection vulnerability.