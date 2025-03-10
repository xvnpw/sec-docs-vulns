- Vulnerability Name: Command Injection via Experiment Configuration

- Description:
  An attacker can inject arbitrary commands into the Docker container by crafting a malicious experiment configuration file. When a user runs `caliban run` with this crafted configuration file using the `--experiment_config` flag, the values from the configuration are processed and converted into command-line arguments for the user's script within the Docker container. If these values are not properly sanitized, an attacker can inject malicious commands that will be executed within the container's shell.

  Steps to trigger vulnerability:
  1. Create a malicious experiment configuration file (e.g., `malicious_config.json`). This file should contain a key-value pair where the value includes a command to be injected. For example:
     ```json
     {
       "experiment_config": {
         "learning_rate": ["0.01"],
         "model_name": ["`touch /tmp/pwned`"]
       }
     }
     ```
  2. Trick a user into running `caliban run` with the malicious configuration file:
     ```bash
     caliban run --experiment_config malicious_config.json --nogpu mnist.py
     ```
  3. Caliban will parse the `malicious_config.json` and expand it into a set of commands.
  4. The value associated with `model_name` parameter, which is `"`touch /tmp/pwned`"`, will be passed as a command-line argument to the user's script within the Docker container.
  5. If the user's script or Caliban itself executes these arguments in a shell without proper sanitization, the injected command `touch /tmp/pwned` will be executed, creating a file `/tmp/pwned` inside the Docker container.

- Impact:
  * **High**. Successful exploitation of this vulnerability allows arbitrary command execution within the Docker container. This can lead to:
    * **Data Breaches**: Access to sensitive data within the container environment.
    * **Container Takeover**: Full control over the Docker container, allowing further malicious activities.
    * **Lateral Movement**: Potential to pivot to other systems if the Docker container has network access.
    * **Resource Manipulation**: Unauthorized modification or deletion of data and resources within the container.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
  * **None**. The code analysis shows no explicit sanitization of the experiment configuration values before they are passed as command-line arguments.

- Missing Mitigations:
  * **Input Sanitization**: Implement robust input sanitization for all values read from the experiment configuration file. This should include:
    * **Escaping Shell Metacharacters**:  Ensure that any shell metacharacters (e.g., ` ` `$` `&` `|` `;` `<` `>` `\` `"` `'` `{` `}` `(` `)`) within the configuration values are properly escaped before being passed to the shell.
    * **Validation of Input Values**: Implement strict validation rules for configuration values, ensuring they conform to expected formats and do not contain unexpected or malicious characters.
    * **Principle of Least Privilege**:  Run the Docker container with the least privileges necessary to perform its intended tasks. This limits the impact of any command injection vulnerability.

- Preconditions:
  * User must be tricked into running `caliban run` with a maliciously crafted experiment configuration file via `--experiment_config` flag.
  * The user's script or Caliban itself must execute the command-line arguments in a shell without proper sanitization.

- Source Code Analysis:
  1. **`caliban/config/experiment.py:experiment_to_args(m: Experiment)`**: This function converts the experiment configuration dictionary `m` into a list of command-line arguments. It iterates through the dictionary and formats keys and values into strings suitable for command-line arguments.
  2. **`caliban/platform/run.py:execute_jobs(job_specs: Iterable[JobSpec])`**: This function iterates through `job_specs`. Each `job_spec` contains the command-line arguments generated by `experiment_to_args`.
  3. **`caliban/platform/run.py:_create_job_spec_dict(...)`**: This function constructs the dictionary `JobSpec` which includes the command to be executed in the Docker container. The `cmd_args` generated by `experiment_to_args` are directly appended to the `base_cmd`.
  4. **`caliban/util/fs.py:capture_stdout(cmd: List[str], ...)`**: This function executes the command using `subprocess.Popen(cmd, ...)`. The `cmd` list, which includes the unsanitized arguments from the experiment config, is passed directly to `subprocess.Popen`.
  5. **Vulnerability Point**: The lack of sanitization between step 1 and step 4 creates a command injection vulnerability. Malicious values in the `experiment_config` can be interpreted as shell commands by `subprocess.Popen`.

  ```
  # Visualization of vulnerable code path:

  experiment_config.json --> load_experiment_config() --> expand_experiment_config()
      --> experiment_to_args() --> _create_job_spec_dict() --> execute_jobs()
          --> ufs.capture_stdout(cmd) --> subprocess.Popen(cmd) # Command Injection
  ```

- Security Test Case:
  1. Create a file named `malicious_config.json` with the following content:
     ```json
     {
       "learning_rate": [0.01],
       "model_name": ["`touch /tmp/pwned_security_test`"]
     }
     ```
  2. In a terminal, navigate to a directory containing `mnist.py` (or any other Caliban example script).
  3. Execute the following command:
     ```bash
     caliban run --experiment_config malicious_config.json --nogpu mnist.py
     ```
  4. After the command completes, access the Docker container's shell using `caliban shell --nogpu`.
  5. Inside the Docker container, check if the file `/tmp/pwned_security_test` exists:
     ```bash
     ls /tmp/pwned_security_test
     ```
  6. If the file `/tmp/pwned_security_test` exists, the vulnerability is confirmed. This indicates that the command injected through `malicious_config.json` was successfully executed within the Docker container.