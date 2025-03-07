## Combined Vulnerability Report

This report consolidates identified high and critical vulnerabilities, removing duplicates and excluding those that do not meet the specified criteria.

### 1. Command Injection via Unsafe Argument Handling in `caliban run`

- **Description:**
    1. A user executes `caliban run` with a Python script and provides additional command-line arguments intended for the script itself.
    2. Caliban constructs a Docker command to execute the user-provided Python script within a container.
    3. If the Python script directly uses `sys.argv` or `argparse` to process these command-line arguments without proper sanitization, an attacker can inject malicious commands.
    4. By crafting command-line arguments that include shell metacharacters (e.g., `;`, `|`, `&&`, `$()`, `` ` ``), an attacker can execute arbitrary commands within the Docker container, bypassing the intended script execution.

- **Impact:**
    - **High**: Successful command injection allows an attacker to execute arbitrary commands inside the Docker container. This could lead to:
        - Data exfiltration: Accessing and stealing sensitive data within the container or mounted volumes.
        - Container takeover: Gaining complete control over the Docker container.
        - Privilege escalation: Potentially escaping the container if Docker is misconfigured or vulnerabilities exist.
        - Lateral movement: Using the compromised container as a stepping stone to attack other systems or cloud resources.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - None: The project does not implement any sanitization or validation of user-supplied command-line arguments within Caliban itself before passing them to the user's script inside the Docker container. The responsibility for sanitization is implicitly left to the user's Python script.

- **Missing Mitigations:**
    - Input Sanitization: Caliban should sanitize or validate command-line arguments passed to `caliban run` before executing the Docker command. This could involve:
        - Quoting or escaping shell metacharacters in arguments before passing them to `docker run`.
        - Validating argument format and content against expected patterns.
    - Documentation and User Education:  Clear documentation should warn users about the risks of unsafely handling command-line arguments in their Python scripts and recommend secure coding practices, such as using `argparse` correctly and avoiding direct shell command construction with user inputs.

- **Preconditions:**
    1. User must execute `caliban run` with a Python script.
    2. User must provide command-line arguments to `caliban run` that are passed to the Python script.
    3. The Python script must unsafely process these command-line arguments, for example by directly using `sys.argv` or `os.system` without proper sanitization.

- **Source Code Analysis:**
    1. **`caliban/cli.py`:** The `parse_flags` function and related functions parse command-line arguments for Caliban. The `add_script_args` function handles arguments for the user's script and stores them in `script_args`.
    2. **`caliban/main.py`:** The `run_app` function retrieves `script_args` and passes them to `caliban.platform.run.run_experiments` or `caliban.platform.run.run`.
    3. **`caliban/platform/run.py`:** The `run` and `run_experiments` functions construct the `docker run` command. The `script_args` are directly appended to the `docker run` command without sanitization.
    ```python
    # File: caliban/platform/run.py
    def run(
        job_mode: c.JobMode,
        run_args: Optional[List[str]] = None,
        script_args: Optional[List[str]] = None, # User-provided script args
        image_id: Optional[str] = None,
        **build_image_kwargs,
    ) -> None:
        # ...
        base_cmd = _run_cmd(job_mode, run_args)

        command = base_cmd + [image_id] + script_args # script_args appended directly

        logging.info("Running command: {}".format(" ".join(command)))
        subprocess.call(command) # Executes the command
        return None
    ```
    4. **User's Python Script:** Example scripts use `absl.app`, `argparse` or directly access `sys.argv` to process command-line arguments. If these scripts do not implement input sanitization, they are vulnerable to command injection if Caliban passes through malicious arguments.

- **Security Test Case:**
    1. Create a vulnerable Python script (`vuln_script.py`):
    ```python
    # File: vuln_script.py
    import os
    import sys

    command = "echo Hello, " + sys.argv[1]
    os.system(command)
    ```
    2. Run `caliban run` with the vulnerable script and a malicious argument:
    ```bash
    caliban run --nogpu vuln_script.py -- --argument '; touch /tmp/caliban_vuln'
    ```
    3. Access the Docker container:
    ```bash
    docker run -it --rm <caliban_image_id> /bin/bash
    ```
    4. Check if `/tmp/caliban_vuln` exists inside the container:
    ```bash
    ls -l /tmp/caliban_vuln
    ```
    5. If the file exists, command injection is confirmed.

### 2. Command Injection via Experiment Configuration in `caliban run` and `caliban cloud`

- **Description:**
    1. An attacker crafts a malicious experiment configuration (e.g., in a JSON file via `--experiment_config` or stdin) containing a command injection payload.
    2. When a user executes `caliban run` or `caliban cloud` with this malicious configuration, Caliban parses it.
    3. During experiment expansion and execution, Caliban improperly handles configuration values, injecting the payload into commands executed by `docker run` within the container.
    4. This leads to arbitrary code execution within the Docker container or cloud environment with the privileges of the user running `caliban`.

- **Impact:**
    - **High**. Successful command injection allows an attacker to execute arbitrary commands within the Docker container or cloud environment. This could lead to:
        - Data exfiltration: Stealing sensitive data from the experiment environment or mounted volumes.
        - Container/Environment takeover: Gaining control over the Docker container or cloud execution environment.
        - Lateral movement: Potential to pivot to other systems if the compromised environment has network access.
        - Resource manipulation: Modifying or deleting experiment data, models, or other resources.
        - Denial of service: Disrupting experiments or consuming excessive resources.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - None: The code lacks input sanitization or command construction methods to prevent command injection in the context of experiment configurations.

- **Missing Mitigations:**
    - Input sanitization: Implement robust input validation and sanitization for all values read from experiment configurations, especially those used in constructing Docker commands.
    - Secure command construction: Utilize safe methods for constructing Docker commands, such as parameterization or shell-escaping functions to prevent injection. Avoid directly embedding user-provided strings into shell commands.
    - Least privilege: Ensure the Docker container and Caliban itself run with the minimum privileges necessary to reduce the impact of a successful exploit.

- **Preconditions:**
    1. An attacker needs to provide a malicious experiment configuration to a Caliban user, potentially through social engineering, man-in-the-middle attacks, or supply chain attacks.
    2. The user must execute `caliban run` or `caliban cloud` using the malicious configuration via `--experiment_config` flag or stdin.

- **Source Code Analysis:**
    1. **`caliban/config/experiment.py:experiment_to_args(m: Experiment)`**: Converts experiment configuration dictionaries to command-line arguments without sanitization.
    2. **`caliban/platform/run.py:execute_jobs(job_specs: Iterable[JobSpec])`**: Iterates through job specifications, each containing command-line arguments derived from experiment configurations.
    3. **`caliban/platform/run.py:_create_job_spec_dict(...)`**: Constructs `JobSpec` dictionaries, appending unsanitized `cmd_args` from `experiment_to_args` to the base command.
    4. **`caliban/util/fs.py:capture_stdout(cmd: List[str], ...)`**: Executes commands using `subprocess.Popen(cmd, ...)`, passing unsanitized arguments directly to the shell.
    5. **Vulnerability Point**: Lack of sanitization between configuration parsing and command execution in `subprocess.Popen` creates a command injection vulnerability.

    ```
    # Vulnerable code path:

    experiment_config.json --> load_experiment_config() --> expand_experiment_config()
        --> experiment_to_args() --> _create_job_spec_dict() --> execute_jobs()
            --> ufs.capture_stdout(cmd) --> subprocess.Popen(cmd) # Command Injection
    ```

- **Security Test Case:**
    1. Create `malicious_config.json`:
    ```json
    {
      "learning_rate": [0.01, "0.001; touch /tmp/pwned_security_test; #"]
    }
    ```
    2. Execute `caliban run` with the malicious configuration:
    ```bash
    caliban run --experiment_config malicious_config.json --nogpu tutorials/basic/mnist.py
    ```
    3. Access the Docker container:
    ```bash
    caliban shell --nogpu
    ```
    4. Check if `/tmp/pwned_security_test` exists inside the container:
    ```bash
    ls /tmp/pwned_security_test
    ```
    5. If the file exists, command injection via experiment configuration is confirmed.