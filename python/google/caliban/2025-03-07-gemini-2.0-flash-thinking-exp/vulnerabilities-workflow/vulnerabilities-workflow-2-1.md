### Vulnerability 1: Command Injection via Unsafe Argument Handling in `caliban run`

- Description:
    1. A user executes `caliban run` with a Python script and additional command-line arguments intended for the script.
    2. Caliban constructs a Docker command to run the user-provided Python script inside a container.
    3. If the Python script directly uses `sys.argv` or `argparse` to process the command-line arguments without proper sanitization, an attacker can inject malicious commands.
    4. By crafting command-line arguments that include shell metacharacters (e.g., `;`, `|`, `&&`, `$()`, `` ` ``), an attacker can execute arbitrary commands within the Docker container, bypassing the intended script execution.

- Impact:
    - **High**: Successful command injection allows an attacker to execute arbitrary commands inside the Docker container. This could lead to:
        - Data exfiltration: Accessing and stealing sensitive data within the container or mounted volumes.
        - Container takeover: Gaining complete control over the Docker container.
        - Privilege escalation: Potentially escaping the container if Docker is misconfigured or vulnerabilities exist.
        - Lateral movement: Using the compromised container as a stepping stone to attack other systems or cloud resources.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None: The provided project files do not show any explicit sanitization or validation of user-supplied command-line arguments within Caliban itself before passing them to the user's script inside the Docker container. The responsibility for sanitization is implicitly left to the user's Python script.

- Missing Mitigations:
    - Input Sanitization: Caliban should sanitize or validate command-line arguments passed to `caliban run` before executing the Docker command. This could involve:
        - Quoting or escaping shell metacharacters in arguments before passing them to `docker run`.
        - Validating argument format and content against expected patterns.
    - Documentation and User Education:  Clear documentation should warn users about the risks of unsafely handling command-line arguments in their Python scripts and recommend secure coding practices, such as using `argparse` correctly and avoiding direct shell command construction with user inputs.

- Preconditions:
    1. User must execute `caliban run` with a Python script.
    2. User must provide command-line arguments to `caliban run` that are passed to the Python script.
    3. The Python script must unsafely process these command-line arguments, for example by directly using `sys.argv` or `os.system` without proper sanitization.

- Source Code Analysis:
    1. **`caliban/cli.py`:** The `parse_flags` function and related functions in `caliban/cli.py` parse the command-line arguments for Caliban itself. The `add_script_args` function specifically handles arguments intended for the user's script and stores them in `script_args`.
    2. **`caliban/main.py`:** The `run_app` function in `caliban/main.py` retrieves `script_args` and passes them to `caliban.platform.run.run_experiments` or `caliban.platform.run.run`.
    3. **`caliban/platform/run.py`:** The `run` and `run_experiments` functions in `caliban/platform/run.py` construct the `docker run` command. The `script_args` are appended to the `docker run` command. Crucially, Caliban itself does not perform any sanitization or validation of these `script_args`.
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
    4. **User's Python Script (e.g., `tutorials/basic/mnist.py`, `tutorials/uv-metrics/mnist.py`, `tutorials/uv-metrics/trainer/train.py`):** These example scripts, like typical Python scripts, use `absl.app`, `argparse` or directly access `sys.argv` to process command-line arguments. If these scripts do not implement input sanitization, they become vulnerable to command injection if Caliban passes through malicious arguments.

- Security Test Case:
    1. Create a vulnerable Python script (e.g., `vuln_script.py`) that executes a shell command using `os.system` and incorporates command-line arguments from `sys.argv` without sanitization:
    ```python
    # File: vuln_script.py
    import os
    import sys

    command = "echo Hello, " + sys.argv[1]
    os.system(command)
    ```
    2. Run `caliban run` with the vulnerable script and a malicious command injection payload as a command-line argument:
    ```bash
    caliban run --nogpu vuln_script.py -- --argument '; touch /tmp/caliban_vuln'
    ```
    3. After the command completes, use `docker exec` to access the running container (or run a new container from the same image if the original exited immediately after running the script):
    ```bash
    docker run -it --rm <caliban_image_id> /bin/bash
    ```
    (Replace `<caliban_image_id>` with the image ID output by `caliban run` or build the image manually using `caliban build --nogpu vuln_script.py`)
    4. Inside the Docker container shell, check if the file `/tmp/caliban_vuln` exists:
    ```bash
    ls -l /tmp/caliban_vuln
    ```
    5. If the file `/tmp/caliban_vuln` exists, it confirms successful command injection, as the `touch /tmp/caliban_vuln` command (injected via `--argument '; touch /tmp/caliban_vuln'`) was executed within the Docker container.

This vulnerability allows an attacker to bypass the intended execution flow of the user's script and run arbitrary commands within the Docker container managed by Caliban. This is a serious security risk.