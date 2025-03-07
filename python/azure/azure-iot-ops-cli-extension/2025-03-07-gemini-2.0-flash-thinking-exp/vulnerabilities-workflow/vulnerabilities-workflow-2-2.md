- vulnerability name: Potential Command Injection in Integration Tests and Tools
- description:
  - The `az iot ops` extension uses `helpers.run` function in integration tests and `tools/codespace_connect.sh` script, which executes shell commands.
  - In `test_init_int.py`, the `test_init_scenario` test uses `process_additional_args` to parse arguments from `additional_init_args` and `additional_create_args`, which are environment variables.
  - These arguments are then passed to the `az iot ops init` and `az iot ops create` commands executed via `helpers.run`.
  - If an attacker can control the `azext_edge_init_args` or `azext_edge_create_args` environment variables, they could inject malicious commands.
  - Similarly, `tools/codespace_connect.sh` uses shell variables `CODESPACE_NAME`, `REPO`, and `BRANCH` which are derived from user input or environment variables and are used in `gh` commands.
  - An attacker with control over these input variables could inject malicious commands.

- impact:
  - In test scenarios, command injection could lead to unauthorized access to test resources or modification of test environments.
  - In `tools/codespace_connect.sh`, command injection could lead to unauthorized actions on the attacker's or victim's GitHub Codespace environment, potentially including data exfiltration or further malicious activities.

- vulnerability rank: high

- currently implemented mitigations:
  - None in the `helpers.run` or `tools/codespace_connect.sh` scripts.
  - Usage of `process_additional_args` in tests might be intended as mitigation, but it does not prevent command injection if environment variables are maliciously crafted.

- missing mitigations:
  - Sanitize inputs to `helpers.run` and `tools/codespace_connect.sh` to prevent command injection.
  - Avoid using shell execution for integration tests and tools, or use parameterized commands with safe execution methods.
  - Validate and sanitize environment variables used in tests and tools.

- preconditions:
  - For `test_init_int.py`, attacker needs to control the environment variables `azext_edge_init_args` or `azext_edge_create_args`. This is typically only possible in a development or CI environment, not in production deployments of the Azure CLI extension itself.
  - For `tools/codespace_connect.sh`, attacker needs to control the input parameters `-c`, `-r` or `-b` or environment variables that are used to construct commands.

- source code analysis:
  - `/code/azext_edge/tests/helpers.py`:
    ```python
    def run(command: str, shell_mode: bool = True, expect_failure: bool = False):
        ...
        result = subprocess.run(command, check=False, shell=shell_mode, text=True, capture_output=True, encoding="utf-8")
        ...
    ```
    - The `run` function uses `subprocess.run` with `shell=True`, which is vulnerable to command injection if the `command` argument is not properly sanitized.

  - `/code/azext_edge/tests/edge/init/int/test_init_int.py`:
    ```python
    @pytest.mark.init_scenario_test
    def test_init_scenario(init_test_setup, tracked_files):
        additional_init_args = init_test_setup["additionalInitArgs"] or ""
        init_arg_dict = process_additional_args(additional_init_args)
        additional_create_args = init_test_setup["additionalCreateArgs"] or ""
        create_arg_dict = process_additional_args(additional_create_args)
        ...
        command = f"az iot ops init -g {resource_group} --cluster {cluster_name} --no-progress {additional_init_args} "
        run(command) # Calls vulnerable run function

        create_command = (
            f"az iot ops create -g {resource_group} --cluster {cluster_name} "
            f"--sr-resource-id {registry_id}  -n {instance_name} "
            f"--no-progress {additional_create_args} "
        )
        run(create_command) # Calls vulnerable run function
        ...
    ```
    - `test_init_scenario` test calls `run` function with commands constructed using f-strings that include environment variables `additional_init_args` and `additional_create_args`.

  - `/code/tools/codespace_connect.sh`:
    ```bash
    ...
    # Forward port
    echo "forwarding codespace $CODESPACE_NAME port $PORT to local port $PORT"
    gh codespace ports forward $PORT:$PORT -c $CODESPACE_NAME # Calls vulnerable gh command
    ```
    - `codespace_connect.sh` script calls `gh codespace ports forward` command using shell variables derived from user input or environment variables.

- security test case:
  - **For `test_init_int.py` (Development/CI environment vulnerability):**
    1.  Set environment variable `AZURE_EXTENSION_DIR` to a writable directory.
    2.  Set environment variable `azext_iot_ops_init_args` to a malicious command, e.g., `--name '; touch /tmp/pwned;'`.
    3.  Run the integration tests, e.g., `pytest azext_edge/tests/edge/init/int/test_init_int.py`.
    4.  Observe if the command injection is successful, e.g., check if the file `/tmp/pwned` is created in the test environment.

  - **For `tools/codespace_connect.sh` (Tool vulnerability):**
    1.  Run `codespace_connect.sh -c "$(touch /tmp/pwned)"`.
    2.  Observe if the command injection is successful, e.g., check if the file `/tmp/pwned` is created in the local machine or codespace environment.