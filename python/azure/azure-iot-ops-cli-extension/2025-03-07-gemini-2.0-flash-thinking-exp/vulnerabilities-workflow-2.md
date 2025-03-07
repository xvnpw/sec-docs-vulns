## Combined Vulnerability List

This document summarizes identified vulnerabilities, detailing their descriptions, impacts, mitigations, and steps to reproduce. Only high and critical severity vulnerabilities that are realistic to exploit, fully described, and evidenced in source code analysis are included.

### Potential Command Injection in Integration Tests and Tools

- **Description:**
  - The `az iot ops` extension utilizes the `helpers.run` function in integration tests and the `tools/codespace_connect.sh` script, both of which execute shell commands. In `test_init_int.py`, the `test_init_scenario` test uses `process_additional_args` to parse arguments from environment variables (`additional_init_args` and `additional_create_args`). These arguments are then passed to the `az iot ops init` and `az iot ops create` commands executed via `helpers.run`. If an attacker can control these environment variables, they could inject malicious commands. Similarly, `tools/codespace_connect.sh` uses shell variables derived from user input or environment variables in `gh` commands, creating another potential injection point.

- **Impact:**
  - In test scenarios, command injection could lead to unauthorized access to test resources or modification of test environments. In `tools/codespace_connect.sh`, it could lead to unauthorized actions on the attacker's or victim's GitHub Codespace environment, potentially including data exfiltration or further malicious activities.

- **Vulnerability Rank:** high

- **Currently Implemented Mitigations:**
  - None in the `helpers.run` or `tools/codespace_connect.sh` scripts. The usage of `process_additional_args` in tests, while parsing arguments, does not prevent command injection if environment variables themselves are malicious.

- **Missing Mitigations:**
  - Input sanitization for `helpers.run` and `tools/codespace_connect.sh` to prevent command injection.
  - Avoiding shell execution for integration tests and tools, or using parameterized commands with safe execution methods.
  - Validation and sanitization of environment variables used in tests and tools.

- **Preconditions:**
  - For `test_init_int.py`: Attacker needs to control the environment variables `azext_edge_init_args` or `azext_edge_create_args`. This is typically only possible in a development or CI environment.
  - For `tools/codespace_connect.sh`: Attacker needs to control input parameters `-c`, `-r`, or `-b`, or environment variables that influence command construction.

- **Source Code Analysis:**
  - File: `/code/azext_edge/tests/helpers.py`
    ```python
    def run(command: str, shell_mode: bool = True, expect_failure: bool = False):
        ...
        result = subprocess.run(command, check=False, shell=shell_mode, text=True, capture_output=True, encoding="utf-8")
        ...
    ```
    - The `run` function uses `subprocess.run` with `shell=True`, making it vulnerable to command injection if the `command` argument is not sanitized.

  - File: `/code/azext_edge/tests/edge/init/int/test_init_int.py`
    ```python
    @pytest.mark.init_scenario_test
    def test_init_scenario(init_test_setup, tracked_files):
        additional_init_args = init_test_setup["additionalInitArgs"] or ""
        init_arg_dict = process_additional_args(additional_init_args)
        additional_create_args = init_test_setup["additionalCreateArgs"] or ""
        create_arg_dict = process_additional_args(additional_create_args)
        ...
        command = f"az iot ops init -g {resource_group} --cluster {cluster_name} --no-progress {additional_init_args} "
        run(command)

        create_command = (
            f"az iot ops create -g {resource_group} --cluster {cluster_name} "
            f"--sr-resource-id {registry_id}  -n {instance_name} "
            f"--no-progress {additional_create_args} "
        )
        run(create_command)
        ...
    ```
    - The `test_init_scenario` test calls the vulnerable `run` function with commands constructed using f-strings that include environment variables.

  - File: `/code/tools/codespace_connect.sh`
    ```bash
    ...
    # Forward port
    echo "forwarding codespace $CODESPACE_NAME port $PORT to local port $PORT"
    gh codespace ports forward $PORT:$PORT -c $CODESPACE_NAME
    ```
    - `codespace_connect.sh` script calls `gh codespace ports forward` using shell variables derived from user inputs or environment variables.

- **Security Test Case:**
  - **For `test_init_int.py`:**
    1. Set environment variable `AZURE_EXTENSION_DIR` to a writable directory.
    2. Set environment variable `azext_iot_ops_init_args` to a malicious command, e.g., `--name '; touch /tmp/pwned;'`.
    3. Run the integration tests: `pytest azext_edge/tests/edge/init/int/test_init_int.py`.
    4. Check if the file `/tmp/pwned` is created, indicating successful command injection.

  - **For `tools/codespace_connect.sh`:**
    1. Run `codespace_connect.sh -c "$(touch /tmp/pwned)"`.
    2. Check if the file `/tmp/pwned` is created, indicating successful command injection.

### Kubeconfig Exposure via Default Location

- **Description:**
  - The Azure IoT Operations extension relies on the default kubeconfig file at `~/.kube/config`. Unauthorized access to the user's filesystem could lead to the theft of this kubeconfig. A stolen kubeconfig grants full administrative access to the Kubernetes cluster without proper authorization, bypassing authentication and authorization controls.

- **Impact:**
  - An attacker gaining access to the kubeconfig file can achieve complete, unauthorized administrative access to the Kubernetes cluster. This can lead to full cluster compromise, unauthorized deployments, data exfiltration, and denial-of-service attacks.

- **Vulnerability Rank:** critical

- **Currently Implemented Mitigations:**
  - No specific mitigations are implemented within the project. The project relies on the standard Kubernetes tooling and default kubeconfig location as documented in `README.md`.

- **Missing Mitigations:**
  - Implement secure kubeconfig storage mechanisms, potentially outside the user's home directory or using encryption.
  - Adhere to the principle of least privilege, minimizing required Kubernetes permissions.
  - Explore and implement alternative, more secure authentication methods beyond static kubeconfig files, such as Azure Active Directory integration.
  - Provide clear user documentation on kubeconfig security risks and best practices.

- **Preconditions:**
  - Azure IoT Operations extension is installed and configured to manage Kubernetes clusters.
  - A kubeconfig file exists in the default location (`~/.kube/config`) or is accessible by the extension.
  - An attacker gains unauthorized read access to the user's filesystem where the kubeconfig is stored.

- **Source Code Analysis:**
  - File: `/code/README.md`
    - Step 1: The `README.md` states the extension uses the default kubeconfig location: "👉 To maintain minimum friction between K8s tools, the `az iot ops` edge side commands are designed to make use of your existing kube config (typically located at `~/.kube/config`)."
    - Step 2: Documentation mentions `--context` parameter for kubeconfig context, implying direct kubeconfig usage. "All k8s interaction commands include an optional `--context` param. If none is provided `current_context` as defined in the kube config will be used."
    - Step 3: While specific kubeconfig loading code isn't in provided files, reliance on default location is documented, suggesting standard Kubernetes libraries are used which default to `~/.kube/config`.

  - Visualization:
  ```
  User's Machine --> Filesystem ( ~/.kube/config ) --> Azure IoT Ops CLI Extension --> Kubernetes Cluster
  ```

- **Security Test Case:**
  1. **Environment Setup:** Install Azure IoT Operations extension, configure it to manage a test Kubernetes cluster with a valid kubeconfig at `~/.kube/config`. Verify basic CLI interaction with `az iot ops check --cluster <cluster_name> -g <resource_group>`.
  2. **Simulate Kubeconfig Theft:** As attacker, simulate filesystem access and copy `~/.kube/config` to `/tmp/attacker_kubeconfig`.
  3. **Attempt Unauthorized Cluster Access:** In a new terminal (attacker's env), use `kubectl --kubeconfig /tmp/attacker_kubeconfig get pods --all-namespaces`.
  4. **Verification:** Successful retrieval of pod information confirms unauthorized cluster access via stolen kubeconfig.

### Kubeconfig Manipulation via Codespace Connect Script

- **Description:**
  - The `codespace_connect.sh` script copies kubeconfig from a remote codespace to the user's local machine and replaces `0.0.0.0` with `127.0.0.1`. An attacker compromising the GitHub Codespace environment or performing a MITM attack during the copy process could inject a malicious kubeconfig. This malicious kubeconfig can redirect `az iot ops` commands to an attacker-controlled cluster or embed commands for execution within the user's cluster context.

- **Impact:**
  - **High**: An attacker could gain unauthorized access to the user's Kubernetes cluster, potentially leading to data breaches, service disruption, or complete cluster takeover, depending on the permissions associated with the manipulated kubeconfig context.

- **Vulnerability Rank:** high

- **Currently Implemented Mitigations:**
  - **None**: The script lacks security measures to prevent kubeconfig manipulation during copy or validation of its content.

- **Missing Mitigations:**
  - Implement integrity checks (e.g., checksum) on the kubeconfig after copying.
  - Ensure a secure copy channel for `gh codespace cp` (though it uses SSH, explicit verification is missing).
  - Implement kubeconfig content validation to reject malicious configurations, checking for unusual server addresses or embedded commands.

- **Preconditions:**
  1. Attacker compromises GitHub Codespace or performs MITM during `codespace_connect.sh` execution.
  2. User executes `codespace_connect.sh` and subsequently uses `az iot ops` commands relying on the manipulated kubeconfig.

- **Source Code Analysis:**
  - File: `/code/tools/codespace_connect.sh`
    ```sh
    ...
    # Copy kubeconfig from codespace
    TRIES=0
    MAX_TRIES=6
    SLEEP=10s
    echo "Copying $REMOTE_KUBECONF from codespace $CODESPACE_NAME to local $LOCAL_KUBECONF"
    until gh codespace cp -e "remote:$REMOTE_KUBECONF" -e $LOCAL_KUBECONF -c $CODESPACE_NAME
    do
        ...
    done

    # Update local IP
    echo "Updating localhost endpoint in local config $LOCAL_KUBECONF"
    sed -i -e "s/0.0.0.0/127.0.0.1/g" "$LOCAL_KUBECONF"
    ...
    ```
    - Script uses `gh codespace cp` for copying, relying on `gh` CLI and Codespaces environment security.
    - `sed` command blindly replaces IPs without kubeconfig validation, enabling manipulation if the copied file is already malicious.
    - No integrity or authenticity checks for the kubeconfig from codespace.

- **Security Test Case:**
  1. **Attacker Setup:** Create a malicious GitHub Codespace, modify kubeconfig to point to an attacker-controlled cluster or include malicious commands, host it on a public repo.
  2. **Victim Action:** User runs `codespace_connect.sh -r attacker-org/malicious-repo -b main` (or `-c malicious-codespace-name`). Malicious kubeconfig is copied to `~/.kube/config`.
  3. **Exploitation:** Victim runs `az iot ops check`. If malicious kubeconfig redirects, command executes against attacker's infrastructure or malicious commands execute in victim's cluster.
  4. **Verification:** Observe `az iot ops check` interacting with attacker's cluster (redirection) or malicious command execution in victim's cluster. Verify lack of integrity checks in `codespace_connect.sh`.