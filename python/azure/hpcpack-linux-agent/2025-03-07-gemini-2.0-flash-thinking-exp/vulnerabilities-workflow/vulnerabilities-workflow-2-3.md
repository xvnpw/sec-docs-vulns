## Vulnerability List

- Vulnerability Name: Command Injection in shim.sh via Unvalidated Arguments

- Description:
  1. The `shim.sh` script is the main entry point for the HPC Pack Linux NodeAgent extension.
  2. It executes `hpcnodemanager.py` and directly passes all arguments received by `shim.sh` to `hpcnodemanager.py` without any validation.
  3. An attacker could potentially inject malicious commands by crafting specific arguments when interacting with the Azure extension management framework.
  4. For example, an attacker might be able to inject shell commands by using arguments like `--argument="; malicious command; "`.
  5. These injected commands would be executed in the context of the user running the `shim.sh` script, which is typically root.

- Impact:
  - Remote Command Execution: Successful exploitation allows an attacker to execute arbitrary commands on the Linux node with root privileges.
  - Full System Compromise: An attacker can gain complete control over the compromised Linux node, potentially leading to data theft, malware installation, or further attacks on the HPC cluster.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
  - None: The `shim.sh` script directly passes arguments without any input validation.

- Missing Mitigations:
  - Input Validation: Implement robust input validation in `shim.sh` to sanitize or reject potentially malicious arguments before passing them to `hpcnodemanager.py`.
  - Parameterized Execution:  Instead of directly passing arguments as strings, use parameterized execution methods where possible to avoid shell injection.

- Preconditions:
  - The attacker must be able to influence the arguments passed to the `shim.sh` script. This is typically achieved through interaction with the Azure extension management framework, for example, by crafting a malicious extension configuration update request.

- Source Code Analysis:
  ```bash
  File: /code/VMExtension/shim.sh

  #!/usr/bin/env bash
  ...
  ARG="$@"
  ...
  ${PYTHON} ${COMMAND} ${ARG}
  ```
  - The line `ARG="$@"` captures all arguments passed to `shim.sh` and stores them in the variable `ARG`.
  - The line `${PYTHON} ${COMMAND} ${ARG}` then executes the Python script `hpcnodemanager.py` with the arguments stored in `ARG`.
  - There is no input validation or sanitization performed on the arguments before they are passed to the Python script.
  - This direct and unvalidated passing of arguments creates a command injection vulnerability.
  - Visualization:
    ```
    External Input (via Azure Extension Framework) --> shim.sh (ARG="$@") --> hpcnodemanager.py (Unvalidated Arguments) --> System Command Execution (Potential Injection)
    ```

- Security Test Case:
  1. Prepare environment to deploy Azure VM extension for HPC Linux Node Agent.
  2. Craft a malicious payload to be passed as an argument to the extension. For example, when triggering a "enable" operation, try to inject command using `--operation="enable ; touch /tmp/pwned ;"`. Note that the actual argument name may differ based on how extension interacts with `hpcnodemanager.py`. It requires further investigation of `hpcnodemanager.py` to find vulnerable argument. For now, assume any argument passed to `shim.sh` is vulnerable.
  3. Deploy or update the extension on a test Linux VM with the crafted malicious payload as part of the extension settings or operation parameters.
  4. Check if the injected command `touch /tmp/pwned` was executed on the VM.
  5. If the file `/tmp/pwned` is created, it confirms the command injection vulnerability.
  6. For more advanced testing, try to execute more harmful commands like reverse shell or data exfiltration.