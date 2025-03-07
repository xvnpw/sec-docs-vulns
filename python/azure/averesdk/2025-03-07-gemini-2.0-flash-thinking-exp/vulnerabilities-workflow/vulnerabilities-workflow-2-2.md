### Vulnerability List

- Vulnerability Name: Insecure Command Logging of Admin Password in `enablecloudtrace.sh`
- Description:
    1. The `enablecloudtrace.sh` script is designed to enable cloud tracing on the vFXT cluster for debugging purposes during installation.
    2. This script utilizes the `averecmd` command-line tool to interact with the vFXT cluster's XML-RPC API.
    3. The `ADMIN_PASSWORD` for the vFXT cluster is passed to `averecmd` as a command-line argument using the `--password` parameter.
    4. If the `enablecloudtrace.sh` script is executed with the `-x` option (set -x) for debugging, or if shell history logging is enabled on the controller VM, the command-line invocation of `averecmd`, including the plain text `ADMIN_PASSWORD`, can be logged.
    5. An attacker who gains access to the controller VM's shell history, debug logs, or standard error/output streams could potentially retrieve the `ADMIN_PASSWORD` from these logs.
- Impact:
    - Successful exploitation of this vulnerability allows an attacker to obtain the `ADMIN_PASSWORD` of the vFXT cluster administrator.
    - With the `ADMIN_PASSWORD`, the attacker can gain full administrative access to the vFXT cluster via the Avere Control Panel or the XML-RPC API.
    - This administrative access allows the attacker to modify cluster configurations, access data managed by the cluster, and potentially compromise the entire vFXT cluster environment.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations:
    - The `installvfxt.sh` script attempts to redact the `ADMIN_PASSWORD` from the `vfxt.py` command that is logged to `create_cluster_command.log`. This mitigation is specific to the cluster creation command and does not cover other scripts like `enablecloudtrace.sh`.
    - Source code location of mitigation: `/code/controller/armscripts/installvfxt.sh` within the `create_vfxt` function where the `create_cluster_command.log` is generated.
- Missing Mitigations:
    - Redact the `ADMIN_PASSWORD` when invoking `averecmd` in `enablecloudtrace.sh` to prevent it from being logged in plain text.
    - Implement secure password handling practices in all scripts that use `ADMIN_PASSWORD`, such as avoiding command-line arguments for sensitive data and using secure input methods or environment variables where possible, with appropriate redaction in logs.
    - Provide documentation and guidance to users on securely managing shell history and logging on the controller VM, emphasizing the risks of exposing sensitive information like passwords in logs and command history.
- Preconditions:
    - The attacker must gain access to the controller VM's shell environment or log files. This could be achieved through various means, such as compromising the controller VM directly, gaining access to a shared logging system, or exploiting other vulnerabilities in the system's security posture.
    - The `enablecloudtrace.sh` script must have been executed at least once while logging was enabled (either through `set -x` or shell history). This is more likely if debugging was enabled during installation (`ENABLE_CLOUD_TRACE_DEBUG=True` in `install.sh`).
- Source Code Analysis:
    - File: `/code/controller/armscripts/enablecloudtrace.sh`
    - Step 1: The script defines variables, including `ADMIN_PASSWORD`.
    - Step 2: The `sendRPC` function is defined, which constructs the `averecmd` command:
      ```bash
      AVERECMD="averecmd --raw --no-check-certificate --user admin --password $ADMIN_PASSWORD --server $ipaddress"
      ```
    - Step 3: The `main` function calls `enable_cloud_trace` and `disable_cloud_trace`, both of which use `sendRPC` to execute `averecmd` commands with the `$ADMIN_PASSWORD`.
    - Step 4: If the `install.sh` script (which calls `enablecloudtrace.sh` when `ENABLE_CLOUD_TRACE_DEBUG=True`) or `enablecloudtrace.sh` is executed with `set -x`, or if shell history is active, the command including `$ADMIN_PASSWORD` will be logged.
    - Visualization:
      ```
      enablecloudtrace.sh --> sendRPC() --> AVERECMD (contains ADMIN_PASSWORD as command-line argument) --> system logs/shell history
      ```
- Security Test Case:
    1. Pre-requisite: Deploy a controller VM using the provided scripts or a similar setup.
    2. Modify `/code/controller/armscripts/installvfxt.sh` to set `ENABLE_CLOUD_TRACE_DEBUG="True"`:
       ```bash
       ENABLE_CLOUD_TRACE_DEBUG="True"
       ```
    3. Re-run the installation script `/code/controller/armscripts/installvfxt.sh`. This will execute `enablecloudtrace.sh` with debug mode enabled (`set -x`).
    4. Log in to the controller VM as the administrative user (e.g., `azureadmin`).
    5. Examine the shell history file (e.g., using `cat ~/.bash_history` or `history`).
    6. Alternatively, check the output logs of the installation process if logging to a file was configured which would capture stderr/stdout.
    7. Search for lines containing `enablecloudtrace.sh` and `averecmd`.
    8. Verify if the `ADMIN_PASSWORD` is visible in plain text within the `averecmd` command in the shell history or logs. For example, look for lines like:
       ```
       + averecmd --raw --no-check-certificate --user admin --password <ADMIN_PASSWORD> --server <MGMT_IP> support.acceptTerms yes
       ```
    9. If the `ADMIN_PASSWORD` is found in plain text in the logs or shell history, the vulnerability is confirmed.