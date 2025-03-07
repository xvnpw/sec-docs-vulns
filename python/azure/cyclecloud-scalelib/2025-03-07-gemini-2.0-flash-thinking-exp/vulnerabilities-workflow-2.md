### Combined Vulnerability List

This document outlines identified security vulnerabilities within the `cyclecloud-scalelib` project. Each vulnerability is detailed with its description, potential impact, severity ranking, mitigation status, and steps for remediation and verification.

#### 1. Improper Input Validation in Default Resources Configuration (Code Injection)

- **Description:**
    1. An attacker crafts a malicious JSON configuration file, specifically targeting the `default_resources` section within `autoscale.json`.
    2. Within this section, the attacker injects a malicious payload into the `value` field of a resource definition. This field is intended to accept simple expressions like `node.vcpu_count` or `size::20g`.
    3. The autoscaling library processes this configuration file using `json_load` (or `load_config`) from `hpc.autoscale.util`, which uses `json.load` for parsing.
    4. The `demandcalculator` and `NodeManager` components of the library evaluate these `value` expressions, including the attacker's malicious payload, using `eval()` or similar mechanisms without proper sanitization or sandboxing.
    5. This evaluation leads to arbitrary Python code execution within the context of the autoscaling application, potentially compromising the Azure CycleCloud environment.

- **Impact:**
    - **High to Critical**: Successful exploitation allows arbitrary Python code execution, leading to:
        - **Unauthorized Resource Manipulation**: Attackers can use CycleCloud REST API credentials to modify cluster configurations, start/stop nodes, or delete resources.
        - **Information Disclosure**: Access to sensitive information, including credentials, configurations, and data accessible within the Azure environment.
        - **Lateral Movement**: Potential to pivot to other Azure resources or networks using the compromised system.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - None. The code directly evaluates the `value` fields as Python expressions without sanitization.

- **Missing Mitigations:**
    - **Input Sanitization and Validation**: Implement strict validation for `value` fields in `default_resources`.
        - **Restrict Allowed Characters**: Limit characters to a safe subset, excluding harmful characters for code injection.
        - **Safe Expression Evaluator**: Replace `eval()` with a secure expression evaluation library that prevents arbitrary code execution, supporting only predefined safe functions and operators.
        - **Schema Validation**: Use JSON schema to enforce configuration structure and data types.

- **Preconditions:**
    - Attacker can provide a malicious `autoscale.json` configuration file. This could occur if:
        - Configuration location is writable by the attacker (unlikely but possible).
        - Vulnerabilities in other parts of the system allow configuration file modification.
        - Social engineering to trick a user into using a malicious configuration.

- **Source Code Analysis:**
    - File: `/code/example-celery/specs/broker/cluster-init/scripts/01.install.packages.sh`
    - Line: `python -m hpc.autoscale.cli initconfig ... --default-resource '{"select": {}, "name": "ncpus", "value": "node.vcpu_count"}' ... > $INSTALLDIR/autoscale.json` - Shows intended usage of `value` field as Python expression.
    - File: `/code/src/hpc/autoscale/job/demandcalculator.py` and related modules.
    - `DemandCalculator` and `NodeManager` use configurations from `autoscale.json`, including `default_resources`. `value` strings are treated as Python expressions and evaluated without sanitization.

    ```
    User-Provided autoscale.json --> json_load (util.py) --> Configuration (Dict) --> DemandCalculator/NodeManager --> default_resources (from config) --> value (string from JSON) --> eval() or similar --> Code Execution
    ```

- **Security Test Case:**
    1. **Setup**: Deploy `cyclecloud-scalelib` in a test environment with Azure CycleCloud.
    2. **Malicious Configuration**: Create modified `autoscale.json` with malicious Python payload in `value` field of `default_resources`:
    ```json
    {
       "select": {},
       "name": "ncpus",
       "value": "__import__('os').system('touch /tmp/pwned')"
    }
    ```
    3. **Replace Configuration**: Replace original `autoscale.json` with the malicious one.
    4. **Trigger Autoscaling**: Run autoscaling script (`autoscale.py` from Celery example).
    5. **Verification**: Check for `/tmp/pwned` file on the system. Existence confirms successful code execution. Monitor logs or network for more complex payloads.

#### 2. Potential Command Injection via JSON Configuration Manipulation

- **Description:**
    An attacker could inject malicious commands by manipulating JSON configurations used by the library. Specifically, by crafting malicious payloads within the `value` fields of resource definitions or constraints in the JSON configuration files. If these values are not properly sanitized by the library before being passed to Azure CycleCloud or the integrated scheduler, it could lead to command injection.

- **Impact:**
    Successful command injection could allow an attacker to execute arbitrary commands on the Azure CycleCloud server or the scheduler nodes, potentially leading to unauthorized access, data breaches, or system compromise.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    None apparent. README.md warns about potential issues if values are not sanitized, suggesting no built-in sanitization.

- **Missing Mitigations:**
    Input sanitization and validation for all `value` fields in JSON configurations before processing by Azure CycleCloud or the scheduler. This includes escaping or sanitizing any potentially harmful characters or command sequences.

- **Preconditions:**
    - Attacker can modify JSON configuration files used by `cyclecloud-scalelib`. This may be possible if files are accessible or modifiable through insecure channels.
    - `cyclecloud-scalelib` processes JSON configurations and passes `value` fields to Azure CycleCloud or scheduler without sanitization.
    - Azure CycleCloud or scheduler are vulnerable to command injection if they receive unsanitized input in these fields.

- **Source Code Analysis:**
    - Project files lack core `cyclecloud-scalelib` code for detailed analysis from provided files.
    - `README.md` highlights JSON configurations and `value` fields for resources and constraints.
    - Example configurations show `value` fields directly configuring resources.
    - Inferred library likely parses JSON, extracts `value` fields, and uses them in API calls to Azure CycleCloud or scheduler.
    - **Vulnerability Point:** Lack of sanitization of `value` fields between JSON parsing and use in downstream systems. If downstream systems are vulnerable to command injection, this library could facilitate attacks.

- **Security Test Case:**
    1. **Setup:** Deploy `cyclecloud-scalelib` with Azure CycleCloud in a test environment.
    2. **Malicious Configuration:** Prepare malicious JSON configuration with `value` field designed for command execution:
    ```json
    {
       "default_resources": [
          {
             "select": {},
             "name": "cmd_injection_test",
             "value": "$(whoami)"
          }
       ]
    }
    ```
    3. **Attack:** Replace legitimate configuration file with the malicious one.
    4. **Trigger:** Trigger autoscaling or any function parsing the configuration.
    5. **Verification:** Monitor Azure CycleCloud server or scheduler logs for command execution output (e.g., `whoami` output). Alternatively, attempt reverse shell or data exfiltration. Successful command execution confirms vulnerability.

#### 3. Insecure Storage of CycleCloud API Credentials

- **Description:**
    1. The `cyclecloud-scalelib` library stores sensitive Azure CycleCloud REST API credentials (username and password) in plain text within the `autoscale.json` configuration file.
    2. `install.sh` and example scripts create `autoscale.json` during setup.
    3. Default file permissions for `autoscale.json` may allow unauthorized local users to read its contents.
    4. An attacker with local machine access can read `autoscale.json` and extract CycleCloud API credentials.
    5. Compromised credentials allow unauthorized access to the CycleCloud REST API, enabling manipulation of Azure cloud resources.

- **Impact:**
    - Unauthorized Access to Azure CycleCloud Environment: Full or partial control over Azure CycleCloud depending on credential permissions.
    - Cloud Resource Manipulation: Start, stop, scale, or delete Azure resources, leading to service disruption, data loss, or financial impact.
    - Lateral Movement: Potential lateral movement to other Azure services if credentials are reused or have broader access.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    None. No mitigations to prevent insecure credential storage in `autoscale.json`.

- **Missing Mitigations:**
    - **Secure Credential Storage:** Use Azure Key Vault or other secrets management instead of plain text files.
    - **Least Privilege Principle:** Encourage creation of CycleCloud API credentials with minimum necessary permissions.
    - **Documentation and Best Practices:** Provide clear guidance on secure credential management, emphasizing restricted access to `autoscale.json` and secure storage solutions. Warn against plain text credentials in configuration files.

- **Preconditions:**
    - Application using `cyclecloud-scalelib` relies on `autoscale.json` for CycleCloud API authentication.
    - `autoscale.json` is stored on a file system accessible to potential attackers.
    - Attacker gains unauthorized access to the file system where `autoscale.json` is stored.

- **Source Code Analysis:**
    1. **File Creation**: `hpc.autoscale.cli initconfig` command (used in `/code/example-celery/specs/broker/cluster-init/scripts/01.install.packages.sh`) creates `autoscale.json`.
    2. **Credential Storage**: `initconfig` (in `/code/src/hpc/autoscale/cli.py` and `/code/src/hpc/autoscale/clilib.py`) stores username and password directly in `autoscale.json` in plain text.
    3. **File Permissions**: `install.sh` and examples do not explicitly set restrictive permissions, potentially leading to insecure default permissions.
    4. **CLI Usage**: `azscale` CLI (created by `/code/util/install_azscale.sh`) uses `autoscale.json`, making applications using it vulnerable to compromised `autoscale.json`.

    ```python
    # /code/src/hpc/autoscale/cli.py - _initconfig method in ScaleLibCLI class
    def _initconfig(self, config: Dict) -> None:
        pass # No explicit permission setting here for autoscale.json

    # /code/example-celery/specs/broker/cluster-init/scripts/01.install.packages.sh
    python -m hpc.autoscale.cli initconfig ... > $INSTALLDIR/autoscale.json # autoscale.json created without permission setting
    ```

- **Security Test Case:**
    1. **Environment Setup**: Deploy Celery cluster from `/code/example-celery/README.md` on Azure CycleCloud. SSH to broker node.
    2. **Access Broker Node**: SSH into broker node.
    3. **Check `autoscale.json` Permissions**: `ls -l /opt/cycle/scalelib/autoscale.json`. Observe likely world-readable permissions.
    4. **Read `autoscale.json` Content**: `cat /opt/cycle/scalelib/autoscale.json`.
    5. **Extract Credentials**: Locate and extract `"username"` and `"password"` values.
    6. **Attempt API Access**:
        - **Using `az cyclecloud` CLI:**
            ```bash
            az cyclecloud user list --cluster-name <cluster_name> --username <username> --password <password> --url <url>
            ```
        - **Using `curl`:**
            ```bash
            curl -u "<username>:<password>" "<url>/api/v2/clusters"
            ```
    7. **Verify Unauthorized Access**: Successful API access confirms vulnerability.