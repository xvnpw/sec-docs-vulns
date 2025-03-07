### Vulnerability List

- Vulnerability Name: Insecure Default Symphony Administrator Password and Potential Weak Credentials on IBM Spectrum Symphony Web Interface
- Description:
  - The IBM Spectrum Symphony master installation script `010_install_symphony_master.sh` in older versions automatically sets the Symphony administrator password to a weak default value "Admin" using the command `egoconfig setpassword -x Admin`. Although this specific command is commented out in the provided script for version 7.3.2, the risk remains high as users might manually uncomment it or employ similar methods to set default passwords during installation for initial ease of setup or due to insufficient security awareness.
  - Furthermore, even if default passwords are not automatically set, the lack of enforced strong password policies during and after deployment can lead to users configuring weak or easily guessable credentials for the Symphony web interface.
  - An attacker with network access to the deployed IBM Spectrum Symphony web interface or command-line tools can attempt to log in using default usernames (like "Admin") and common default passwords (like "Admin", "password", etc.) or weak passwords.
  - If successful, the attacker gains administrative access to the IBM Spectrum Symphony cluster. This could be through the web interface or command-line tools.
- Impact:
  - **Critical.** Full administrative access to the IBM Spectrum Symphony cluster.
  - Unauthorized access to the IBM Spectrum Symphony web interface and command-line tools.
  - An attacker can manage workloads, access sensitive data processed by Symphony, potentially pivot to other systems within the network, and disrupt cluster operations.
  - This could lead to data breaches, disruption of services, and further malicious activities within the Azure environment.
- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
  - For newer versions, the provided `010_install_symphony_master.sh` script *comments out* the command that would automatically set a default password (`egoconfig setpassword -x Admin`), which is a partial mitigation.
  - The scripts use `jetpack config` to manage credentials (`symphony.soam.user`, `symphony.soam.password`), guiding users towards configuring credentials via CycleCloud parameters, a more secure approach than hardcoding default passwords.

- Missing Mitigations:
  - **Enforce Strong Password Policy:** The deployment scripts should enforce the setting of a strong, non-default administrator password during the automated deployment process.
    - This could be achieved by:
      - Generating a random password and securely storing it (e.g., in Azure Key Vault or CycleCloud secrets).
      - Prompting the user to provide a strong password during deployment setup.
      - Integrating with a password management system.
  - **Password Complexity Requirements:** Implement password complexity requirements (minimum length, character types) if prompting for user input.
  - **Default Password Change Enforcement:** There should be a mechanism to force users to change any initially set password (even if manually set using `egoconfig setpassword` or similar methods) upon first login or during the initial setup process.
  - **Post-Deployment Security Hardening Guidance:** Provide clear documentation and instructions on how to change the default password immediately after deployment and implement other security best practices for IBM Spectrum Symphony. This guide should explicitly warn against using default credentials and provide best practices for securing the IBM Spectrum Symphony web interface, including password management, access control, and network security.
  - **Automated Security Checks:** The project should include automated security checks or scripts that would detect the presence of default or weak credentials on the IBM Spectrum Symphony web interface.

- Preconditions:
  - IBM Spectrum Symphony cluster deployed using the provided scripts.
  - During the installation process, default or weak credentials are set for the IBM Spectrum Symphony web interface, either automatically by older scripts, manually by the user, or due to lack of strong password enforcement.
  - Network access to the IBM Spectrum Symphony web interface or command-line tools.
  - Default username "Admin" or other common usernames are used, and corresponding weak passwords are not changed.

- Source Code Analysis:
  - File: `/code/specs/master/cluster-init/scripts/010_install_symphony_master.sh`
  - Line (Older versions, or if manually uncommented): `su - -c "source /etc/profile.d/symphony.sh && yes | egoconfig setpassword -x Admin && egoconfig setentitlement ${SYM_ENTITLEMENT_FILE}" egoadmin`
  - Visualization:
    ```
    010_install_symphony_master.sh --> egoconfig setpassword -x Admin --> Sets default password to "Admin" (in older versions or if manually enabled)
    ```
  - Step-by-step analysis:
    1. The script `010_install_symphony_master.sh` is executed during the master node initialization process.
    2. In older versions, or if manually enabled, the script switches to the `egoadmin` user using `su - -c`.
    3. Inside the `egoadmin` user context, it sources the Symphony environment script `/etc/profile.d/symphony.sh`.
    4. The command `egoconfig setpassword -x Admin` is executed with `yes` piped to it to bypass interactive prompts.
    5. `egoconfig setpassword -x Admin` sets the Symphony administrator password to the hardcoded value "Admin".
    6. The script continues with other Symphony configuration steps, but the insecure default password remains set if not manually changed later.
    7. Even in newer versions where this line is commented out, the lack of enforced password policies means users can still manually set weak passwords.

- Security Test Case:
  - Precondition: Deploy IBM Spectrum Symphony cluster using the provided scripts. Ensure the master node is publicly accessible or accessible from the attacker's network. For testing default password, manually enable the default password setting in `/code/specs/master/cluster-init/scripts/010_install_symphony_master.sh` (uncomment the relevant line for older versions). For testing weak password scenarios, manually set a weak password during or after installation.
  - Step 1: Identify the public IP address or hostname of the deployed IBM Spectrum Symphony master node.
  - Step 2: Access the IBM Spectrum Symphony web interface (typically on port 8080 or configured port).
  - Step 3: Attempt to log in using the username "Admin" and the password "Admin" (for default password test) or other common weak passwords.
  - Step 4: Verify successful login. If login is successful, the vulnerability is confirmed.
  - Step 5: (Optional) Use command-line tools like `soamview` or `egosh` from a machine with network access to the Symphony master node, attempting authentication with username "Admin" and password "Admin" (or weak password) to further validate command-line access.
  - Expected result: Attacker successfully logs in to the IBM Spectrum Symphony web interface and/or command-line tools with administrative privileges using the default or weak credentials.

---

- Vulnerability Name: Template Injection in `generateWeightedTemplates.sh` via Nodearray Names
  - Description:
    1. An attacker can influence the content of the generated `azureccprov_templates.json` file by crafting nodearray names within the CycleCloud cluster configuration.
    2. The `generateWeightedTemplates.sh` script retrieves nodearray information from the CycleCloud cluster status using `cyclecloud status`.
    3. It then iterates through the nodearrays and extracts the nodearray name to be used as `templateId` in the generated template file.
    4. If a nodearray name contains backticks or command injection characters, these characters will be directly incorporated into the `azureccprov_templates.json` file within the `templateId` field.
    5. When HostFactory reads and utilizes this `azureccprov_templates.json` file, the injected commands within the `templateId` could be executed during template processing or logging, potentially leading to unauthorized actions.

  - Impact:
    - Command Injection: An attacker could execute arbitrary commands on the system where HostFactory runs, potentially compromising the master node or related infrastructure components.
    - Configuration Manipulation: Malicious commands could modify system configurations, install backdoors, or exfiltrate sensitive information.
    - Compromised Worker Node Deployments: While the primary injection point is in template generation, successful command injection could lead to further attacks on worker nodes during deployment if the injected commands modify template processing logic or deployment scripts.

  - Vulnerability Rank: High

  - Currently Implemented Mitigations:
    - None. The script directly uses nodearray names without sanitization when generating the template file.

  - Missing Mitigations:
    - Input Sanitization: Implement input sanitization within `generateWeightedTemplates.sh` to remove or escape any special characters (like backticks, $, parentheses, etc.) from nodearray names before using them to construct the `templateId` in `azureccprov_templates.json`.
    - Validation of Template ID: Implement validation on the `templateId` field when reading `azureccprov_templates.json` in HostFactory to ensure it conforms to expected patterns and does not contain potentially malicious characters.
    - Principle of Least Privilege: Ensure that the HostFactory process and the user account running it have the minimum necessary privileges to perform their functions, limiting the impact of potential command injection vulnerabilities.

  - Preconditions:
    - An attacker needs to have the ability to define or influence nodearray names within the Azure CycleCloud cluster configuration. This is typically possible for users with administrative or cluster creation privileges in CycleCloud.
    - The HostFactory must be configured to use the generated `azureccprov_templates.json` file.

  - Source Code Analysis:
    1. **`hostfactory/host_provider/generateWeightedTemplates.sh`**:
       ```bash
       #!/bin/bash -e
       TEMP_HF_LOGDIR=/tmp/log
       export HF_LOGDIR=$TEMP_HF_LOGDIR
       export HF_CONFDIR=$HF_TOP/conf
       TEMP_HF_WORKDIR=/tmp/work
       export HF_WORKDIR=$TEMP_HF_WORKDIR
       mkdir -p $HF_LOGDIR
       mkdir -p $HF_WORKDIR
       cat <<EOF >/tmp/genTemplates.input.${USER}.json
       {}
       EOF
       export PRO_LOG_DIR=${HF_LOGDIR}
       export PRO_CONF_DIR=${HF_CONFDIR}/providers/azurecc
       export PRO_DATA_DIR=${HF_WORKDIR}

       venv_path=$HF_TOP/$HF_VERSION/providerplugins/azurecc/venv/bin
       scriptDir=`dirname $0`
       export PYTHONPATH=$PYTHONPATH:$scriptDir/src
       . $venv_path/activate
       $venv_path/python3 -m cyclecloud_provider generate_templates -f /tmp/genTemplates.input.${USER}.json
       exit_status=$?
       rm -rf $TEMP_HF_LOGDIR
       rm -rf $TEMP_HF_WORKDIR
       exit $exit_status
       ```
       - This script calls `cyclecloud_provider.py` with `generate_templates` action.

    2. **`hostfactory/host_provider/src/cyclecloud_provider.py`**:
       - In `CycleCloudProvider.generate_sample_template()` function:
         ```python
         def generate_sample_template(self):
             buckets = self.cluster.get_buckets()
             template_dict = {}
             for bucket in buckets:
                 autoscale_enabled = bucket.software_configuration.get("autoscaling", {}).get("enabled", False)
                 if not autoscale_enabled:
                     print("Autoscaling is disabled in CC for nodearray %s" % bucket.nodearray, file=sys.stderr)
                     continue
                 if template_dict.get(bucket.nodearray) is None:
                     template_dict[bucket.nodearray] = {}
                     template_dict[bucket.nodearray]["templateId"] = bucket.nodearray # Vulnerable line
                     template_dict[bucket.nodearray]["attributes"] = {}
                     # ... (rest of the template generation logic)
             templates = {"templates": list(template_dict.values())}
             print(json.dumps(templates, indent=4))
         ```
         - **Vulnerable Line:** `template_dict[bucket.nodearray]["templateId"] = bucket.nodearray`
           - The `templateId` is directly assigned the `bucket.nodearray` value without any sanitization. If `bucket.nodearray` contains malicious characters, they will be included in the generated JSON.
         - The generated template JSON is printed to standard output, which is then redirected to `azureccprov_templates.json` in `hostfactory/host_provider/generateWeightedTemplates.sh`.

    3. **Visualization:**

       ```
       CycleCloud Cluster Configuration --> Nodearray Name (potentially malicious)
                                          |
                                          V
       cyclecloud status (via generateWeightedTemplates.sh) --> Retrieves Nodearray Names
                                          |
                                          V
       cyclecloud_provider.py (generate_sample_template) --> Sets templateId = Nodearray Name (no sanitization)
                                          |
                                          V
       azureccprov_templates.json         <-- Generated template file with potentially malicious templateId
                                          |
                                          V
       HostFactory (reads azureccprov_templates.json) --> Potentially executes injected commands from templateId
       ```

  - Security Test Case:
    1. **Precondition:** Assume you have administrative access to Azure CycleCloud or permissions to create/modify clusters.
    2. **Create/Modify CycleCloud Cluster Configuration:**
       - Define a nodearray with a malicious name, for example: `execute\`\`command_injection\`\` `.  Note the backticks.
       - Apply this configuration to your CycleCloud cluster.
    3. **Execute `generateWeightedTemplates.sh`:**
       - Log in to the Symphony master node where HostFactory is installed.
       - Navigate to the `$HF_TOP/$HF_VERSION/providerplugins/azurecc/scripts` directory.
       - Run the script: `./generateWeightedTemplates.sh > /tmp/malicious_templates.json`
    4. **Inspect Generated `azureccprov_templates.json`:**
       - Examine the `/tmp/malicious_templates.json` file.
       - Verify that the `templateId` in the generated JSON for the crafted nodearray contains the injected backticks:
         ```json
         {
           "templates": [
             {
               "templateId": "execute``command_injection`` ",
               "attributes": { ... },
               "vmTypes": { ... },
               "maxNumber": ...
             },
             ...
           ]
         }
         ```
    5. **Simulate HostFactory Loading Template (Manual Verification):**
       - In a test environment, simulate the HostFactory loading and parsing of `/tmp/malicious_templates.json`.
       - Observe if the backticks in `templateId` cause any command execution during parsing or subsequent HostFactory operations, for example, by checking logs or system behavior. A simple way to test is to grep logs for "command_injection" to see if backticks caused command execution during template processing.
    6. **Expected Outcome:**
       - The `azureccprov_templates.json` file should contain the malicious nodearray name as the `templateId` without sanitization.
       - If command injection is successful, you might observe unexpected behavior or entries in system logs related to the injected commands (depending on where and how `templateId` is processed by HostFactory).