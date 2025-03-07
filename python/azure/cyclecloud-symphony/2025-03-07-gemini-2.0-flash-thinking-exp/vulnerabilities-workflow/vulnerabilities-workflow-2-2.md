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
       - In `CycleCloudProvider.templates()` function:
         ```python
         def templates(self):
             try:
                 pro_conf_dir = os.getenv('PRO_CONF_DIR', os.getcwd())
                 conf_path = os.path.join(pro_conf_dir, "conf", "azureccprov_templates.json")
                 with open(conf_path, 'r') as json_file:
                     templates_json = json.load(json_file)
                 templates_json["message"] = "Get available templates success."
                 return self.stdout_handler.handle(templates_json, debug_output=False)
             except:
                 logger.warning("Exiting Non-zero so that symphony will retry")
                 logger.exception(f"Could not get azureccprov_templates.json at {conf_path}")
                 sys.exit(1)
         ```
         - This function reads the `azureccprov_templates.json` file. This is not where the template is *generated*, but where it is *read*.

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

This vulnerability allows for template injection by manipulating nodearray names, leading to potential command execution within the HostFactory context. Input sanitization and template ID validation are necessary mitigations.