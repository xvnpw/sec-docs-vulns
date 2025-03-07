- Vulnerability Name: Sensitive Data Exposure via Command-Line History
- Description:
    1. A user executes an Azure CLI command using the `az sapmonitor provider-instance create` command to create a provider instance for SAP Monitor.
    2. The user includes sensitive credentials, such as database passwords, directly within the `--provider-instance-properties` parameter as shown in the `README.md` documentation. For example:
        ```bash
        az sapmonitor provider-instance create \
            --resource-group $RESOURCE_GROUP \
            --monitor-name $SAP_MONITOR_NAME \
            --provider-instance-name $PROVIDER_INSTANCE_NAME \
            --provider-instance-type SapHana \
            --provider-instance-properties '{"hanaHostname":"10.0.0.6","hanaDbName":"SYSTEMDB","hanaDbSqlPort":30013,"hanaDbUsername":"SYSTEM"," hanaDbPassword":"password"}'
        ```
    3. The shell command, including the plaintext password, is recorded in the user's shell history file (e.g., `.bash_history` for Bash, `.zsh_history` for Zsh).
    4. An attacker gains unauthorized access to the user's system or account. This could be through various means such as malware, phishing, or insider threat.
    5. The attacker reads the shell history file.
    6. The attacker finds the previously executed Azure CLI command containing the plaintext password.
    7. The attacker extracts the sensitive credentials (e.g., `hanaDbPassword`) from the command.
    8. The attacker uses these credentials to gain unauthorized access to the SAP HANA system, potentially leading to data breaches or further system compromise.
- Impact:
    Successful exploitation of this vulnerability can lead to the exposure of sensitive credentials for SAP HANA systems. An attacker with access to these credentials can:
    1. Gain unauthorized access to SAP HANA databases.
    2. Read, modify, or delete sensitive data within the SAP HANA system.
    3. Potentially pivot to other systems or resources accessible from the compromised SAP HANA environment.
    4. Cause significant business disruption and financial loss due to data breaches, system downtime, or regulatory fines.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    Key Vault integration is implemented for storing and retrieving database passwords. In `azext_hanaonazure/custom.py`, the `create_providerinstance` function includes logic to handle `hanaDbPasswordKeyVaultUrl` and `keyVaultId` in `provider_instance_properties`. This allows users to securely manage passwords using Azure Key Vault instead of directly providing them in the command-line.
- Missing Mitigations:
    1. Remove or deprecate the direct password input option (`hanaDbPassword`, `sqlPassword` etc.) in command-line parameters to enforce secure credential management practices.
    2. Implement a clear warning message in the CLI when users attempt to use direct password input in commands. This warning should advise against this practice and strongly recommend using secure alternatives like Azure Key Vault.
    3. Update the `README.md` and help documentation to remove examples that show passwords in command-line parameters and instead emphasize the use of Azure Key Vault for secure credential management. Provide clear instructions and examples on how to use Key Vault with the extension.
- Preconditions:
    1. The user must use the `az sapmonitor provider-instance create` command or similar commands that accept sensitive credentials as direct command-line parameters.
    2. The user must choose to provide the sensitive credentials directly in the command-line parameter (e.g., `--provider-instance-properties '{"hanaDbPassword":"password"}'`) instead of using secure alternatives like Key Vault.
    3. The user's shell history must be enabled and accessible to a potential attacker.
- Source Code Analysis:
    1. File: `/code/azext_hanaonazure/custom.py`
    2. Function: `create_providerinstance`
    3. The function `create_providerinstance` is responsible for handling the creation of provider instances for SAP Monitor.
    4. It takes `provider_instance_properties` as a parameter, which is expected to be a JSON string.
    5. ```python
       def create_providerinstance(
             cmd,
             client,
             resource_group_name,
             monitor_name,
             provider_instance_name,
             provider_instance_type,
             provider_instance_properties, # Vulnerable parameter
             provider_instance_metadata=None):
           import json
           properties_json = json.loads(provider_instance_properties) # Parses JSON properties, including potential passwords
       ```
    6. The code parses the `provider_instance_properties` JSON string using `json.loads()`. This JSON string, supplied directly by the user in the command line, can contain sensitive information like `hanaDbPassword` as shown in `README.md`.
    7. While the code includes a conditional block to handle Key Vault URLs for `SapHana` provider type:
       ```python
       if provider_instance_type == 'SapHana':
           if 'hanaDbPasswordKeyVaultUrl' in properties_json and 'keyVaultId' in properties_json:
               # Keyvault URL was passed in
               # ... Key Vault integration logic ...
           elif 'hanaDbPassword' not in properties_json:
               raise ValueError("Either hanaDbPassword or both hanaDbPasswordKeyVaultUrl and keyVaultId.")
       ```
    8. This Key Vault integration is a mitigation, but the code still accepts and processes `hanaDbPassword` directly from `properties_json` if Key Vault parameters are not provided.
    9. The `README.md` examples encourage users to pass passwords directly within `provider_instance_properties`, leading to the vulnerability.
    10. Visualization:

    ```mermaid
    graph LR
        A[User Command Line Input: az sapmonitor provider-instance create --provider-instance-properties '{"hanaDbPassword":"password"}' ] --> B(CLI Parameter Parsing)
        B --> C{custom.py: create_providerinstance()}
        C --> D[properties_json = json.loads(provider_instance_properties)]
        D --> E{Check for KeyVault Params}
        E -- No KeyVault --> F[Use hanaDbPassword from properties_json]
        F --> G[API Call with properties_json]
        E -- KeyVault Params --> H[KeyVault Logic (Mitigation)]
        H --> G
    ```
- Security Test Case:
    1. Precondition: Ensure Azure CLI with `sap-hana` extension is installed and configured.
    2. Step 1: Execute the `az sapmonitor provider-instance create` command with a plaintext password in `--provider-instance-properties`. Replace placeholders with your actual resource group, monitor name, provider instance name, and a test password.
        ```bash
        az sapmonitor provider-instance create \
            --resource-group <your_resource_group> \
            --monitor-name <your_monitor_name> \
            --provider-instance-name test-provider-instance \
            --provider-instance-type SapHana \
            --provider-instance-properties '{"hanaHostname":"<hana_hostname>","hanaDbName":"SYSTEMDB","hanaDbSqlPort":30013,"hanaDbUsername":"SYSTEM","hanaDbPassword":"P@$$wOrd123"}'
        ```
        *(Note: Replace `<hana_hostname>` with a placeholder or a non-production HANA hostname for testing purposes. This test case is to demonstrate credential exposure in history, not to actually connect to HANA.)*
    3. Step 2: Check Shell History.
        - For Bash, use: `history | grep "az sapmonitor provider-instance create"`
        - For Zsh, use: `history | grep "az sapmonitor provider-instance create"`
        - For PowerShell, use: `Get-History | Where-Object {$_.CommandLine -like "*az sapmonitor provider-instance create*"}`
    4. Step 3: Observe the output. The command you executed in Step 1, including the plaintext password `P@$$wOrd123` (or your chosen password), should be present in the shell history.
    5. Step 4: (Simulate Attacker) As an attacker who has gained access to the user's shell environment, retrieve the shell history file (e.g., `.bash_history`).
    6. Step 5: (Simulate Attacker) Search the history file for the `az sapmonitor provider-instance create` command.
    7. Step 6: (Simulate Attacker) Extract the plaintext password `P@$$wOrd123` from the command.
    8. Step 7: (Simulate Attacker) The attacker now possesses the plaintext password that was intended to be secret.

This test case demonstrates that sensitive credentials provided directly in the command-line parameters are indeed recorded in shell history, confirming the vulnerability.