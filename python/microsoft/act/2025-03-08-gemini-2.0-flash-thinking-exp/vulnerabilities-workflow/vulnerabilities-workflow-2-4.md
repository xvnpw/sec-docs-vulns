- vulnerability name: Hardcoded Azure Credentials in Configuration Files
  - description: |
    The tool's documentation instructs users to store Azure account keys, SAS tokens, and other Azure service principal credentials in YAML and JSON configuration files. These files are intended to be stored locally by the user. However, if these files are not properly secured, they can be unintentionally exposed. For example, users might mistakenly commit these configuration files to public version control repositories, leave them in directories with overly permissive access rights, or inadvertently share them.

    Step-by-step to trigger the vulnerability:
    1. User follows the installation instructions in `README.md`.
    2. User creates configuration files as instructed: `aux_data/configs/vigblob_account.yaml`, `aux_data/aml/config.json`, and potentially modifies `aux_data/aml/aml.yaml` to include paths to credential files.
    3. User stores Azure credentials (account key, SAS token, subscription ID, resource group, workspace name) in these configuration files in plain text as instructed.
    4. User unintentionally exposes these configuration files, for example by:
        - Committing the files to a public Git repository.
        - Storing the files in a publicly accessible directory on a server.
        - Sharing the files through insecure channels.
    5. An attacker discovers these exposed configuration files.
    6. The attacker extracts the Azure credentials (account key, SAS token, etc.) from the configuration files.
    7. The attacker uses these extracted credentials to authenticate to the victim's Azure account.
    8. The attacker gains unauthorized access to the victim's Azure Machine Learning resources.

  - impact: |
    Successful exploitation of this vulnerability allows an attacker to gain unauthorized access to the victim's Azure Machine Learning resources. This can lead to severe consequences, including:
    - **Data Breach:** The attacker can access, download, modify, or delete sensitive data stored in Azure Blob Storage and other Azure services accessible with the compromised credentials.
    - **Resource Hijacking:** The attacker can utilize the victim's Azure Machine Learning compute resources to execute arbitrary commands, potentially for malicious purposes like cryptocurrency mining, launching further attacks, or disrupting services.
    - **Denial of Service:** The attacker can intentionally or unintentionally disrupt the victim's Azure Machine Learning workloads, leading to a denial of service.
    - **Lateral Movement:** In a more complex scenario, the attacker might use the compromised Azure account as a stepping stone to gain access to other parts of the victim's cloud infrastructure or on-premises network if the Azure environment is connected to other systems.
    - **Reputational Damage:** A security breach resulting from exposed credentials can severely damage the reputation of the victim organization.

  - vulnerability rank: Critical
  - currently implemented mitigations:
    - None. The project provides instructions that lead to the vulnerability without any security warnings or mitigations.
  - missing mitigations: |
    - **Secure Credential Storage Recommendation and Implementation:** The project should strongly discourage storing credentials in plain text configuration files. Instead, it should:
        - Recommend secure alternatives for credential storage, such as:
            - Azure Key Vault: For securely managing secrets.
            - Azure Managed Identities: For authenticating Azure services without embedding credentials in code or config files.
            - Environment Variables: For injecting credentials at runtime, preferably in a secure environment.
        - Provide code examples and documentation on how to integrate these secure methods into the tool.
    - **Documentation Security Warning:** The documentation (especially `README.md` and any setup guides) must include a prominent and clear security warning about the dangers of storing credentials in configuration files. This warning should:
        - Explicitly state the risks of exposing credentials.
        - Strongly recommend against committing configuration files containing credentials to version control.
        - Guide users towards secure credential management practices.
    - **Credential Input Redesign (Long-term):** Consider redesigning the tool to minimize or eliminate the need for users to manually manage and store long-lived credentials. Explore options like:
        - Interactive authentication flows (Azure CLI login) for initial setup.
        - Just-in-time credential retrieval from secure stores.
        - Role-Based Access Control (RBAC) and least privilege principles to limit the scope of access granted by credentials.
  - preconditions: |
    - User must follow the installation and configuration instructions in the `README.md`.
    - User must create the configuration files (`vigblob_account.yaml`, `config.json`, `aml.yaml`) and store Azure credentials in them as instructed.
    - These configuration files must be exposed to an attacker through insecure storage or sharing practices.
  - source code analysis: |
    1. **Credential Loading in `act/cloud_storage.py`:**
        - The `create_cloud_storage` function in `/code/act/cloud_storage.py` is responsible for creating `CloudStorage` objects.
        - It loads configuration from YAML files using `load_from_yaml_file` (from `/code/act/common.py`).
        - It reads `account_name`, `account_key`, and `sas_token` directly from the loaded configuration dictionary.
        ```python
        def create_cloud_storage(x=None, config_file=None, config=None):
            # ...
            config = load_from_yaml_file(config_file)
            c = CloudStorage(config) # Credentials passed to CloudStorage constructor
            return c

        class CloudStorage(object):
            def __init__(self, config=None):
                # ...
                account_name = config['account_name'] # Account name loaded from config
                account_key = config.get('account_key') # Account key loaded from config
                self.sas_token = config.get('sas_token') # SAS token loaded from config
                # ...
        ```
    2. **Configuration Instructions in `README.md`:**
        - The `README.md` file, specifically steps 3, 4, and 5 under "Installation", explicitly instructs users to create and populate YAML and JSON files with Azure credentials.
        - Step 3 for `vigblob_account.yaml`:
        ```markdown
        3. Create the config file of `aux_data/configs/vigblob_account.yaml` for azure storage.
           The file format is
           ```yaml
           account_name: xxxx
           account_key: xxxx
           sas_token: ?xxxx
           container_name: xxxx
           ```
           The SAS token should start with the question mark.
        ```
        - This clearly shows the intended way to configure credentials is by hardcoding them into files.
    3. **Credential Usage in `CloudStorage` Class:**
        - The `CloudStorage` class then uses these `account_key` and `sas_token` attributes to instantiate Azure Blob Storage clients, as seen in the `block_blob_service` property:
        ```python
        @property
        def block_blob_service(self):
            if self._block_blob_service is None:
                if self.is_new_package:
                    # ...
                    if self.sas_token:
                        self._block_blob_service = BlobServiceClient(
                            account_url='https://{}.blob.core.windows.net'.format(self.account_name),
                            credential=self.sas_token) # SAS token used as credential
                    else:
                        self._block_blob_service = BlobServiceClient(
                            account_url='https://{}.blob.core.windows.net/'.format(self.account_name),
                            credential={'account_name': self.account_name, 'account_key': self.account_key}) # Account key used as credential
                else:
                    from azure.storage.blob import BlockBlobService
                    self._block_blob_service = BlockBlobService(
                            account_name=self.account_name,
                            account_key=self.account_key, # Account key used as credential
                            sas_token=self.sas_token) # SAS token used as credential
            return self._block_blob_service
        ```
    - This analysis confirms that the code directly loads and uses credentials from configuration files as instructed by the documentation, creating the hardcoded credential vulnerability.

  - security test case: |
    1. **Setup:**
        - Install the ACT tool as described in the `README.md`.
        - Create the configuration file `aux_data/configs/vigblob_account.yaml` with the following content, replacing placeholders with **dummy values**:
        ```yaml
        account_name: dummyaccountname
        account_key: dummyaccountkey
        sas_token: ?dummysastoken
        container_name: dummycontainername
        ```
        - Create the configuration file `aux_data/aml/config.json` with the following content, replacing placeholders with **dummy values**:
        ```json
        {
            "subscription_id": "dummysubscriptionid",
            "resource_group": "dummyresourcegroup",
            "workspace_name": "dummyworkspacename"
        }
        ```
        - Create the configuration file `aux_data/aml/aml.yaml` with the following content:
        ```yaml
        azure_blob_config_file: ./aux_data/configs/vigblob_account.yaml
        aml_config: aux_data/aml/config.json
        config_param:
            code_path:
                azure_blob_config_file: ./aux_data/configs/vigblob_account.yaml
                path: path/to/code.zip
            data_folder:
                azure_blob_config_file: ./aux_data/configs/vigblob_account.yaml
                path: path/to/data
            output_folder:
                azure_blob_config_file: ./aux_data/configs/vigblob_account.yaml
                path: path/to/output
        platform: aml
        compute_target: dummycomputetarget
        experiment_name: dummyexperimentname
        ```
        - Make the `aux_data/configs/vigblob_account.yaml` file publicly accessible. For example, create a public GitHub repository, commit the file, and make the repository public. Note down the raw URL of the `vigblob_account.yaml` file in the public repository.
    2. **Attack:**
        - As an attacker, access the publicly hosted `vigblob_account.yaml` file using its raw URL.
        - Open the file and observe the `account_key` and `sas_token` values (which are the dummy values in this test case).
        - Try to use the ACT tool with a command. For example, set the alias as instructed in `README.md`:
        ```bash
        alias a='python -m act.aml_client '
        ```
        - Run a command that would attempt to use the dummy credentials:
        ```bash
        a -c aml submit ls data
        ```
        - Observe the output and error messages.
    3. **Expected Result:**
        - The attacker successfully retrieves the dummy Azure account key and SAS token from the publicly accessible `vigblob_account.yaml` file.
        - When running `a -c aml submit ls data`, the ACT tool will attempt to use the dummy credentials to access Azure.
        - Due to the dummy credentials, the Azure operation will likely fail with an authentication error or authorization error. However, the attempt itself demonstrates that the tool is indeed using the credentials from the exposed configuration file.
        - In a real-world scenario where valid credentials are exposed, the attacker would successfully authenticate and gain unauthorized access to the Azure resources.