#### 1. Insecure Storage of Azure Credentials in Configuration Files

- **Description:**
    1. The ACT tool relies on configuration files (`vigblob_account.yaml`, `config.json`, `aml.yaml`) stored locally on the user's machine.
    2. The `README.md` documentation instructs users to manually create these files and store sensitive Azure credentials in plain text within them. This includes:
        - `vigblob_account.yaml`: Azure Storage account `account_name`, `account_key`, and `sas_token`.
        - `config.json`: Azure Machine Learning workspace `subscription_id`, `resource_group`, and `workspace_name`.
    3. An attacker who gains unauthorized access to the user's local machine (e.g., through malware, phishing, or physical access) can easily read these configuration files.
    4. By extracting the plain text credentials, the attacker can impersonate the user and gain full unauthorized access to their Azure Machine Learning environment.

- **Impact:**
    - **Critical Account Compromise:** Successful exploitation grants the attacker complete control over the victim's Azure Machine Learning environment.
    - **Data Breach:** Attackers can access, modify, or delete sensitive data stored in Azure Machine Learning workspaces and linked storage accounts.
    - **Malicious Operations:** Attackers can run arbitrary code and commands within the victim's Azure ML environment, potentially leading to resource abuse, data manipulation, or further attacks on connected systems.
    - **Financial Impact:** Attackers may incur significant costs by utilizing the victim's Azure subscription resources for their own purposes.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - None. The project currently provides no security mechanisms to protect the stored credentials. The `README.md` documentation explicitly instructs users to store credentials in plain text.

- **Missing Mitigations:**
    - **Credential Encryption:** Implement encryption for sensitive fields within the configuration files. This would prevent plain text exposure even if the files are accessed by an attacker.
    - **Secure Credential Storage:** Recommend and ideally integrate with secure credential storage mechanisms provided by the operating system (e.g., Credential Manager on Windows, Keychain on macOS, or dedicated secret management tools).
    - **Azure Key Vault Integration:** Explore and implement integration with Azure Key Vault to securely store and retrieve Azure credentials, avoiding local storage altogether.
    - **Principle of Least Privilege:** Encourage users to use Service Principals with restricted permissions instead of full account keys where possible.
    - **Security Warnings:** Add prominent warnings in the `README.md` and during the setup process about the security risks of storing credentials in plain text and recommend best practices for secure credential management.

- **Preconditions:**
    1. The user has installed the ACT tool and configured it by creating the configuration files as instructed in the `README.md`.
    2. The configuration files (`vigblob_account.yaml`, `config.json`, `aml.yaml`) are stored on the user's local file system.
    3. An attacker gains unauthorized access to the user's local machine.

- **Source Code Analysis:**
    1. **`File: /code/README.md`**:
        - Step 3 and 4 of the "Setup" section explicitly instruct the user to create `vigblob_account.yaml` and `config.json` files and store sensitive credentials like `account_key`, `sas_token`, `subscription_id`, `resource_group`, and `workspace_name` in plain text within these files.
    2. **`File: /code/act/cloud_storage.py`**:
        - `def create_cloud_storage(x=None, config_file=None, config=None):` function is responsible for creating `CloudStorage` objects.
        - It loads configuration from yaml files using `load_from_yaml_file(config_file)`.
        - The loaded configuration, which includes `account_name`, `account_key`, and `sas_token` from `vigblob_account.yaml`, is directly passed to the `CloudStorage` class constructor: `c = CloudStorage(config)`.
        - `class CloudStorage(object):` constructor `__init__(self, config=None):` directly assigns `account_name`, `account_key`, and `sas_token` from the `config` dictionary to instance attributes: `self.account_name = account_name`, `self.account_key = account_key`, `self.sas_token = self.sas_token`. These attributes are then used to initialize the `BlockBlobService` or `BlobServiceClient` for interacting with Azure Storage.
    3. **`File: /code/act/aml_client.py`**:
        - `def create_aml_client(**kwargs):` function handles the creation of `AMLClient` objects.
        - It loads configuration from `aml.yaml` and `config.json` using `load_from_yaml_file`.
        - It reads the `aml_config` path from `aml.yaml` which points to `config.json`.
        - It also reads `azure_blob_config_file` paths from `aml.yaml` (e.g., for `code_path`, `data_folder`, `output_folder`), which point to files like `vigblob_account.yaml`.
        - The loaded configurations, including credentials from `vigblob_account.yaml` and workspace details from `config.json`, are used to initialize `AMLClient` and `CloudStorage` objects, enabling interaction with Azure services using the plain text credentials.

    **Visualization:**

    ```
    README.md (Setup Instructions) --> User creates config files (vigblob_account.yaml, config.json) with plain text credentials
                                        |
                                        V
    act/aml_client.py (create_aml_client) --> Loads config files using load_from_yaml_file
                                                |
                                                V
    act/cloud_storage.py (create_cloud_storage) --> Loads vigblob_account.yaml using load_from_yaml_file
                                                        |
                                                        V
    CloudStorage.__init__ --> Stores plain text credentials (account_key, sas_token) as attributes
                                                        |
                                                        V
    CloudStorage methods (e.g., upload, download) --> Uses plain text credentials to authenticate with Azure Storage
    AMLClient methods (e.g., submit, query)        --> Uses CloudStorage objects to interact with Azure services
    ```

- **Security Test Case:**
    1. **Setup ACT and Configuration:**
        - Follow steps 1-6 in the `README.md` to install ACT and create the configuration files: `aux_data/configs/vigblob_account.yaml`, `aux_data/aml/config.json`, and `aux_data/aml/aml.yaml`.
        - Populate these configuration files with valid (or test) Azure credentials. For example, in `vigblob_account.yaml`, enter a valid `account_name` and `account_key` (or a SAS token). In `config.json`, provide valid `subscription_id`, `resource_group`, and `workspace_name` for an Azure ML workspace.
    2. **Simulate Attacker Access:**
        - Assume the attacker has gained access to the local machine where ACT is installed. This could be simulated by simply opening a terminal on the same machine or by copying the `aux_data` folder to a separate attacker-controlled system.
    3. **Examine Configuration Files:**
        - Navigate to the `aux_data/configs/vigblob_account.yaml` file and open it in a text editor or using a command like `cat aux_data/configs/vigblob_account.yaml`.
        - Observe that the `account_key` and `sas_token` (if used) are stored in plain text and are directly readable.
        - Similarly, examine `aux_data/aml/config.json` and verify that `subscription_id`, `resource_group`, and `workspace_name` are also in plain text.
    4. **Extract Credentials:**
        - Manually copy the plain text `account_key` or `sas_token` from `vigblob_account.yaml` and the `subscription_id`, `resource_group`, and `workspace_name` from `config.json`.
    5. **Attempt Unauthorized Azure Access (Optional Exploit Demonstration):**
        - Install the Azure CLI (`az`).
        - Use the extracted `subscription_id` and `workspace_name` to attempt to log in to the Azure ML workspace using the Azure CLI.  This might require additional steps depending on the type of credentials used (account key or SAS token). For instance, with an account key, you might try to configure Azure Storage access using `az storage account keys list`.
        - If successful, demonstrate unauthorized access by listing resources within the workspace (e.g., `az ml workspace list`) or performing other actions that would be possible with valid user credentials.

This test case demonstrates that the Azure credentials are indeed stored in plain text and are easily accessible to an attacker with local machine access, confirming the vulnerability.