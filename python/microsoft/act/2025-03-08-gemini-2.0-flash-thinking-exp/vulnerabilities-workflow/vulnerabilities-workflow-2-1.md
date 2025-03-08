- Vulnerability Name: Insecure Storage of Azure Storage Account Credentials in Configuration Files
- Description:
    1. The AML Command Transfer (ACT) tool requires users to manually create configuration files, specifically `aux_data/configs/vigblob_account.yaml`, to store Azure Storage account credentials. These credentials can include `account_name`, `account_key`, and `sas_token`.
    2. The tool's documentation, as seen in `/code/README.md`, instructs users to create these files and explicitly shows the YAML structure for storing these sensitive credentials in plain text.
    3. These configuration files are stored locally on the user's file system within the `aux_data/configs/` directory of the ACT project.
    4. If a user improperly secures their local ACT project directory, for example by committing it to a public version control repository or by failing to restrict file system permissions, these configuration files, and consequently the Azure Storage account credentials, could be exposed to unauthorized parties.
    5. An attacker who gains access to these configuration files can extract the plain text Azure Storage account credentials.
- Impact:
    - Unauthorized access to the user's Azure Storage account.
    - Potential data breach, allowing the attacker to read, modify, or delete data within the storage account.
    - Resource abuse, where the attacker could utilize the storage account for malicious purposes, potentially incurring costs for the legitimate account owner.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The project provides no built-in mechanisms to secure the storage of Azure Storage account credentials. The documentation instructs users to create configuration files that store credentials in plain text without any security warnings or recommendations.
- Missing Mitigations:
    - **Secure Credential Storage:** The project should be redesigned to avoid storing credentials in plain text configuration files. Consider using more secure methods like:
        - **Azure Key Vault:** Integrate with Azure Key Vault to securely store and retrieve credentials.
        - **Environment Variables:** Encourage or enforce the use of environment variables for credential configuration, which are less likely to be unintentionally exposed in version control.
        - **Credential Encryption:** Implement encryption for the configuration files, requiring a secure decryption key to access the credentials.
    - **Documentation and User Guidance:** The documentation should be updated to:
        - **Warn users explicitly** about the security risks of storing credentials in plain text configuration files.
        - **Provide clear instructions** on how to secure these files, emphasizing the importance of proper file permissions and avoiding committing these files to version control.
        - **Recommend secure alternatives** for credential management, such as Azure Key Vault or environment variables.
- Preconditions:
    - The user has installed the ACT tool and followed the setup instructions to create the configuration files as described in `/code/README.md`.
    - The user has stored Azure Storage account credentials (account name, account key, or SAS token) in `aux_data/configs/vigblob_account.yaml` or similar configuration files.
    - An attacker gains access to the local file system where the ACT project and configuration files are stored. This could be through various means, such as:
        - Compromise of the user's local machine.
        - Accidental exposure of the configuration files in a public repository (e.g., GitHub).
        - Insider threat.
- Source Code Analysis:
    1. **Configuration File Loading:** The `create_cloud_storage` function in `/code/act/cloud_storage.py` is responsible for loading Azure Storage account configurations.
    ```python
    # /code/act/cloud_storage.py
    def create_cloud_storage(x=None, config_file=None, config=None):
        if config is not None:
            return CloudStorage(config)
        if config_file is None:
            config_file = './aux_data/configs/{}blob_account.yaml'.format(x) # config_file path is constructed based on input 'x' or defaults to './aux_data/configs/{}blob_account.yaml'
        config = load_from_yaml_file(config_file) # load_from_yaml_file function is used to read the yaml config file
        c = CloudStorage(config) # CloudStorage object is created with loaded config
        return c
    ```
    This function determines the configuration file path and uses `load_from_yaml_file` from `/code/act/common.py` to parse the YAML file. The default path `./aux_data/configs/{}blob_account.yaml` clearly indicates where the tool expects to find these configuration files.

    2. **YAML Parsing and Credential Extraction:** The `load_from_yaml_file` function in `/code/act/common.py` uses `yaml.load` to parse the YAML configuration file. This function reads the file and directly loads its content into a Python dictionary.
    ```python
    # /code/act/common.py
    def load_from_yaml_file(file_name):
        with open(file_name, 'r') as fp: # opens the config file in read mode
            data = load_from_yaml_str(fp) # load_from_yaml_str is called to parse yaml content
        # ... (rest of the function for handling base configs)
        return data

    def load_from_yaml_str(s):
        return yaml.load(s, Loader=yaml.UnsafeLoader) # yaml.load with UnsafeLoader parses the yaml string and returns python object (dict in this case)
    ```
    `yaml.load(s, Loader=yaml.UnsafeLoader)` directly parses the YAML content from the file, including the `account_name`, `account_key`, and `sas_token` fields, and makes them accessible as values in the returned dictionary.

    3. **`CloudStorage` Class Initialization:** The `CloudStorage` class in `/code/act/cloud_storage.py` then initializes itself using the loaded configuration dictionary.
    ```python
    # /code/act/cloud_storage.py
    class CloudStorage(object):
        def __init__(self, config=None):
            if config is None:
                config_file = 'aux_data/configs/azure_blob_account.yaml'
                config = load_from_yaml_file(config_file) # if no config is passed, it loads default config file
            account_name = config['account_name'] # account_name is directly read from config dict
            account_key = config.get('account_key') # account_key is directly read from config dict
            self.sas_token = config.get('sas_token') # sas_token is directly read from config dict
            self.container_name = config['container_name'] # container_name is directly read from config dict
            # ... (rest of the __init__ function)
    ```
    The `__init__` method directly accesses the `account_name`, `account_key`, and `sas_token` keys from the `config` dictionary, which was loaded from the YAML file. These are then stored as attributes of the `CloudStorage` object, making the plain text credentials readily available for use throughout the class and the ACT tool.

    **Visualization:**

    ```
    User File System --> /code/aux_data/configs/vigblob_account.yaml (Plain Text Credentials)
        ^
        | (Configuration file path - './aux_data/configs/{}blob_account.yaml')
        |
    cloud_storage.create_cloud_storage()
        ^
        | (Loads YAML file content)
        |
    common.load_from_yaml_file()
        ^
        | (Parses YAML to Python dict using yaml.load)
        |
    yaml.load()
        ^
        | (Returns Python dictionary with credentials in plain text)
        |
    CloudStorage.__init__(config)
        ^
        | (Extracts and stores credentials as object attributes)
        |
    CloudStorage Object (Credentials readily accessible in plain text) --> Used for Azure Storage operations
    ```

- Security Test Case:
    1. **Precondition:** Assume you are an external attacker and have gained read access to a system where the ACT tool is installed and configured. This could be through various means, such as exploiting a separate vulnerability to gain unauthorized file system access, or if a user has inadvertently made their ACT project directory publicly accessible (e.g., in a misconfigured shared folder or a public GitHub repository).
    2. **Locate Configuration File:** Navigate to the `aux_data/configs/` directory within the ACT project installation directory.
    3. **Read Configuration File:** Open and read the `vigblob_account.yaml` file (or any other relevant `*blob_account.yaml` file if its name is different).
    4. **Extract Credentials:** Examine the content of the YAML file. Look for the keys `account_name`, `account_key`, and `sas_token`. The corresponding values are the Azure Storage account credentials stored in plain text.
    5. **Verify Access (Optional but Recommended):**
        - Use the extracted `account_name` and `account_key` (or `sas_token`) to attempt to access the Azure Storage account using tools like Azure Storage Explorer, `azcopy`, or the Azure CLI.
        - Try to list containers or download blobs to confirm unauthorized access.
    6. **Expected Result:** You should be able to successfully extract the Azure Storage account credentials in plain text from the configuration file. If you proceed to step 5, you should be able to confirm unauthorized access to the Azure Storage account. This demonstrates the vulnerability of insecure credential storage.