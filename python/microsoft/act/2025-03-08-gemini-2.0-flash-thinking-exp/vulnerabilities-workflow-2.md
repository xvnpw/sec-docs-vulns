## Combined Vulnerability Report

### 1. Insecure Storage of Azure Credentials in Configuration Files

- **Description:**
    1. The AML Command Transfer (ACT) tool relies on various configuration files (`vigblob_account.yaml`, `config.json`, `aml.yaml`) stored locally on the user's machine.
    2. The tool's documentation, as found in `README.md`, explicitly instructs users to manually create these files and store sensitive Azure credentials in plain text within them. This includes:
        - `vigblob_account.yaml`: Azure Storage account credentials such as `account_name`, `account_key`, and `sas_token`.
        - `config.json`: Azure Machine Learning workspace credentials including `subscription_id`, `resource_group`, and `workspace_name`.
    3. These configuration files are stored locally on the user's file system within the `aux_data/configs/` and `aux_data/aml/` directories of the ACT project.
    4. If a user improperly secures their local ACT project directory, for example by committing it to a public version control repository, by failing to restrict file system permissions, or through malware on the user's machine, these configuration files, and consequently the Azure credentials, could be exposed to unauthorized parties.
    5. An attacker who gains access to these configuration files can extract the plain text Azure credentials.
    6. By extracting the plain text credentials, the attacker can impersonate the user and gain unauthorized access to their Azure Machine Learning environment and Azure Storage accounts.

- **Impact:**
    - **Critical Account Compromise:** Successful exploitation grants the attacker complete control over the victim's Azure Machine Learning environment and associated Azure Storage accounts.
    - **Data Breach:** Attackers can access, modify, or delete sensitive data stored in Azure Machine Learning workspaces and linked storage accounts.
    - **Resource Hijacking:** Attackers can utilize the victim's Azure Machine Learning compute resources to execute arbitrary commands, potentially for malicious purposes such as cryptocurrency mining or launching further attacks.
    - **Malicious Operations:** Attackers can run arbitrary code and commands within the victim's Azure ML environment, potentially leading to data manipulation, or further attacks on connected systems.
    - **Financial Impact:** Attackers may incur significant costs by utilizing the victim's Azure subscription resources for their own purposes.
    - **Reputational Damage:** A security breach resulting from exposed credentials can severely damage the reputation of the victim organization.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - None. The project currently provides no security mechanisms to protect the stored credentials. The documentation explicitly instructs users to store credentials in plain text without any security warnings or recommendations.

- **Missing Mitigations:**
    - **Secure Credential Storage:** The project should be redesigned to avoid storing credentials in plain text configuration files. Consider using more secure methods like:
        - **Azure Key Vault Integration:** Integrate with Azure Key Vault to securely store and retrieve credentials, avoiding local storage in configuration files altogether.
        - **Azure Managed Identities:** Explore and implement integration with Azure Managed Identities to authenticate Azure services without embedding credentials in configuration files.
        - **Environment Variables:** Encourage or enforce the use of environment variables for credential configuration, which are less likely to be unintentionally exposed in version control and can be managed more securely within deployment environments.
        - **Credential Encryption:** Implement encryption for sensitive fields within the configuration files. This would prevent plain text exposure even if the files are accessed by an attacker.
        - **Secure Credential Storage Recommendation:** Recommend and ideally integrate with secure credential storage mechanisms provided by the operating system (e.g., Credential Manager on Windows, Keychain on macOS, or dedicated secret management tools).
    - **Documentation and User Guidance:** The documentation (especially `README.md` and any setup guides) should be updated to:
        - **Warn users explicitly and prominently** about the security risks of storing credentials in plain text configuration files.
        - **Provide clear instructions** on how to secure these files if local storage is absolutely necessary, emphasizing the importance of proper file permissions and avoiding committing these files to version control.
        - **Recommend secure alternatives** for credential management, such as Azure Key Vault, Azure Managed Identities or environment variables, and provide guidance on how to use them with the ACT tool.
    - **Principle of Least Privilege:** Encourage users to use Service Principals with restricted permissions instead of full account keys where possible to limit the potential damage from compromised credentials.
    - **Credential Input Redesign (Long-term):** Consider redesigning the tool to minimize or eliminate the need for users to manually manage and store long-lived credentials. Explore options like:
        - Interactive authentication flows (Azure CLI login) for initial setup.
        - Just-in-time credential retrieval from secure stores.
        - Role-Based Access Control (RBAC) and least privilege principles to limit the scope of access granted by credentials.

- **Preconditions:**
    - The user has installed the ACT tool and followed the setup instructions in `README.md` to create the configuration files.
    - The user has stored Azure credentials (account name, account key, SAS token, subscription ID, resource group, workspace name) in configuration files like `vigblob_account.yaml`, `config.json`, or `aml.yaml` as instructed.
    - An attacker gains access to the local file system where the ACT project and configuration files are stored. This could be through various means, such as:
        - Compromise of the user's local machine (e.g., malware, phishing, physical access).
        - Accidental exposure of the configuration files in a public repository (e.g., GitHub).
        - Insider threat.
        - Storing the files in a publicly accessible directory on a server.
        - Sharing the files through insecure channels.

- **Source Code Analysis:**
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
    This function uses `load_from_yaml_file` from `/code/act/common.py` to parse YAML files. Similarly, `aml_client.py` also uses `load_from_yaml_file` for `aml.yaml` and `config.json`.

    2. **YAML/JSON Parsing and Credential Extraction:** The `load_from_yaml_file` function in `/code/act/common.py` uses `yaml.load` to parse YAML and `json.load` to parse JSON configuration files.
    ```python
    # /code/act/common.py
    import yaml
    import json

    def load_from_yaml_file(file_name):
        with open(file_name, 'r') as fp: # opens the config file in read mode
            if file_name.endswith(('.yaml', '.yml')):
                data = load_from_yaml_str(fp) # load_from_yaml_str is called to parse yaml content
            elif file_name.endswith('.json'):
                data = json.load(fp)
        # ... (rest of the function for handling base configs)
        return data

    def load_from_yaml_str(s):
        return yaml.load(s, Loader=yaml.UnsafeLoader) # yaml.load with UnsafeLoader parses the yaml string and returns python object (dict in this case)
    ```
    `yaml.load(s, Loader=yaml.UnsafeLoader)` and `json.load(fp)` directly parse the content from the files, including sensitive credentials like `account_name`, `account_key`, `sas_token`, `subscription_id`, `resource_group`, and `workspace_name`, and makes them accessible as values in the returned Python dictionaries.

    3. **`CloudStorage` and `AMLClient` Class Initialization:** The `CloudStorage` class in `/code/act/cloud_storage.py` and `AMLClient` class in `/code/act/aml_client.py` then initialize themselves using the loaded configuration dictionaries.
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
    ```python
    # /code/act/aml_client.py
    class AMLClient(object):
        def __init__(self, aml_config_file, azure_blob_config_file,
                     config_param, platform='aml', compute_target=None,
                     experiment_name=None, **kwargs):
            # ...
            aml_config = load_from_yaml_file(aml_config_file)
            config_json_file = aml_config['aml_config']
            config_json = load_from_yaml_file(config_json_file) # actually json is loaded by load_from_yaml_file
            self.subscription_id = config_json['subscription_id']
            self.resource_group = config_json['resource_group']
            self.workspace_name = config_json['workspace_name']
            # ...
            self.azure_blob_config = load_from_yaml_file(azure_blob_config_file)
            self.cloud_storage = create_cloud_storage(config=self.azure_blob_config) # CloudStorage created with loaded config
            # ...
    ```
    The `__init__` methods directly access the credential keys from the `config` dictionaries, which were loaded from the configuration files. These are then stored as attributes of the objects, making the plain text credentials readily available for use throughout the classes and the ACT tool. The `README.md` documentation further reinforces this insecure practice by explicitly instructing users to store credentials in these files.

    **Visualization:**

    ```
    README.md (Setup Instructions) --> User creates config files (vigblob_account.yaml, config.json, aml.yaml) with plain text credentials
                                        |
                                        V
    act/aml_client.py (AMLClient.__init__) --> Loads config files using load_from_yaml_file
                                                |
                                                V
    act/cloud_storage.py (CloudStorage.__init__) --> Loads vigblob_account.yaml using load_from_yaml_file
                                                        |
                                                        V
    common.load_from_yaml_file() --> Parses YAML/JSON to Python dict using yaml.load/json.load
                                                        |
                                                        V
    YAML.load/JSON.load() --> Returns Python dictionary with credentials in plain text
                                                        |
                                                        V
    CloudStorage/AMLClient Objects --> Stores plain text credentials as attributes
                                                        |
                                                        V
    CloudStorage methods (e.g., upload, download) --> Uses plain text credentials to authenticate with Azure Storage
    AMLClient methods (e.g., submit, query)        --> Uses CloudStorage objects and workspace credentials to interact with Azure services
    ```

- **Security Test Case:**
    1. **Setup ACT and Configuration:**
        - Follow steps 1-6 in the `README.md` to install ACT and create the configuration files: `aux_data/configs/vigblob_account.yaml`, `aux_data/aml/config.json`, and `aux_data/aml/aml.yaml`.
        - Populate these configuration files with valid (or test) Azure credentials. For example, in `vigblob_account.yaml`, enter a valid `account_name` and `account_key` (or a SAS token). In `config.json`, provide valid `subscription_id`, `resource_group`, and `workspace_name` for an Azure ML workspace.
    2. **Simulate Attacker Access:**
        - Assume the attacker has gained access to the local machine where ACT is installed. This could be simulated by simply opening a terminal on the same machine or by copying the `aux_data` folder to a separate attacker-controlled system. Or, for remote access scenario, make `aux_data/configs/vigblob_account.yaml` file publicly accessible by hosting it in public GitHub repository.
    3. **Examine Configuration Files:**
        - Navigate to the `aux_data/configs/vigblob_account.yaml` file and open it in a text editor or using a command like `cat aux_data/configs/vigblob_account.yaml`.
        - Observe that the `account_key` and `sas_token` (if used) are stored in plain text and are directly readable.
        - Similarly, examine `aux_data/aml/config.json` and verify that `subscription_id`, `resource_group`, and `workspace_name` are also in plain text.
    4. **Extract Credentials:**
        - Manually copy the plain text `account_key` or `sas_token` from `vigblob_account.yaml` and the `subscription_id`, `resource_group`, and `workspace_name` from `config.json`.
    5. **Attempt Unauthorized Azure Access (Optional Exploit Demonstration):**
        - Install the Azure CLI (`az`).
        - Use the extracted `account_name` and `account_key` (or `sas_token`) to attempt to access the Azure Storage account using tools like Azure Storage Explorer, `azcopy`, or the Azure CLI.  Try to list containers or download blobs to confirm unauthorized access.
        - Use the extracted `subscription_id`, `resource_group`, and `workspace_name` to attempt to log in to the Azure ML workspace using the Azure CLI. For instance, try to list resources within the workspace (e.g., `az ml workspace list`).
    6. **Expected Result:** You should be able to successfully extract the Azure credentials in plain text from the configuration files. If you proceed to step 5, you should be able to confirm unauthorized access to the Azure Storage account and Azure ML workspace. This demonstrates the vulnerability of insecure credential storage.

### 2. Command Injection in `submit cmd` functionality

- **Description:**
    1. A malicious user crafts a command containing shell injection payloads.
    2. The user executes the ACT command `a submit <malicious_command>` via the command-line interface.
    3. The `aml_client.py` script packages this command and submits it to Azure Machine Learning service.
    4. The `aml_server.py` script, running within the AML environment, receives the crafted command.
    5. `aml_server.py` uses `subprocess.Popen` to execute the command, while splitting the command string by spaces and without sufficient sanitization.
    6. Due to lack of sanitization, shell injection payloads within the command are executed by the underlying shell in the AML compute environment.
    7. This allows the attacker to execute arbitrary commands within the AML compute context.

- **Impact:**
    - Arbitrary command execution within the Azure Machine Learning compute environment.
    - Potential for unauthorized access to data and resources within the AML workspace and potentially other connected Azure services.
    - Data exfiltration from the AML environment.
    - Modification or deletion of data and AML configurations.
    - Potential for denial of service by consuming compute resources or disrupting AML services.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - None. The code directly executes user-provided commands without any input sanitization or validation.

- **Missing Mitigations:**
    - **Input sanitization on the client-side (`aml_client.py`)**: Implement sanitization to escape or reject shell metacharacters in user-provided commands before submitting them to the AML service.
    - **Secure Command Execution in `aml_server.py`**:
        - Avoid splitting the command string by spaces in `wrap_all` function. Pass the command as a single string argument to `cmd_run`.
        - In `cmd_run`, use secure command execution practices such as:
            - Avoiding the use of `shell=True` in `subprocess.Popen`.
            - Passing commands as a list to `subprocess.Popen` where the first element is the executable and subsequent elements are arguments, ensuring that no shell interpretation occurs on the command string itself. If using this approach, ensure the command is properly parsed and arguments are separated without relying on shell splitting.
            - If shell execution is absolutely necessary, implement robust input validation and sanitization to prevent shell injection. Consider using parameterized commands or prepared statements if applicable.
    - **Principle of Least Privilege**: Employ principle of least privilege by running AML jobs with minimal necessary permissions to limit the blast radius of a successful command injection attack.

- **Preconditions:**
    - The attacker needs to have access to the ACT command-line tool.
    - The attacker needs to have valid Azure credentials to configure ACT and submit jobs to the Azure Machine Learning service.

- **Source Code Analysis:**
    1. **`act/aml_client.py` - `AMLClient.submit` function:**
        ```python
        def submit(self, cmd, num_gpu=None):
            # ...
            script_params = {'--' + p: str(v['mount_point']) if not v.get('submit_with_url') else v['cloud_blob'].get_url(v['path'])
                             for p, v in self.config_param.items()}
            script_params['--command'] = cmd if isinstance(cmd, str) else ' '.join(cmd)
            # ...
        ```
        This code snippet shows that the user-supplied `cmd` is directly placed into the `script_params` dictionary under the key `--command`. This dictionary is then used to construct the arguments for the AML job submission. The raw command string is passed without any sanitization.

    2. **`act/aml_server.py` - `wrap_all` function:**
        ```python
        def wrap_all(code_zip, code_root,
                     folder_link, command,
                     compile_args,
                     ):
            # ...
            logging.info(command)
            if type(command) is str:
                command = list(command.split(' '))

            with MonitoringProcess():
                if len(command) > 0:
                    cmd_run(command, working_directory=code_root,
                                succeed=True)
        ```
        The `wrap_all` function in `aml_server.py` receives the `command` argument. Critically, it splits the command string by spaces into a list if it's a string using `command = list(command.split(' '))`. This splitting, even though `cmd_run` itself doesn't use `shell=True`, introduces a potential vulnerability if the command string contains shell metacharacters.

    3. **`act/aml_server.py` - `cmd_run` function:**
        ```python
        def cmd_run(cmd, working_directory='./', succeed=False,
                    return_output=False, stdout=None, stderr=None,
                    silent=False,
                    no_commute=False,
                    timeout=None,
                    ):
            # ...
            if not return_output:
                try:
                    p = sp.Popen(
                        cmd, stdin=sp.PIPE,
                        cwd=working_directory,
                        env=e,
                        stdout=stdout,
                        stderr=stderr,
                    )
                    if not no_commute:
                        p.communicate(timeout=timeout)
                        if succeed:
                            logging.info('return code = {}'.format(p.returncode))
                            assert p.returncode == 0
                    return p
                except:
                    # ...
        ```
        The `cmd_run` function uses `subprocess.Popen` to execute the command. It does not use `shell=True`, which is good, but it directly takes the `cmd` argument (which is now a list due to splitting in `wrap_all`) and passes it to `Popen`.  While directly passing a list to `Popen` generally avoids shell injection, the prior splitting by spaces in `wrap_all`, combined with potential command construction in `aml_client.py`, opens a window for injection if user-provided input is not carefully sanitized before being passed as the `cmd`.

- **Security Test Case:**
    1. **Prerequisites:**
        - Install ACT tool as described in `README.md`.
        - Configure ACT with valid Azure credentials and AML workspace details as per `README.md`.
        - Ensure you have the `act` alias set up as `alis a='python -m act.aml_client '`.
    2. **Steps:**
        - Open a terminal where ACT is configured.
        - Execute the following command to submit a job with a command injection payload:
          ```bash
          a submit bash -c "mkdir /tmp/pwned && touch /tmp/pwned/success"
          ```
        - Wait for the job to complete or fail. You can monitor the job status using `a query <run_id>` (replace `<run_id>` with the run ID returned after submitting the job).
        - After the job is in a "Completed" or "Failed" state, examine the job logs. Use `a query <run_id>` again. The logs will be downloaded to `./assets/<run_id>`.
        - Check the logs, particularly `70_driver_log_0.txt` or similar driver logs, for any output indicating successful execution of the injected commands `mkdir /tmp/pwned` and `touch /tmp/pwned/success`.
    3. **Expected Result:**
        - If the vulnerability is present, the injected commands `mkdir /tmp/pwned && touch /tmp/pwned/success` will be executed in the AML compute environment. Successful execution can be inferred from log messages or by observing the creation of `/tmp/pwned/success` if you have sufficient access to the AML compute environment to verify file system changes. In the logs, look for entries related to the execution of `bash -c "mkdir /tmp/pwned && touch /tmp/pwned/success"`.