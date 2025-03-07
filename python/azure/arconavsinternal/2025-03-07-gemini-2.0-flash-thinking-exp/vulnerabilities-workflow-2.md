## Combined Vulnerability List

This document outlines the identified vulnerabilities, their descriptions, impacts, mitigations, and steps to reproduce and verify them.

### 1. Command Injection in vCenter connection parameters

- **Vulnerability Name:** Command Injection in vCenter connection parameters
  - **Description:**
    1. The script reads vCenter connection details (FQDN, port, username) from a user-provided configuration file.
    2. In the `_connect_vcenter` function within `/code/src/appliance-onboarding-script/appliance_setup/pkgs/_arcvmware_resources.py`, these configuration values (`vCenterFQDN`, `vCenterPort`, `vCenterUserName`) are directly incorporated into an `az cli connectedvmware vcenter connect` command.
    3. The script then executes this command using `az_cli`, which uses `subprocess.check_output`.
    4. Due to the lack of input sanitization for `vCenterFQDN`, `vCenterPort`, and `vCenterUserName`, an attacker who can control the configuration file can inject arbitrary commands into these parameters.
    5. When the script executes the command, the injected commands will be executed by the system.

  - **Impact:**
    - An attacker can execute arbitrary commands on the system running the script with the privileges of the user executing the script.
    - This can lead to a range of malicious activities, including:
      - Full system compromise.
      - Unauthorized data access and exfiltration.
      - Modification or deletion of critical system files.

  - **Vulnerability Rank:** High

  - **Currently Implemented Mitigations:**
    - The script uses the `safe_escape_characters` function to escape the `vCenterPassword` parameter before including it in the `az cli` command.
    - However, this mitigation is not applied to `vCenterFQDN`, `vCenterPort`, and `vCenterUserName` parameters, leaving them vulnerable to command injection.

  - **Missing Mitigations:**
    - **Input Validation and Sanitization:** Implement robust input validation and sanitization for `vCenterFQDN`, `vCenterPort`, and `vCenterUserName` obtained from the configuration file. This should include checks for disallowed characters and patterns that could be used for command injection.
    - **Parameterized Commands:** Utilize parameterized commands or secure command construction methods provided by the `az cli` SDK (if available) to prevent command injection. This would involve separating the command structure from the user-supplied data.
    - **Principle of Least Privilege:** Ensure that the script and the user running it operate with the minimum necessary privileges to reduce the potential impact of a successful command injection attack.

  - **Preconditions:**
    - An attacker must be able to provide or modify the configuration file used by the script. This could be achieved through various means, such as:
      - Social engineering to trick a user into using a malicious configuration file.
      - Compromising a system or process that generates or stores the configuration file.
      - Man-in-the-middle attacks if the configuration file is transmitted over an insecure channel.

  - **Source Code Analysis:**
    - **File:** `/code/src/appliance-onboarding-script/appliance_setup/pkgs/_arcvmware_resources.py`
    - **Function:** `_connect_vcenter`
    - **Vulnerable Code Snippet:**
      ```python
      res, err = az_cli('connectedvmware', 'vcenter', 'connect',
          '--resource-group', f'"{rg}"',
          '--name', f'"{name}"',
          '--location', f'"{location}"',
          '--custom-location', f'"{custom_location_id}"',
          '--fqdn', f'"{fqdn}"',  # Vulnerable: User-controlled value, not sanitized
          '--port', f'"{port}"',  # Vulnerable: User-controlled value, not sanitized
          '--username', f'"{username}"', # Vulnerable: User-controlled value, not sanitized
          '--password="{}"'.format(safe_escape_characters(password)) # Partially mitigated: Password is escaped
      )
      ```
    - The `fqdn`, `port`, and `username` variables are directly sourced from the `config` dictionary, which is populated by parsing a user-provided JSON configuration file. These variables are then directly embedded into the shell command string passed to `az_cli` without any sanitization to prevent command injection.

  - **Security Test Case:**
    1. **Malicious Configuration File Creation:** Create a JSON configuration file named `malicious_config.json` with the following content. This payload attempts to execute the `touch /tmp/pwned` command.
       ```json
       {
         "vCenterFQDN": "$(touch /tmp/pwned)",
         "vCenterPort": "443",
         "vCenterUserName": "testuser",
         "vCenterPassword": "testpassword",
         "resourceGroup": "your-resource-group",
         "nameForVCenterInAzure": "malicious-vcenter",
         "location": "westus2",
         "subscriptionId": "your-subscription-id",
         "customLocationAzureName": "test-custom-location",
         "nameForApplianceInAzure": "test-appliance",
         "isAVS": true,
         "register": true,
         "isStatic": true,
         "staticIpNetworkDetails": {
           "networkForApplianceVM": "test-segment",
           "networkCIDRForApplianceVM": "192.168.10.0/28"
         },
         "privateCloud": "your-private-cloud"
       }
       ```
       **Note:** Replace `"your-resource-group"`, `"your-subscription-id"`, and `"your-private-cloud"` with valid Azure details if you intend to run this test in a real environment.
    2. **Script Execution with Malicious Configuration:** Execute the `run.sh` script, providing the `onboard` operation and the path to the `malicious_config.json` file as arguments:
       ```bash
       ./code/src/appliance-onboarding-script/run.sh onboard malicious_config.json
       ```
    3. **Verification of Command Injection:** After the script execution, check if the file `/tmp/pwned` has been created.
       ```bash
       ls /tmp/pwned
       ```
       - **Successful Injection:** If the `ls /tmp/pwned` command shows that the file `/tmp/pwned` exists, it confirms that the command injection was successful. The `$(touch /tmp/pwned)` part in the `vCenterFQDN` field was executed as part of the `az cli connectedvmware vcenter connect` command.

### 2. Command Injection in vCenter Operations via govc CLI

- **Vulnerability Name:** Command Injection in vCenter Operations via govc CLI
  - **Description:**
    1. The application takes user-provided configuration in JSON format, including parameters for vCenter operations like creating folders and resource pools.
    2. Specifically, the `folderForApplianceVM` and `resourcePoolForApplianceVM` parameters from the configuration are used as folder and resource pool names respectively.
    3. These names are directly passed as arguments to the `govc_cli` function in `/code/src/appliance-onboarding-script/appliance_setup/pkgs/_govc_cli.py`.
    4. The `govc_cli` function executes these arguments in a shell using `subprocess.check_output(cmd, shell=True)`.
    5. If an attacker can manipulate the configuration file to include malicious commands within the `folderForApplianceVM` or `resourcePoolForApplianceVM` parameters, they can inject arbitrary shell commands that will be executed on the system running the script with the privileges of the script user.

  - **Impact:**
    - **High**. Successful command injection can allow an attacker to execute arbitrary commands on the system hosting the appliance onboarding script.
    - This could lead to:
        - Unauthorized access to sensitive information.
        - Modification or deletion of critical system files.
        - Installation of malware or backdoors.
        - Complete compromise of the system.

  - **Vulnerability Rank:** High

  - **Currently Implemented Mitigations:**
    - None. The code directly passes the folder and resource pool names to the shell without any sanitization or validation.

  - **Missing Mitigations:**
    - **Input Sanitization:** Sanitize the `folderForApplianceVM` and `resourcePoolForApplianceVM` inputs to remove or escape shell-sensitive characters before passing them to `govc_cli`. A whitelist approach for allowed characters in folder and resource pool names would be more secure than a blacklist.
    - **Parameterization:** If possible, use a `govc` library or API that supports parameterized commands instead of constructing shell commands from strings. This would avoid shell injection vulnerabilities altogether.
    - **Input Validation:** Validate the format and content of the `folderForApplianceVM` and `resourcePoolForApplianceVM` parameters to ensure they conform to expected naming conventions and do not contain unexpected or malicious characters.

  - **Preconditions:**
    - The attacker must be able to modify the configuration file that is provided as input to the `run.py` script (specified by the second command line argument).

  - **Source Code Analysis:**
    - **File: `/code/src/appliance-onboarding-script/appliance_setup/pkgs/_govc_cli.py`**
      ```python
      def govc_cli(*args):
          create_dir_if_doesnot_exist(_govc_binary_dir)
          with TempChangeDir(_govc_binary_dir):
              args = ' '.join(args) # [!] Arguments are joined with space and used in shell=True
              res = None
              try:
                  cmd = os.path.join('.', 'govc')
                  cmd = cmd + ' ' + args # [!] User controlled 'args' is concatenated to form command
                  try:
                      res = subprocess.check_output(cmd, shell=True) # [!] shell=True is used, making it vulnerable
      ```
    - **File: `/code/src/appliance-onboarding-script/appliance_setup/pkgs/_vmware_env_setup.py`**
      ```python
      class VMwareEnvSetup(object):
          ...
          def _create_folder(self):
              logging.info("in _create_folder")
              folder = self._config['folderForApplianceVM'] # [!] User controlled folder name from config
              datacenter = self._config['datacenterForApplianceVM']
              if self._folder_exists(folder):
                  logging.info("folder already exists")
                  return
              _, err = govc_cli('folder.create', folder) # [!] Folder name passed to govc_cli
              if err:
                  raise vCenterOperationFailed('Folder creation failed.')

          def _create_resource_pool(self):
              logging.info("in _create_resource_pool")
              resource_pool = self._config['resourcePoolForApplianceVM'] # [!] User controlled resource pool name from config
              datacenter = self._config['datacenterForApplianceVM']
              if self._resource_pool_exists(resource_pool):
                  logging.info("resource pool already exists")
                  return
              _, err = govc_cli('pool.create', resource_pool) # [!] Resource pool name passed to govc_cli
              if err:
                  raise vCenterOperationFailed('Resource Pool creation failed.')
      ```

  - **Security Test Case:**
    1. Create a malicious JSON configuration file (e.g., `malicious_config.json`) with the following content to test folder creation command injection:
        ```json
        {
          "isAVS": true,
          "register": true,
          "isStatic": true,
          "location": "westus2",
          "subscriptionId": "YOUR_SUBSCRIPTION_ID",
          "resourceGroup": "YOUR_RESOURCE_GROUP",
          "privateCloud": "YOUR_PRIVATE_CLOUD_NAME",
          "vCenterFQDN": "YOUR_VCENTER_FQDN",
          "vCenterPort": "443",
          "vCenterUserName": "YOUR_VCENTER_USERNAME",
          "vCenterPassword": "YOUR_VCENTER_PASSWORD",
          "datacenterForApplianceVM": "YOUR_DATACENTER",
          "datastoreForApplianceVM": "YOUR_DATASTORE",
          "resourcePoolForApplianceVM": "YOUR_RESOURCE_POOL",
          "networkForApplianceVM": "YOUR_NETWORK_SEGMENT",
          "folderForApplianceVM": "test_folder`touch /tmp/pwned`",  // [!] Malicious folder name with command injection
          "vmTemplateName": "YOUR_TEMPLATE_NAME",
          "staticIpNetworkDetails": {
            "networkForApplianceVM": "YOUR_NETWORK_SEGMENT",
            "networkCIDRForApplianceVM": "YOUR_CIDR",
            "gatewayIPAddress": "YOUR_GATEWAY_IP"
          },
          "nameForApplianceInAzure": "test-appliance",
          "customLocationAzureName": "test-custom-location",
          "nameForVCenterInAzure": "test-vcenter"
        }
        ```
        **Note:** Replace placeholders with valid values for your vCenter and Azure environment.

    2. Execute the `run.sh` script with the malicious configuration file:
        ```bash
        ./code/src/appliance-onboarding-script/run.sh onboard malicious_config.json INFO false
        ```

    3. After the script execution, check if the file `/tmp/pwned` exists on the system where the script was executed.
        ```bash
        ls -l /tmp/pwned
        ```
        - If the file `/tmp/pwned` exists, it confirms successful command injection.

### 3. Malicious govc Binary Download via PR Modification

- **Vulnerability Name:** Malicious govc Binary Download via PR Modification
  - **Description:**
    1. A malicious actor submits a pull request to modify the `/code/src/appliance-onboarding-script/run.sh` script.
    2. In the pull request, the attacker changes the `URL_TO_BINARY` variable to a URL pointing to a malicious `govc_linux_amd64.gz` binary hosted on an attacker-controlled server.
    3. If the pull request is merged or if a user executes the modified script from the attacker's branch, the script will download the malicious `govc` binary instead of the legitimate one.
    4. The script proceeds to extract the downloaded archive and make the binary executable using `chmod +x`.
    5. Subsequently, when other parts of the scripts or related components attempt to use `govc`, they will be executing the malicious binary.

  - **Impact:**
    - Execution of arbitrary code on the system where the script is run.
    - Potential compromise of the vCenter environment if the malicious `govc` binary is designed to interact with vCenter in a harmful way.
    - Potential compromise of Azure resources if the malicious binary gains access to Azure credentials or is designed to interact with Azure services maliciously.

  - **Vulnerability Rank:** High

  - **Currently Implemented Mitigations:**
    - None. The script downloads and executes the binary directly without any integrity checks.

  - **Missing Mitigations:**
    - **Integrity Checks:** Implement integrity checks for downloaded binaries, such as checksum verification or signature verification.
    - **Secure Binary Hosting:** Host the `govc` binary in a controlled and trusted location instead of relying on external public repositories.
    - **Dependency Pinning/Vendoring:** Consider including the `govc` binary directly in the repository or using a secure distribution mechanism to avoid runtime downloads.

  - **Preconditions:**
    - The attacker must be able to submit a pull request and convince a maintainer to merge it, or be able to execute the script from their own modified branch.
    - The script must be executed in an environment that has internet access to download the binary.

  - **Source Code Analysis:**
    - **File:** `/code/src/appliance-onboarding-script/run.sh`
    - **Line 86:** `URL_TO_BINARY="https://github.com/vmware/govmomi/releases/download/v0.24.0/govc_linux_amd64.gz"` - Defines the download URL for the `govc` binary, which can be modified.
    - **Line 88:** `curl -L $URL_TO_BINARY | gunzip > ./.temp/govc` - Downloads and extracts the binary from the URL.
    - **Line 89:** `sudo -E chmod +x ./.temp/govc` - Sets execute permissions on the downloaded binary.

  - **Security Test Case:**
    1. **Setup Attacker Environment:** Prepare a malicious `govc_linux_amd64.gz` binary and host it on an attacker-controlled web server (e.g., `https://attacker.example.com/malicious-govc_linux_amd64.gz`).
    2. **Fork Repository and Modify `run.sh`:** Fork the target GitHub repository and modify the `run.sh` script in your fork to change `URL_TO_BINARY` to point to your malicious binary URL.
    3. **Execute Modified Script:** In a test environment, clone your forked repository and execute the modified `run.sh` script.
    4. **Observe Execution:** Observe the output of the script and verify if the malicious code from your binary is executed.