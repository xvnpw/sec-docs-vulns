- Vulnerability Name: Command Injection via Proxy Configuration in `run.sh`
- Description:
    1. An attacker crafts a malicious `config_avs.json` file.
    2. This file contains specially crafted values within the `managementProxyDetails` section, specifically in `http`, `https`, or `noProxy` fields.
    3. When `run.sh` script processes this malicious `config_avs.json` file, it uses `grep -Po` to extract proxy settings.
    4. Due to insufficient input validation and the use of shell commands to process the configuration, an attacker can inject arbitrary commands. For example, by injecting backticks or command substitution within the proxy values.
    5. These injected commands are then executed by the shell when the script attempts to set proxy environment variables using `export`.

- Impact:
    - **High**: Successful command injection allows the attacker to execute arbitrary commands on the system running the script, with the privileges of the script user (potentially root if run with `sudo`). This could lead to system compromise, data exfiltration, or denial of service. In the context of Azure VMware Solution integration, this could be used to compromise the management plane or connected Azure services if credentials are exposed or manipulated.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None. The script directly uses `grep -Po` and `export` without any sanitization of the values extracted from the configuration file.

- Missing Mitigations:
    - Input validation: The script should validate and sanitize the proxy values extracted from `config_avs.json` to ensure they do not contain command injection characters or sequences.
    - Secure parsing: Instead of using `grep` and shell commands to parse JSON, use a dedicated JSON parsing tool within bash (like `jq`) or, ideally, move the proxy configuration logic into the Python script to leverage Python's safer JSON handling and string manipulation capabilities.
    - Principle of least privilege: While not directly mitigating the injection, running the script with the least necessary privileges would reduce the impact of a successful exploit. However, the script likely requires elevated privileges for some operations.

- Preconditions:
    - The user must download and execute the `run.sh` script.
    - The user must be tricked into using a malicious `config_avs.json` file provided by the attacker.
    - The script must be executed in an environment where the user has permissions that the attacker wants to leverage.

- Source Code Analysis:
    - File: `/code/src/run.sh`
    - Vulnerable code section:
      ```bash
      if [ -n "$2" ] && [ -f "$2" ]
      then
        http_p=$(grep -A 20 "managementProxyDetails" "$2" | grep -Po '(?<="http": ")[^"]*')
        https_p=$(grep -A 20 "managementProxyDetails" "$2" | grep -Po '(?<="https": ")[^"]*')
        noproxy=$(grep -A 20 "managementProxyDetails" "$2" | grep -Po '(?<="noProxy": ")[^"]*')
        proxyCAInput=$(grep -A 20 "managementProxyDetails" "$2" | grep -Po '(?<="certificateFilePath": ")[^"]*')
        # ... (certificate file path processing) ...
        export http_proxy=$http_p
        export HTTP_PROXY=$http_p
        export https_proxy=$https_p
        export HTTPS_PROXY=$https_p
        export no_proxy=$noproxy
        export NO_PROXY=$noproxy
      fi
      ```
    - The script takes the second argument `$2` as the path to the configuration file.
    - It then uses `grep -A 20 "managementProxyDetails" "$2"` to extract the section related to proxy settings from the file specified by `$2`.
    - Subsequently, it uses `grep -Po '(?<="http": ")[^"]*'`, `grep -Po '(?<="https": ")[^"]*'`, and `grep -Po '(?<="noProxy": ")[^"]*'` to extract the values for `http`, `https`, and `noProxy` respectively. The `-P` option for `grep` enables Perl Compatible Regular Expressions, and `-o` option prints only the matched part.
    - The extracted values are assigned to variables `http_p`, `https_p`, and `noproxy`.
    - Finally, these variables are directly used in `export` commands to set environment variables like `http_proxy`, `https_proxy`, and `no_proxy`.
    - **Vulnerability**: An attacker can inject shell commands within the `config_avs.json` file in the `managementProxyDetails` section. For example, setting `http` to ``"`http://vulnerable.com`; malicious_command`"``. When `grep -Po '(?<="http": ")[^"]*'` extracts this value, it will include the injected command. When `export http_proxy=$http_p` is executed, the shell will interpret the backticks and execute `malicious_command`.

    ```mermaid
    graph LR
        A[run.sh starts] --> B{Check if config file path provided};
        B -- Yes --> C{grep proxy details from config file};
        C --> D{Extract http_proxy, https_proxy, no_proxy using grep -Po};
        D --> E{export http_proxy=$http_p};
        E --> F{export https_proxy=$https_p};
        F --> G{export no_proxy=$noproxy};
        G --> H[Continue script execution];
        B -- No --> H;
    ```

- Security Test Case:
    1. Create a malicious `config_avs.json` file with the following content:
       ```json
       {
         "managementProxyDetails": {
           "http": "`touch /tmp/pwned`",
           "https": "https://normal-proxy.com",
           "noProxy": "localhost,127.0.0.1"
         },
         "subscriptionId": "YOUR_SUBSCRIPTION_ID",
         "resourceGroup": "YOUR_RESOURCE_GROUP",
         "privateCloud": "YOUR_PRIVATE_CLOUD",
         "location": "westus2",
         "vCenterFQDN": "...",
         "vCenterUserName": "...",
         "vCenterPassword": "...",
         "staticIpNetworkDetails": {
           "networkForApplianceVM": "arc-segment-444",
           "networkCIDRForApplianceVM": "192.168.10.0/28"
         }
       }
       ```
    2. Save this file as `malicious_config_avs.json`.
    3. Execute the `run.sh` script with the malicious configuration file:
       ```bash
       sudo chmod +x run.sh
       sudo bash run.sh onboard malicious_config_avs.json
       ```
    4. After the script execution, check if the file `/tmp/pwned` exists.
    5. If the file `/tmp/pwned` exists, it confirms that the command injection was successful, as the `touch /tmp/pwned` command injected through the `http` proxy setting was executed.