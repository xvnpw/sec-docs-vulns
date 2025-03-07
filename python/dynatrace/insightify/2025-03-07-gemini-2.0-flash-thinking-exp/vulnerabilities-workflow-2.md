### Vulnerability List

- Vulnerability Name: Insecure Storage of Dynatrace API Tokens in Extension Configuration

- Description:
    1. The Insightify Extension requires users to provide sensitive Dynatrace API tokens (Tenant Token and Publish Token) during its configuration within the Dynatrace UI. These tokens authorize the extension to access Dynatrace APIs for pulling metrics and publishing data.
    2. Upon configuration, these API tokens are stored as part of the extension's configuration. Insecurely, these tokens are stored in plain text within the ActiveGate extension's configuration files. These files are typically located within the ActiveGate's plugin deployment directory on the file system.
    3. An attacker gains unauthorized access to the ActiveGate host's file system. This could be achieved through various means, such as exploiting vulnerabilities in the ActiveGate itself, gaining unauthorized access to the server through compromised credentials, or through insider threats.
    4. The attacker navigates to the extension's configuration directory within the ActiveGate's plugin deployment folder (e.g., `/opt/dynatrace/remotepluginmodule/plugin_deployment/custom.remote.python.dt_health_report/` or `/opt/dynatrace/remotepluginmodule/plugin_deployment/custom.remote.python.insightify/`).
    5. The attacker locates and opens the extension's configuration file. This file could be named `config.json`, `activation.json`, `plugin.json` or similar, depending on the extension framework and ActiveGate implementation.
    6. The attacker examines the configuration file and easily extracts the Dynatrace API tokens (both "Tenant Token" and "Publish Token") which are stored in plain text.
    7. With these extracted plain text API tokens, the attacker can now directly authenticate to the Dynatrace tenant, bypassing extension-level access controls. The attacker can then leverage these tokens to access sensitive Dynatrace APIs.

- Impact:
    - **Unauthorized Access to Dynatrace Tenant:** With the extracted API tokens, the attacker gains unauthorized access to the configured Dynatrace tenant, effectively bypassing intended access controls.
    - **Confidentiality Breach of Sensitive Monitoring Data:** The attacker can access sensitive monitoring data within the Dynatrace tenant, including performance metrics, problem details, configuration data, and potentially business-sensitive information depending on the monitored environment. This allows data exfiltration and insights into the monitored environment's performance, security posture, and business operations.
    - **Integrity Breach and Data Manipulation:** Depending on the scopes of the compromised tokens, especially the "Publish Token" (which is often configured with "Write config" and "Ingest Metrics" scopes), the attacker can manipulate data within the Dynatrace tenant. This includes modifying Dynatrace configurations, creating or modifying dashboards, injecting malicious metrics or logs, or even potentially disrupting monitoring operations.
    - **Account Takeover (Potentially):** In severe cases, depending on the token scopes, attackers could potentially gain control over aspects of the Dynatrace tenant, leading to further abuse.
    - **Lateral Movement (Potentially):** If the compromised Dynatrace tenant is integrated with other systems or services, the attacker might use this initial access to facilitate lateral movement within the organization's infrastructure.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - None. The code directly retrieves and uses the tokens from the configuration without any explicit encryption or secure storage mechanisms. The project relies on the user to securely manage the API tokens during configuration, but does not provide secure storage within the extension itself.

- Missing Mitigations:
    - **Secure Storage of API Tokens:** API tokens should be stored securely, ideally using encryption at rest. The ActiveGate platform may provide mechanisms for secure credential storage that the extension should leverage. If not, a robust encryption method should be implemented, ensuring that encryption keys are also managed securely and not stored alongside the encrypted tokens. Recommended approaches include:
        - **Encryption at rest:** Encrypt the configuration file where tokens are stored, or encrypt the token values before storing them in the configuration.
        - **Secrets Vault Integration:** Integrate with a secure secrets vault (like HashiCorp Vault, CyberArk, or cloud provider secret services) to store and retrieve API tokens instead of storing them in the extension's configuration.
    - **Principle of Least Privilege for API Tokens:** The API tokens should be created with the minimum necessary scopes and permissions required for the extension to function. This limits the potential impact if the tokens are compromised. The documentation should strongly emphasize the principle of least privilege when creating API tokens, advising users to grant only the necessary scopes to the tokens used for the extension.
    - **Regular Token Rotation:** Implement a mechanism for regular rotation of API tokens. This reduces the window of opportunity for an attacker if a token is compromised.
    - **Access Control to ActiveGate File System:** Harden the ActiveGate server and implement strict access control policies to limit who can access the file system and configuration files. This is a general security best practice for ActiveGate deployments.
    - **Input Masking/Obfuscation:** While not full mitigation, masking the token input fields in the Dynatrace UI can reduce accidental exposure during configuration.
    - **Warning Documentation:** Documentation should strongly emphasize the critical importance of securely managing Dynatrace API tokens. It should advise users against using highly privileged tokens if not necessary and highlight the risks of exposing these tokens.
    - **Secure Configuration Practices Guidance:** Documentation should recommend best practices for securing Dynatrace tenant configurations and ActiveGate access to minimize the risk of unauthorized access to extension configurations.

- Preconditions:
    1. An instance of the Insightify extension is deployed on a Dynatrace ActiveGate.
    2. The extension is configured with valid Dynatrace API tokens for accessing a Dynatrace tenant.
    3. The attacker gains unauthorized access to the ActiveGate's file system. Alternatively, if the extension configuration is accessible through any management interface without proper authorization, that could also be a precondition.
    4. A user with sufficient privileges to manage Dynatrace extensions exists and has configured the Insightify extension.

- Source Code Analysis:
    1. **File:** `/code/src/EF1.0/src/insightify.py` and `/code/src/EF2.0/src/insightify/__main__.py`
    2. **Token Retrieval:** The `initialize` function in both `EF1.0` and `EF2.0` versions, and the `query` function in `EF2.0` retrieve API tokens from the configuration using `self.config.get()` or directly accessing configuration dictionaries like `endpoint["token"]` and `endpoint_config["conftoken"]`.
        - **Code Snippet (EF1.0 - `insightify.py` - `RemoteInsightifyExtension.initialize()`):**
          ```python
          self.url = self.config.get("url", "https://demo.live.dynatrace.com/api/v1/")
          self.password = self.config.get("token", "admin")
          self.confurl = self.config.get("confurl","https://push.live.dynatrace.com/api/v2/")
          self.conf_password = self.config.get("conftoken", "Token")
          ```
        - **Code Snippet (EF2.0 - `__main__.py` - `ExtensionImpl.query()` and API functions):**
          ```python
          for endpoint in self.activation_config["endpoints"]:
             url = endpoint["url"]
             # ...
             endpoint_config = endpoint.get("config", {})
             config_url = endpoint_config["confurl"]
             conf_password = endpoint_config["conftoken"]
             password=endpoint_detail["token"]
          ```
    3. **Plain Text Usage in API Requests:** The retrieved tokens (`self.password`, `self.conf_password`, `password`, `conf_password`) are directly used in the `Authorization` header of HTTP requests to Dynatrace APIs without any intermediate secure handling within functions like `dtApiQuery`, `dtApiV2GetQuery`, `dtApiIngestMetrics`, etc.
        - **Code Snippet (Example from `dtApiQuery` in `EF1.0`):**
          ```python
          get_param = {'Accept':'application/json', 'Authorization':'Api-Token {}'.format(self.password)}
          ```
        - **Code Snippet (Example from `dtApiIngestMetrics` in `__main__.py` - EF2.0):**
          ```python
          post_param = {'Content-Type':'text/plain;charset=utf-8', 'Authorization':'Api-Token {}'.format(conf_password)}
          ```
    4. **No Secure Storage:** There is no code present in the provided files that suggests any form of encryption, secure storage, or retrieval of these tokens from a secrets management system. The tokens obtained from configuration are treated as plain text secrets throughout the extension's code.
    5. **Visualization:**
    ```
    Configuration File (e.g., config.json on ActiveGate)
    ----------------------------------
    {
      "tenant_url": "https://<tenant-id>.live.dynatrace.com/api/v1/",
      "tenant_token": "YOUR_TENANT_API_TOKEN",  <-- Plain text token
      "publish_url": "https://<tenant-id>.live.dynatrace.com/api/v2/",
      "publish_token": "YOUR_PUBLISH_API_TOKEN" <-- Plain text token
    }
    ----------------------------------
        ^
        | Attacker Accesses File System
        |
    ActiveGate File System
    ----------------------------------
    /opt/dynatrace/remotepluginmodule/plugin_deployment/custom.remote.python.dt_health_report/config.json (Example Path)
    ----------------------------------
        |
        | Reads config.json
        V
    Attacker Extracts Tokens: "YOUR_TENANT_API_TOKEN", "YOUR_PUBLISH_API_TOKEN"
        |
        | Uses tokens in API calls
        V
    Dynatrace Tenant API (https://<tenant-id>.live.dynatrace.com/api/*)
    ----------------------------------
    ```
    6. This direct retrieval and usage of configuration values without secure handling confirms that the API tokens are likely stored in plain text in the extension's configuration, making them easily accessible if the configuration file is compromised.

- Security Test Case:
    1. **Precondition:** Deploy the Insightify extension (EF1.0 or EF2.0) on a test ActiveGate and configure it with Dynatrace API tokens for a non-production Dynatrace tenant. Ensure "Tenant Token" has `Read problems (API v2)` scope and "Publish Token" has `Write config (Configuration API v1)`, `Read config (Configuration API v1)`, `Ingest Metrics (API v2)`, `Read Metrics (API v2)`, and `Ingest Logs (API v2) (Optional)` scopes for comprehensive testing.
    2. **Access ActiveGate File System:** As an attacker, gain shell access to the ActiveGate server. This step simulates gaining unauthorized access; in a real scenario, this could be via various exploits or misconfigurations.
    3. **Locate Extension Configuration:** Navigate to the plugin deployment directory on the ActiveGate file system (e.g., `/opt/dynatrace/remotepluginmodule/plugin_deployment/` or `/var/lib/dynatrace/remotepluginmodule/plugin_deployment/`). Identify the extension's folder (e.g., `custom.remote.python.dt_health_report` or `custom.remote.python.insightify`).
    4. **Examine Configuration Files:** Look for configuration files within the extension's directory. Assume a file like `config.json`, `activation.json`, `plugin.json` or similar exists.
    5. **Verify Plain Text Tokens:** Open the configuration file in a text editor (e.g., using `cat <config_file>`). Search for configuration parameters related to Dynatrace API tokens, such as "token", "conftoken", "password", "conf_password". Verify that the values associated with these parameters are the actual Dynatrace API tokens in plain text.
    6. **Exploit API Tokens:**
        - **Using Tenant Token:** Use `curl` or a similar tool to make an API request to the configured Dynatrace tenant using the extracted "Tenant Token". For example:
          ```bash
          curl -H "Authorization: Api-Token YOUR_TENANT_API_TOKEN" "https://<tenant-id>.live.dynatrace.com/api/v2/problems?from=now-1h"
          ```
          Verify that the API request is successful and returns problem data, confirming unauthorized access using the compromised token.
        - **Using Publish Token:** Similarly, test the "Publish Token" by attempting to ingest a metric:
          ```bash
          curl -X POST -H "Authorization: Api-Token YOUR_PUBLISH_API_TOKEN" -H "Content-Type: text/plain" --data-binary 'custom.metric,dt.entity.custom_device=insightify-test 1' "https://<tenant-id>.live.dynatrace.com/api/v2/metrics/ingest"
          ```
          Verify that the metric is successfully ingested into the Dynatrace tenant, demonstrating the capabilities granted by the "Publish Token".
    7. **Expected Result:** The test should successfully demonstrate that an attacker, with access to the ActiveGate file system, can extract Dynatrace API tokens from the extension's configuration and use these tokens to gain unauthorized access and potentially manipulate data in the Dynatrace tenant.