### Vulnerability 1

Vulnerability Name: Insecure Storage of Dynatrace API Tokens

Description:
1. The Insightify Extension requires users to provide Dynatrace API tokens for both pulling metrics and publishing data during its configuration.
2. These tokens, intended to authorize access to sensitive Dynatrace APIs, are stored in plain text within the ActiveGate extension's configuration files.
3. An attacker who gains unauthorized access to the ActiveGate host's file system or the extension's configuration through other means can easily retrieve these plain text API tokens.

Impact:
- If an attacker obtains the "Tenant Token", they can gain unauthorized read access to the Dynatrace tenant's monitoring data via Dynatrace API v1 and v2 endpoints. This includes sensitive information about infrastructure, applications, problems, and license consumption.
- If an attacker obtains the "Publish Token", they can gain unauthorized write and read access to the configured Dynatrace tenant. "Publish Token" with `Write config` scope allows modification of Dynatrace configurations including dashboards. `Ingest Metrics` scope allows injection of arbitrary metrics data into Dynatrace. `Read Metrics` and `Read Config` scopes allow read access to metrics and configurations. `Ingest Logs` scope allows injection of arbitrary logs.
- Successful exploitation can lead to confidentiality breach of sensitive monitoring data, integrity issues by modifying configurations or injecting false metrics/logs, and potentially further abuse of the Dynatrace tenant depending on the scopes of the compromised tokens.

Vulnerability Rank: High

Currently implemented mitigations:
- None. The code directly retrieves and uses the tokens from the configuration without any visible encryption or secure handling mechanisms.

Missing mitigations:
- Secure storage of Dynatrace API tokens is missing. The extension should implement secure storage for these sensitive credentials.
- Recommended mitigations include:
    - **Encryption at rest:** Encrypt the configuration file where tokens are stored, or encrypt the token values before storing them in the configuration.
    - **Secrets Vault Integration:** Integrate with a secure secrets vault (like HashiCorp Vault, CyberArk, or cloud provider secret services) to store and retrieve API tokens instead of storing them in the extension's configuration.
    - **Principle of Least Privilege:** The extension documentation should strongly emphasize the principle of least privilege when creating API tokens, advising users to grant only the necessary scopes to the tokens used for the extension.

Preconditions:
- An attacker must gain unauthorized access to the ActiveGate host's file system where the extension is deployed. This could be achieved through various means, such as exploiting other vulnerabilities in the ActiveGate host, insider threat, or compromised credentials.
- Alternatively, if the extension configuration is accessible through any management interface without proper authorization, that could also be a precondition.

Source code analysis:
1. **File: `/code/src/EF1.0/src/insightify.py` and `/code/src/EF2.0/src/insightify/__main__.py`**
2. The `initialize` function in both versions of the extension retrieves the API tokens using `self.config.get()`:
   - In `/code/src/EF1.0/src/insightify.py`:
     ```python
     self.url = self.config.get("url", "https://demo.live.dynatrace.com/api/v1/")
     self.password = self.config.get("token", "admin")
     self.confurl = self.config.get("confurl","https://push.live.dynatrace.com/api/v2/")
     self.conf_password = self.config.get("conftoken", "Token")
     ```
   - In `/code/src/EF2.0/src/insightify/__main__.py`:
     ```python
     config_url=endpoint_detail["url"]
     password=endpoint_detail["token"]
     config_url = endpoint_config["confurl"]
     conf_password = endpoint_config["conftoken"]
     ```
3. These retrieved `self.password` and `self.conf_password` (or `password` and `conf_password` in EF2.0) variables are then directly used in subsequent API calls within the same files (e.g., in `dtApiQuery`, `dtApiV2GetQuery`, `dtApiV2PostQuery`, `dtApiIngestMetrics`, etc.) to authenticate requests to Dynatrace APIs by setting the `Authorization` header:
   ```python
   get_param = {'Accept':'application/json', 'Authorization':'Api-Token {}'.format(self.password)} # Example from dtApiQuery in EF1.0
   post_param = {'Content-Type':'text/plain;charset=utf-8', 'Authorization':'Api-Token {}'.format(conf_password)} # Example from dtApiIngestMetrics in __main__.py (EF2.0)
   ```
4.  There is no code present in the provided files that suggests any form of encryption, secure storage, or retrieval of these tokens from a secrets management system. The tokens obtained from `self.config.get()` are treated as plain text secrets throughout the extension's code.
5. This direct retrieval and usage of configuration values without secure handling confirms that the API tokens are likely stored in plain text in the extension's configuration.

Security test case:
1. Deploy the Insightify Extension (any version, EF1.0 or EF2.0) on a Dynatrace ActiveGate.
2. Configure a new endpoint for the extension through the Dynatrace UI.
3. In the endpoint configuration, provide a valid Dynatrace API token for "Tenant Token" and "Tenant Config Token" fields.
4. After successfully configuring the extension, access the ActiveGate host's operating system using SSH or a similar method.
5. Navigate to the ActiveGate plugin deployment directory. The exact path may vary based on the ActiveGate installation, but a common location is `/opt/dynatrace/remotepluginmodule/plugin_deployment/`.
6. Locate the configuration file for the Insightify extension. This file is typically within the extension's directory (e.g., `custom.remote.python.insightify/`) and might be named `config.json` or similar, depending on how ActiveGate stores extension configurations.  *(Note: The exact configuration file location and format are ActiveGate implementation details, but the principle of accessible file system configuration remains valid.)*
7. Open the extension's configuration file using a text editor.
8. Search for the configuration parameters related to the Dynatrace API tokens, which would correspond to the "Tenant Token" and "Tenant Config Token" configuration fields you set in the Dynatrace UI.
9. **Verification:** Observe that the Dynatrace API tokens are stored in the configuration file in plain text, directly as you entered them in the Dynatrace UI, without any encryption or obfuscation.
10. **Exploit (Optional):** Copy one of the retrieved plain text API tokens. Use a tool like `curl` or Postman to make a direct API call to the Dynatrace tenant using the copied token for authentication. For example:
    ```bash
    curl -H "Authorization: Api-Token <PASTE_RETRIEVED_TOKEN_HERE>" "https://<your-dynatrace-tenant-url>/api/v2/problems"
    ```
11. **Confirm:** If the API call is successful and returns Dynatrace problem data (or other data depending on the token's scope and the API endpoint), this confirms that the plain text token retrieved from the configuration file can be used to gain unauthorized access to the Dynatrace tenant.

This test case demonstrates that an attacker with file system access to the ActiveGate can retrieve and utilize the plain text Dynatrace API tokens, validating the Insecure Storage of Dynatrace API Tokens vulnerability.