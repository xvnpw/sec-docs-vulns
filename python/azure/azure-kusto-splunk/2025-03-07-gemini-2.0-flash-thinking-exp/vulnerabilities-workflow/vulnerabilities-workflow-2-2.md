### Vulnerability List for Splunk Add-on for Azure Data Explorer

* Vulnerability Name: Insecure Storage of Azure Data Explorer Application Client Secret in Splunk Configuration Files
* Description:
    1. The Splunk Add-on for Azure Data Explorer requires users to configure connection details, including the Azure Application Client Secret, through the Splunk UI when setting up an alert action.
    2. This client secret is stored in plain text or a reversible format within Splunk's configuration files (e.g., `alert_actions.conf`, potentially within the app's directory in Splunk's file system).
    3. An attacker who gains unauthorized access to the Splunk server's file system or Splunk's configuration management interface can retrieve this client secret.
    4. Access to Splunk configuration files can be achieved through various means, including:
        - Exploiting vulnerabilities in the Splunk platform.
        - Compromising Splunk administrator accounts with insufficient security practices (weak passwords, lack of multi-factor authentication).
        - Gaining unauthorized access to the underlying server infrastructure where Splunk is installed.
        - Insider threats.
    5. Once the attacker retrieves the Azure Application Client Secret, they can use it to authenticate against the configured Azure Data Explorer cluster.
* Impact:
    - **Unauthorized Access to Azure Data Explorer Cluster:** An attacker can gain full access to the Azure Data Explorer cluster, potentially leading to:
        - **Data Breach:** Accessing and exfiltrating sensitive data stored in Azure Data Explorer.
        - **Data Manipulation:** Modifying or deleting data within the Azure Data Explorer cluster, compromising data integrity.
        - **Resource Abuse:** Using the compromised credentials to ingest malicious data, perform expensive queries, or otherwise abuse Azure Data Explorer resources, potentially leading to increased costs or denial of service.
* Vulnerability Rank: High
* Currently Implemented Mitigations:
    - None. The provided project files and documentation do not include any explicit mitigations for secure storage of the client secret. The README files guide users to directly input the client secret into the Splunk Add-on configuration.
* Missing Mitigations:
    - **Secure Credential Storage:** Implement secure storage mechanisms for the client secret within the Splunk Add-on. Splunk provides a Credential Store that can be used to securely store and manage sensitive credentials. The add-on should be modified to utilize the Splunk Credential Store instead of storing the secret in plain text in configuration files.
    - **Secret Masking in UI and Logs:** Splunk should provide UI features to mask the display of the client secret after it is entered. Additionally, ensure that the client secret is never logged in plain text in Splunk logs.
    - **Principle of Least Privilege Documentation:** Documentation should strongly emphasize the principle of least privilege for Splunk users and administrators who manage the add-on. Access to Splunk configuration files and the Splunk server itself should be restricted to only authorized personnel.
    - **Security Hardening Guidance:** Provide comprehensive security hardening guidance for Splunk instances used with this add-on, including recommendations for access control, file system permissions, regular security audits, and use of multi-factor authentication for Splunk administrators.
* Preconditions:
    - The Splunk Add-on for Azure Data Explorer is installed and configured with Azure Data Explorer connection details, including the Application Client Secret.
    - An attacker gains unauthorized access to the Splunk server's file system or Splunk's configuration management interface.
* Source Code Analysis:
    - **File: `/code/splunk-adx-alert-addon/README.md` and `/code/README.md`**: These README files, which serve as user documentation, explicitly instruct users to configure the "Azure Application Client secret" in Step 3: Configure Splunk Addon for Azure Data Explorer. Screenshots in `/code/splunk-adx-alert-addon/README.md` visually confirm that the client secret is entered as a plain text value in a configuration field within the Splunk UI when setting up the alert action.
    - **File: `/code/splunk-adx-alert-addon/send_to_adx.py` and `/code/splunk-adx-alert-addon/modalert_send_to_adx_helper.py`**: These Python files are part of the Splunk Add-on's alert action. They retrieve the `app_secret` parameter using `helper.get_param('app_secret')`. This confirms that the client secret, configured through the Splunk UI, is accessed by the add-on's code.
    - ```python
      # File: /code/splunk-adx-alert-addon/modalert_send_to_adx_helper.py
      def process_event(helper, *args, **kwargs):
          # ...
          app_secret = helper.get_param('app_secret')
          # ...
      ```
    - The `helper.get_param('app_secret')` function, part of the Splunk Modular Alert framework, retrieves the parameter value directly from the Splunk configuration. There is no code in these files or elsewhere in the provided project that suggests any secure handling or storage of this secret. It is treated as a regular configuration parameter and passed directly to the `ADXSplunkConnector` class.
    - **File: `/code/splunk-adx-alert-addon/adx_connector.py`**: This file initializes the `ADXSplunkConnector` class, taking `app_secret` as a constructor parameter and using it to build the Kusto connection string.
    - ```python
      # File: /code/splunk-adx-alert-addon/adx_connector.py
      class ADXSplunkConnector:
          def __init__(self, ingest_URL, app_id, app_secret, tenant_id, database_name, table_name, table_mapping_name, durable_mode, session_identifier):
              # ...
              self.app_secret = app_secret
              # ...
              kcsb = KustoConnectionStringBuilder.with_aad_application_key_authentication(self.ingest_URL, self.app_id, self.app_secret, self.tenant_id)
              # ...
      ```
    - The code directly uses the `app_secret` to authenticate with Azure Data Explorer, without any intermediate secure storage or handling within the add-on itself. The vulnerability stems from Splunk's configuration storage mechanism and the add-on's reliance on it for sensitive credentials.

* Security Test Case:
    1. **Prerequisites:**
        - Install a Splunk instance (e.g., Splunk Enterprise Trial).
        - Install the Splunk Add-on for Azure Data Explorer on the Splunk instance.
        - Configure an alert in Splunk that uses the "Send to Azure Data Explorer" alert action.
        - During the alert action configuration, provide valid Azure Data Explorer connection details, including a **test** Azure Application Client Secret (ensure this secret is for a test ADX cluster and limited permissions to minimize risk during testing).
    2. **Access Splunk Configuration Files:**
        - Locate the Splunk app directory for the Azure Data Explorer Add-on. The typical location is within `$SPLUNK_HOME/etc/apps/TA-splunkadx-alert/`.
        - Navigate to the `default` or `local` directory within the app directory (configuration precedence rules in Splunk apply).
        - Identify the configuration file related to alert actions. This is often `alert_actions.conf` or a similar file within the app's configuration.
    3. **Examine Configuration File Content:**
        - Open the relevant configuration file (e.g., `alert_actions.conf`) and examine its contents.
        - Search for the configuration stanza related to the "send_to_adx" alert action.
        - Look for the `app_secret` parameter within this stanza.
    4. **Verify Plain Text Secret Storage:**
        - Observe that the `app_secret` value is stored in plain text or a trivially encoded format within the configuration file. It should be directly readable or easily decoded without specialized tools.
    5. **Attempt Authentication with Retrieved Secret:**
        - Copy the retrieved `app_secret` value.
        - Using a separate tool or script (e.g., Kusto Python SDK, Azure CLI with Kusto extension), attempt to authenticate against the Azure Data Explorer cluster using the retrieved `app_secret`, along with the corresponding `app_id` and `tenant_id` (which are also configured in Splunk and likely retrievable).
        - If authentication is successful and you can access the Azure Data Explorer cluster using the retrieved secret, the vulnerability is confirmed.
    6. **Cleanup (Important):**
        - After testing, immediately rotate or revoke the test Azure Application Client Secret to prevent any potential misuse.
        - Securely delete any configuration files or logs that may contain the client secret from your testing environment.

This security test case demonstrates how an attacker with access to Splunk configuration files can retrieve the Azure Application Client Secret and potentially gain unauthorized access to the Azure Data Explorer cluster.