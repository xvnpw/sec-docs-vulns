- Vulnerability Name: Credentials Exposure in Splunk Addon Configuration
- Description:
  1. An administrator configures the Splunk Addon for Azure Data Explorer within their Splunk instance.
  2. During configuration, the administrator is required to provide the Azure Data Explorer application client ID and application client secret.
  3. These credentials, specifically the application client secret, are stored within the Splunk addon's configuration in plain text or an easily reversible format.
  4. An attacker gains unauthorized access to the Splunk instance, potentially through vulnerabilities in Splunk itself or weak Splunk credentials.
  5. The attacker navigates to the Splunk addon's configuration settings within Splunk.
  6. The attacker retrieves the Azure Data Explorer application client ID and secret from the addon's configuration.
  7. The attacker can now use these credentials to authenticate against the Azure Data Explorer cluster and gain unauthorized access to data and resources within the cluster.
- Impact:
  - Unauthorized access to the Azure Data Explorer cluster.
  - Potential data breach or data manipulation within Azure Data Explorer.
  - Compromise of the Azure resources accessible with the compromised credentials.
- Vulnerability Rank: High
- Currently Implemented Mitigations: None. The code directly uses and likely stores the secret provided in the Splunk configuration without any explicit encryption or secure handling.
- Missing Mitigations:
  - Secure Credential Storage: Implement secure storage of the Azure application client secret using Splunk's built-in credential management system. This involves utilizing Splunk's storage/passwords API or equivalent mechanisms to encrypt and protect sensitive credentials within Splunk's configuration.
- Preconditions:
  - Attacker gains unauthorized access to the Splunk instance where the addon is installed and configured.
  - The Splunk Addon for Azure Data Explorer is installed and configured with Azure Data Explorer credentials.
- Source Code Analysis:
  1. File: `/code/splunk-adx-alert-addon/send_to_adx.py` - This file serves as the entry point for the Splunk alert action.
  2. The `AlertActionWorkersend_to_adx` class inherits from `ModularAlertBase` and handles the alert action logic.
  3. The `validate_params` method ensures that mandatory parameters like `cluster_url`, `app_id`, `app_secret`, `tenant_id`, `database_name`, and `table_name` are provided during the addon configuration.
  4. The `process_event` method in `send_to_adx.py` calls `modalert_send_to_adx_helper.process_event(self, *args, **kwargs)` to handle the core logic of sending data to Azure Data Explorer.
  5. File: `/code/splunk-adx-alert-addon/modalert_send_to_adx_helper.py` - This helper script retrieves the configuration parameters using `helper.get_param()`. Notably, it retrieves the `app_secret` using:
     ```python
     app_secret = helper.get_param('app_secret')
     ```
  6. The `create_ADX_client` function is then called, passing the retrieved `app_secret` as a parameter:
     ```python
     adx_client = create_ADX_client(cluster_endpoint, app_id, app_secret, tenant_id, database, table, mapping_name, durable_mode, session_identifier)
     ```
  7. File: `/code/splunk-adx-alert-addon/adx_connector.py` - The `ADXSplunkConnector` class is responsible for establishing the connection to Azure Data Explorer.
  8. In the `__init__` method of `ADXSplunkConnector`, the `app_secret` is received as a parameter and stored as an instance variable:
     ```python
     def __init__(self, ingest_URL, app_id, app_secret, tenant_id, database_name, table_name, table_mapping_name, durable_mode, session_identifier):
         self.app_secret = app_secret
         # ...
         kcsb = KustoConnectionStringBuilder.with_aad_application_key_authentication(self.ingest_URL, self.app_id, self.app_secret, self.tenant_id)
     ```
  9. The `KustoConnectionStringBuilder.with_aad_application_key_authentication` method is used to construct the connection string, directly utilizing the `self.app_secret`. This indicates that the application secret is used as provided in the configuration without any secure handling within the addon code itself.
  10. There is no evidence within the provided code of any attempt to securely store or retrieve the `app_secret`. It is highly probable that Splunk stores the configured parameters, including the `app_secret`, in a configuration file in plain text or a reversibly encoded format, making it accessible to anyone with filesystem access to the Splunk server or administrative access within Splunk.

- Security Test Case:
  1. Install the `TA-splunkadx-alert` addon on a Splunk instance.
  2. Configure the addon by navigating to Alert Actions and creating a new alert action of type "send_to_adx".
  3. In the alert action configuration, fill in all the required parameters, including "Azure Application Client Id" (app_id) and "Azure Application Client Secret" (app_secret) with valid credentials for accessing an Azure Data Explorer cluster. Save the configuration.
  4. Access the Splunk server's filesystem. Navigate to the addon's configuration directory, typically located at `$SPLUNK_HOME/etc/apps/TA-splunkadx-alert/`.
  5. Look for configuration files that store the alert action parameters. These might be in `local/` or `default/` directories and could be `.conf` files (like `alert_actions.conf`, `app.conf` or a custom configuration file for the addon).
  6. Open and examine these configuration files. Search for the parameter names related to the Azure credentials, such as `app_secret` or `application_client_secret` (or similar names used in the addon's configuration).
  7. Verify if the value of `app_secret` is stored in plain text or in a format that is easily decodable (e.g., base64 without proper encryption). If the secret is directly visible or easily recovered, it confirms the credentials exposure vulnerability.
  8. (Optional, for deeper verification and impact demonstration): If the secret is retrieved, use it along with the configured `app_id` and `tenant_id` to attempt authentication against the configured Azure Data Explorer cluster. You can use the Azure CLI, PowerShell, or a programming language with the Azure SDK to attempt to connect to the ADX cluster using the exposed credentials. Successful authentication and data access would further demonstrate the impact of the vulnerability.