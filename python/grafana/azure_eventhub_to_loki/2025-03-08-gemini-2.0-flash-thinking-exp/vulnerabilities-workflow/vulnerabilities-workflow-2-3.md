- Vulnerability Name: Insecure Storage of Loki Credentials in Environment Variables
- Description:
    - The Grafana Loki credentials (username and password) for authentication are configured using environment variables: `LOKI_USERNAME` and `LOKI_PASSWORD`.
    - These environment variables are typically stored in plain text within the Azure Function's configuration.
    - If an attacker gains access to the Azure Function's configuration settings, they can easily retrieve these credentials in plain text.
    - Access to the Azure Function configuration can be achieved through various means, including:
        - Unauthorized access to the Azure portal.
        - Exploiting other vulnerabilities in the Azure environment to gain access to configuration APIs.
        - Insider threats or compromised accounts with access to the Azure subscription.
- Impact:
    - Exposure of Loki credentials allows unauthorized access to the Grafana Loki instance.
    - An attacker can read sensitive logs stored in Loki, potentially containing confidential information.
    - Attackers could modify or delete logs, disrupting security monitoring and potentially covering their tracks.
    - Compromised Loki access can be a stepping stone for further attacks within the infrastructure if Loki is connected to other systems or holds valuable information about the network.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The project relies on the user to manually secure environment variables within their Azure environment. There are no built-in mechanisms within the code to protect these credentials.
- Missing Mitigations:
    - Secure Secret Storage: Implement and recommend the use of Azure Key Vault or a similar secure secret management service to store Loki credentials. The Azure Function should be configured to retrieve these credentials from Key Vault at runtime instead of directly using environment variables. This prevents credentials from being stored in plain text in the Function App configuration.
    - Documentation on Secure Credential Management: Add documentation that explicitly warns users about the risks of storing credentials in environment variables and strongly recommends using secure secret storage solutions like Azure Key Vault. Provide step-by-step instructions on how to configure the Azure Function to retrieve credentials from Key Vault.
    - Principle of Least Privilege: Document and emphasize the importance of applying the principle of least privilege when configuring access permissions for the Azure Function and related resources. Ensure the Function has only the necessary permissions to access Event Hub and Loki, minimizing the potential impact of credential compromise.
- Preconditions:
    - The Azure Function must be deployed and configured to use `LOKI_USERNAME` and `LOKI_PASSWORD` environment variables for Loki authentication.
    - An attacker must gain unauthorized access to the Azure Function's configuration settings in the Azure environment. This could be through various means, such as compromised Azure accounts, insider access, or exploitation of other vulnerabilities in the Azure infrastructure.
- Source Code Analysis:
    - `function_app.py`:
        ```python
        loki_client = LokiClient(
            os.environ["LOKI_ENDPOINT"],
            os.environ.get("LOKI_USERNAME"),
            os.environ.get("LOKI_PASSWORD"),
        )
        ```
        - This code snippet shows that the `LokiClient` is initialized by directly fetching the Loki endpoint, username, and password from environment variables using `os.environ`.
        - The `os.environ.get()` method retrieves the values of the environment variables in plain text if they are set.
        - The `LokiClient` constructor then receives these plain text credentials.
        - There is no attempt to mask, encrypt, or retrieve these credentials from a secure storage mechanism within this code.
    - `logexport/loki/client.py`:
        ```python
        class LokiClient:
            ...
            def __init__(
                self, url: str, username: str | None = None, password: str | None = None
            ):
                ...
                if username is not None and password is not None:
                    self.auth = HTTPBasicAuth(username, password)
                else:
                    self.auth = None
        ```
        - The `LokiClient` class correctly utilizes `HTTPBasicAuth` for authentication when a username and password are provided.
        - However, the vulnerability lies in how these username and password values are obtained in the first place – directly from environment variables in `function_app.py` without any secure handling.
- Security Test Case:
    1. Deploy the Azure Function:
        - Deploy the Azure Function using the provided ARM template or manually through the Azure portal.
        - During deployment or configuration, set the following Application Settings for the Function App:
            - `LOKI_ENDPOINT`:  `<your_loki_endpoint_url>` (e.g., `https://<your_loki_instance>.grafana.net`)
            - `LOKI_USERNAME`: `testuser` (or any test username for Loki)
            - `LOKI_PASSWORD`: `testpassword` (or any test password for Loki)
            - ... (other required environment variables like `EVENTHUB_CONNECTION`, `EVENTHUB_NAME`, etc.)
    2. Access Azure Function Configuration:
        - As an attacker with unauthorized access to the Azure portal (or using Azure CLI/PowerShell with compromised credentials), navigate to the deployed Azure Function App.
        - Go to the "Configuration" section under "Settings" in the Function App menu.
        - Select "Application settings".
    3. Observe Exposed Credentials:
        - In the "Application settings" list, locate the settings named `LOKI_USERNAME` and `LOKI_PASSWORD`.
        - Observe that the "Value" for `LOKI_USERNAME` is `testuser` and for `LOKI_PASSWORD` is `testpassword`, both displayed in plain text.
    4. Attempt Loki Authentication (using exposed credentials):
        - Using `curl`, `wget`, or a similar HTTP client, attempt to query the Loki instance using the exposed credentials:
        ```bash
        curl -u testuser:testpassword -X GET <your_loki_endpoint_url>/loki/api/v1/query --data-urlencode 'query={job="integrations/azure-logexport"}'
        ```
        - Replace `<your_loki_endpoint_url>` with the actual Loki endpoint URL used in the Azure Function configuration.
        - If the Loki instance is accessible and the credentials are valid, the command will return a successful response (HTTP 200 OK) along with Loki query results (or an empty result set if no logs match the query).
    5. Verify Unauthorized Access:
        - Successful authentication to Loki using the exposed credentials confirms that the vulnerability allows unauthorized access to the Grafana Loki instance. An attacker can now perform actions like querying, reading, and potentially manipulating logs depending on Loki's authorization and access control configurations beyond basic authentication.