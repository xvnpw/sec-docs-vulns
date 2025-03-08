## Vulnerability Report

### 1. Insecure Storage of Loki Credentials in Environment Variables

- **Vulnerability Name:** Insecure Storage of Loki Credentials in Environment Variables
- **Description:**
    - The Azure Function configuration relies on environment variables to store sensitive credentials for authenticating with Grafana Loki, specifically `LOKI_USERNAME` and `LOKI_PASSWORD`.
    - Environment variables within Azure Function configurations are stored in plaintext by default.
    - An attacker gaining unauthorized access to the Azure Function's configuration settings in the Azure portal or via Azure APIs can easily retrieve these plaintext credentials.
    - This access could be achieved through various means, including:
        - Compromising Azure account credentials with sufficient permissions.
        - Exploiting vulnerabilities in the Azure platform itself.
        - Gaining access through insider threats.
- **Impact:**
    - If an attacker obtains the plaintext Loki credentials, they can directly authenticate to the Grafana Loki instance.
    - This unauthorized access allows the attacker to:
        - Read sensitive logs collected by the Azure Function.
        - Potentially manipulate or delete logs, depending on Loki's access control configurations (which are outside the scope of this project but are relevant to the overall risk).
        - Use the compromised Loki instance as a pivot point for further attacks if the Loki instance is not properly isolated.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - None. The project currently relies on the default environment variable handling of Azure Functions, which stores them in plaintext.
- **Missing Mitigations:**
    - **Secure Secret Storage:** Implement the use of Azure Key Vault to store Loki credentials securely. Instead of storing credentials directly as environment variables, the Azure Function should be configured to retrieve them from Azure Key Vault. Azure Key Vault encrypts secrets at rest and provides access control mechanisms.
    - **Documentation Update:** Update the project's documentation (INSTALLATION.md and README.md) to strongly recommend and guide users on how to use Azure Key Vault for storing Loki credentials instead of plaintext environment variables.
    - **Principle of Least Privilege:**  While not a code mitigation, emphasize in documentation the importance of applying the principle of least privilege when granting access to the Azure Function and its associated resources in Azure. Restrict access to the Azure Function's configuration settings to only authorized personnel and services.
- **Preconditions:**
    - The Azure Function must be deployed and configured to use environment variables for `LOKI_USERNAME` and `LOKI_PASSWORD`.
    - An attacker must gain unauthorized access to the Azure Function's configuration settings within the Azure environment (e.g., through the Azure portal, Azure APIs, or other Azure security breaches).
- **Source Code Analysis:**
    - **`function_app.py`:**
        ```python
        loki_client = LokiClient(
            os.environ["LOKI_ENDPOINT"],
            os.environ.get("LOKI_USERNAME"),
            os.environ.get("LOKI_PASSWORD"),
        )
        ```
        - This code snippet shows that the `LokiClient` is initialized by directly retrieving `LOKI_USERNAME` and `LOKI_PASSWORD` from environment variables using `os.environ` and `os.environ.get()`.
        - No attempt is made to retrieve these credentials from a secure secret store like Azure Key Vault or to encrypt them within the application's configuration.
    - **`logexport/loki/client.py`:**
        ```python
        class LokiClient:
            # ...
            def __init__(
                self, url: str, username: str | None = None, password: str | None = None
            ):
                # ...
                if username is not None and password is not None:
                    self.auth = HTTPBasicAuth(username, password)
                else:
                    self.auth = None
        ```
        - The `LokiClient` class correctly uses the provided `username` and `password` to set up HTTP Basic Authentication. However, it relies on the caller (`function_app.py`) to provide these credentials, which are fetched from potentially insecure environment variables.
- **Security Test Case:**
    1. **Deployment:** Deploy the Azure Function using the provided ARM template or manual steps as described in `INSTALLATION.md`. During deployment, configure the `LokiUsername` and `LokiPassword` parameters (if using ARM template) or set the `GL_API_USER` and `GL_API_KEY` environment variables (if using manual steps as per `INSTALLATION.md` - note that `GL_API_USER`/`GL_API_KEY` map to Loki username/password in the context of Grafana Cloud, as seen in `INSTALLATION.md`).
    2. **Access Azure Function Configuration:** As an attacker with valid Azure credentials and sufficient permissions to access the deployed Azure Function (or simulate a scenario where such access is compromised), navigate to the Azure Function app resource in the Azure portal.
    3. **Navigate to Configuration Settings:** In the Azure Function app, go to "Configuration" under the "Settings" section in the left-hand navigation menu.
    4. **Examine Application Settings:** Locate the "Application settings" section. Find the settings corresponding to the Loki credentials (e.g., `LOKI_USERNAME`, `LOKI_PASSWORD` or their equivalent if different environment variable names were used based on `INSTALLATION.md` like `GL_API_USER`, `GL_API_KEY`).
    5. **Verify Plaintext Storage:** Observe that the values for the Loki credentials are displayed in plaintext in the "Value" column of the application settings. There is no indication of encryption or secure masking.
    6. **Attempt Loki Authentication:** Copy the plaintext `LOKI_USERNAME` and `LOKI_PASSWORD`. Use these credentials to attempt to authenticate against the Grafana Loki endpoint configured for the Azure Function. This can be done using `curl` or a Grafana client. For example, using `curl`:
        ```bash
        curl -u "<LOKI_USERNAME>:<LOKI_PASSWORD>" "<LOKI_ENDPOINT>/loki/api/v1/query?query={job=\"integrations/azure-logexport\"}"
        ```
        Replace `<LOKI_USERNAME>`, `<LOKI_PASSWORD>`, and `<LOKI_ENDPOINT>` with the retrieved values.
    7. **Validate Unauthorized Access:** If the `curl` command (or equivalent Grafana client action) successfully authenticates and returns data from Grafana Loki, it confirms that an attacker with access to the Azure Function's configuration can retrieve and use the plaintext credentials to gain unauthorized access to the Grafana Loki instance.

### 2. Sensitive Data Exfiltration via Malicious Loki Endpoint

- **Vulnerability Name:** Sensitive Data Exfiltration via Malicious Loki Endpoint
- **Description:**
    1. An attacker convinces a user to deploy the Azure Function. This could be through social engineering, misleading documentation, or supply chain attacks.
    2. During the deployment process, the user is instructed or tricked into setting the `LOKI_ENDPOINT` environment variable to a URL controlled by the attacker. This could be disguised as a legitimate Grafana Loki endpoint.
    3. The Azure Function, upon deployment, reads the `LOKI_ENDPOINT` environment variable and configures the Loki client to send logs to this specified endpoint.
    4. When Azure Event Hub events are received, the Azure Function processes these events and forwards the logs to the configured Loki endpoint, which is now under the attacker's control.
    5. The attacker receives all the sensitive Azure logs sent by the Azure Function to their malicious Loki endpoint. This results in the exfiltration of potentially sensitive information contained within the Azure logs.
- **Impact:**
    - Confidentiality breach: Sensitive Azure logs, which may contain business-critical information, security-related events, or personal data, are exfiltrated to an attacker-controlled system.
    - Compliance violation: Depending on the nature of the exfiltrated logs and applicable regulations (e.g., GDPR, HIPAA, PCI DSS), the data exfiltration could lead to compliance violations and associated penalties.
    - Reputational damage: If the data exfiltration becomes public, it can severely damage the reputation of the organization that deployed the compromised Azure Function.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - None. The code directly uses the `LOKI_ENDPOINT` environment variable without any validation or sanitization.
- **Missing Mitigations:**
    - Input validation for the `LOKI_ENDPOINT` environment variable: Implement checks to ensure that the provided URL is valid and potentially restrict the allowed protocols (e.g., only allow HTTPS) and domains to a predefined whitelist of trusted Grafana Loki instances or Grafana Cloud domains.
    - Documentation enhancement: Add a prominent security warning in the documentation (README.md, INSTALLATION.md) explicitly advising users about the risks of using untrusted Loki endpoints. Recommend using only trusted and secured Grafana Loki instances or Grafana Cloud endpoints. Emphasize the importance of verifying the `LOKI_ENDPOINT` configuration to prevent accidental or malicious data exfiltration.
- **Preconditions:**
    1. An attacker must convince a user to deploy the Azure Function.
    2. The user must be tricked or directed to configure the `LOKI_ENDPOINT` environment variable with a malicious URL controlled by the attacker during the deployment process.
- **Source Code Analysis:**
    1. File: `/code/function_app.py`
        ```python
        loki_client = LokiClient(
            os.environ["LOKI_ENDPOINT"],
            os.environ.get("LOKI_USERNAME"),
            os.environ.get("LOKI_PASSWORD"),
        )
        ```
        - The `LokiClient` is instantiated using the `LOKI_ENDPOINT` environment variable directly from `os.environ`.
        - There is no validation or sanitization of the `LOKI_ENDPOINT` value before it's passed to the `LokiClient` constructor.

    2. File: `/code/logexport/loki/client.py`
        ```python
        class LokiClient:

            endpoint: str
            auth: HTTPBasicAuth | None

            def __init__(
                self, url: str, username: str | None = None, password: str | None = None
            ):
                self.endpoint = url
                # ...
        ```
        - The `LokiClient` class constructor takes the `url` parameter and assigns it directly to `self.endpoint` without any validation or security checks.
        - The `self.endpoint` is then used in `push` and `query` methods to send requests to the specified URL.

    3. File: `/code/README.md` and `/code/INSTALLATION.md`
        - These files describe the deployment process and instruct users to configure the `LOKI_ENDPOINT` environment variable.
        - They do not contain any security warnings or recommendations regarding the importance of using trusted Loki endpoints or validating the `LOKI_ENDPOINT` configuration.

    **Visualization:**

    ```
    User (Deploys Azure Function) --> Configures LOKI_ENDPOINT (Attacker's URL)
                                        |
    Azure Function (Deployed) --------> LokiClient (Endpoint: Attacker's URL)
                                        |
    Azure Event Hub (Logs) ----------> Azure Function
                                        |
    Azure Function (Forwards Logs) --> Attacker's Loki Server (Data Exfiltration)
    ```

- **Security Test Case:**
    1. **Set up Attacker-Controlled Loki Mock Server:**
        - Deploy a simple HTTP server that can act as a mock Grafana Loki instance. This server should be capable of receiving and logging HTTP POST requests to the `/loki/api/v1/push` endpoint. You can use tools like `netcat`, `python -m http.server`, or a more sophisticated mock server framework. This server will be controlled by the attacker and will simulate a malicious Loki endpoint.
    2. **Deploy Azure Function with Malicious Configuration:**
        - Follow the installation steps described in `README.md` or `INSTALLATION.md` to deploy the Azure Function to an Azure Function App.
        - When configuring the Azure Function App settings, specifically set the `LOKI_ENDPOINT` environment variable to the URL of the attacker-controlled Loki mock server (e.g., `http://<attacker-server-ip>:<attacker-server-port}`). Use valid values for other required environment variables to ensure the function starts correctly.
    3. **Generate Azure Logs:**
        - Trigger activities in Azure that generate logs that would be captured by the Azure Event Hub and forwarded by the Azure Function. This could involve interacting with Azure resources, creating or modifying resources, or triggering alerts. The type of logs will depend on the Event Hub configuration.
    4. **Observe Log Exfiltration on Attacker's Server:**
        - Check the logs of the attacker-controlled Loki mock server.
        - Verify that the server has received HTTP POST requests to the `/loki/api/v1/push` endpoint.
        - Inspect the body of these POST requests. They should contain the compressed protobuf data representing the Azure logs that were sent by the deployed Azure Function.
        - If the attacker's server successfully receives and logs the Azure logs, it confirms that sensitive data is being exfiltrated to the attacker-controlled endpoint due to the lack of `LOKI_ENDPOINT` validation.