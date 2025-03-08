### Vulnerability 1: Sensitive Data Exfiltration via Malicious Loki Endpoint
- Description:
    1. An attacker convinces a user to deploy the Azure Function. This could be through social engineering, misleading documentation, or supply chain attacks.
    2. During the deployment process, the user is instructed or tricked into setting the `LOKI_ENDPOINT` environment variable to a URL controlled by the attacker. This could be disguised as a legitimate Grafana Loki endpoint.
    3. The Azure Function, upon deployment, reads the `LOKI_ENDPOINT` environment variable and configures the Loki client to send logs to this specified endpoint.
    4. When Azure Event Hub events are received, the Azure Function processes these events and forwards the logs to the configured Loki endpoint, which is now under the attacker's control.
    5. The attacker receives all the sensitive Azure logs sent by the Azure Function to their malicious Loki endpoint. This results in the exfiltration of potentially sensitive information contained within the Azure logs.
- Impact:
    - Confidentiality breach: Sensitive Azure logs, which may contain business-critical information, security-related events, or personal data, are exfiltrated to an attacker-controlled system.
    - Compliance violation: Depending on the nature of the exfiltrated logs and applicable regulations (e.g., GDPR, HIPAA, PCI DSS), the data exfiltration could lead to compliance violations and associated penalties.
    - Reputational damage: If the data exfiltration becomes public, it can severely damage the reputation of the organization that deployed the compromised Azure Function.
- Vulnerability rank: High
- Currently implemented mitigations:
    - None. The code directly uses the `LOKI_ENDPOINT` environment variable without any validation or sanitization.
- Missing mitigations:
    - Input validation for the `LOKI_ENDPOINT` environment variable: Implement checks to ensure that the provided URL is valid and potentially restrict the allowed protocols (e.g., only allow HTTPS) and domains to a predefined whitelist of trusted Grafana Loki instances or Grafana Cloud domains.
    - Documentation enhancement: Add a prominent security warning in the documentation (README.md, INSTALLATION.md) explicitly advising users about the risks of using untrusted Loki endpoints. Recommend using only trusted and secured Grafana Loki instances or Grafana Cloud endpoints. Emphasize the importance of verifying the `LOKI_ENDPOINT` configuration to prevent accidental or malicious data exfiltration.
- Preconditions:
    1. An attacker must convince a user to deploy the Azure Function.
    2. The user must be tricked or directed to configure the `LOKI_ENDPOINT` environment variable with a malicious URL controlled by the attacker during the deployment process.
- Source code analysis:
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

- Security test case:
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