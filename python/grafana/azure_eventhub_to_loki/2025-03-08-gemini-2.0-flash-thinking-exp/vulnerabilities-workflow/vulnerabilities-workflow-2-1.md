- **Vulnerability Name:** Insecure Credential Handling - Plaintext Storage in Environment Variables
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
- **Vulnerability Rank:** Medium
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