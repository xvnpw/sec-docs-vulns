- Vulnerability Name: Plaintext Storage of OAuth Credentials
- Description:
    - The Rubik application stores OAuth 2.0 client ID, client secret, access token, and refresh token in plaintext within the `rubik.yaml` configuration file.
    - An attacker who gains unauthorized access to the local machine where Rubik is configured can read this file and extract these credentials.
    - This allows the attacker to impersonate the legitimate user and gain unauthorized access to the Google Merchant Center API and Google Cloud Vision API.
- Impact:
    - **Unauthorized Access to Google Merchant Center:** An attacker can use the stolen credentials to access and manipulate the victim's Google Merchant Center account. This could lead to:
        - Data exfiltration of product listings, pricing, and other sensitive business information.
        - Manipulation of product listings, leading to incorrect or malicious information being displayed to customers.
        - Deletion of product listings, causing business disruption and potential financial loss.
    - **Unauthorized Access to Google Cloud Vision API:** The attacker can use the stolen credentials to access the Google Cloud Vision API under the victim's project. This could lead to:
        - Consumption of the victim's Vision API quota, potentially incurring unexpected costs.
        - Potential data breaches if the attacker uses the Vision API to process and exfiltrate sensitive data.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None. The application directly reads and uses plaintext credentials from the `rubik.yaml` file.
- Missing Mitigations:
    - **Secure Credential Storage:** Implement secure storage mechanisms for OAuth credentials. Options include:
        - **Operating System Credential Storage:** Utilize OS-level credential managers (like Credential Manager on Windows, Keychain on macOS, or Secret Service API on Linux) to store credentials securely.
        - **Encrypted Configuration File:** Encrypt the `rubik.yaml` file or at least the sensitive credential sections. Use a strong encryption algorithm and consider using a user-provided passphrase or key for decryption.
        - **Dedicated Secrets Management Solutions:** Integrate with dedicated secrets management services (like HashiCorp Vault, Google Cloud Secret Manager) to store and retrieve credentials securely.
    - **Documentation on Secure Configuration:** Provide clear documentation and best practices for users on how to securely configure and store the `rubik.yaml` file, even if plaintext storage is maintained. This should include warnings about the risks of storing credentials in plaintext and recommendations for restricting file system access to the configuration file.
- Preconditions:
    - An attacker must gain unauthorized access to the local machine where the Rubik application is installed and configured. This could be achieved through various means, such as malware, social engineering, or physical access.
    - The user must have configured the Rubik application with their OAuth client ID, client secret, access token, and refresh token, storing these values in the `rubik.yaml` file.
- Source Code Analysis:
    - **File: `/code/rubik.yaml`**: This file is designed to store configuration parameters, including OAuth credentials, in plaintext YAML format.
    - **File: `/code/config/read.py`**: The `read_from_yaml` function reads the `rubik.yaml` file and loads its content into a Python dictionary without any decryption or secure handling.
        ```python
        def read_from_yaml(file_name="rubik.yaml"):
            logger().info(f"Attempting to read YAML: {file_name}")
            try:
                with open(file_name) as f:
                    data = yaml.load(f, Loader=SafeLoader) # Loads YAML without encryption
                logger().debug("Read yaml with data: " + str(data))
                return data # Returns configuration data including plaintext credentials
            except Exception as ex:
                logger().error("Error when attempting to read yaml: " + str(ex))
                raise ex
        ```
    - **File: `/code/main.py`**: The `Rubik` class constructor reads the configuration using `read_from_yaml` and stores the credential parameters in `rubik_options`. These options are then passed directly to other components.
        ```python
        class Rubik:
            def __init__(self, config_file):
                config = read_from_yaml(config_file) # Reads plaintext config
                pipeline_options = PipelineOptions()
                rubik_options = config # Stores config, including plaintext credentials
                # ... rubik_options passed to other components ...
        ```
    - **File: `/code/merchant/merchant_center_uploader.py` and `/code/vision/vision.py`**: These components receive the plaintext credentials (`client_id`, `client_secret`, `access_token`, `refresh_token`) directly from the configuration and use them to authenticate with Google APIs. There is no evidence of any secure handling or storage within these components.

- Security Test Case:
    1. **Setup:**
        - Assume you have successfully installed and configured Rubik on a test machine, including generating OAuth tokens and storing them in `rubik.yaml`.
        - Simulate an attacker gaining access to the test machine's file system (e.g., through local access or remote access tools).
    2. **Locate and Access `rubik.yaml`:**
        - Navigate to the directory where `rubik.yaml` is stored (typically the project root directory or user's home directory depending on installation).
        - Open `rubik.yaml` with a text editor.
    3. **Extract Credentials:**
        - Observe that `client_id`, `client_secret`, `access_token`, and `refresh_token` are clearly visible and stored in plaintext within the file.
        - Copy the `access_token` and `refresh_token`.
    4. **Attempt Unauthorized API Access (Merchant Center API Example):**
        - Use `curl` or a Python script to make a request to the Google Merchant Center API, using the stolen `access_token`. For example:
            ```bash
            curl -X GET \
              -H "Authorization: Bearer <YOUR_STOLEN_ACCESS_TOKEN>" \
              "https://content.googleapis.com/content/v2.1/<YOUR_MERCHANT_ID>/products"
            ```
            Replace `<YOUR_STOLEN_ACCESS_TOKEN>` with the copied access token and `<YOUR_MERCHANT_ID>` with the merchant ID from your `rubik.yaml` or Merchant Center account.
        - If successful, the API will return Merchant Center product data, proving unauthorized access.
    5. **Attempt Unauthorized API Access (Vision API Example):**
        - Similarly, use `curl` or a Python script with the stolen credentials to access the Google Cloud Vision API, proving unauthorized access to Vision API as well.

This test case demonstrates that an attacker with access to the local machine can easily extract OAuth credentials from `rubik.yaml` and use them to gain unauthorized access to Google Merchant Center and Vision APIs.