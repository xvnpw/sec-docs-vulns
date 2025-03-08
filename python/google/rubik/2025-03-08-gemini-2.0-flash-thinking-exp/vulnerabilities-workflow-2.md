## Combined Vulnerability Report

The following vulnerability has been identified across multiple reports. It describes a critical security flaw related to insecure credential storage in the Rubik project.

### Vulnerability Name: Insecure Storage of OAuth 2.0 Credentials in Configuration File

- **Description:**
  1. The Rubik application stores sensitive OAuth 2.0 credentials directly in the `rubik.yaml` configuration file in plaintext. These credentials include: `client_id`, `client_secret`, `access_token`, and `refresh_token` required to interact with Google Merchant Center API and potentially Google Cloud Vision API.
  2. The project's documentation and configuration files (`README.md`, `rubik.yaml`) explicitly instruct users to store these credentials in plaintext within the `rubik.yaml` file, typically located in the project's root directory.
  3. An attacker who gains unauthorized read access to the `rubik.yaml` file can easily extract these plaintext credentials. This unauthorized access can occur through various means, including accidental commits to public repositories, insecure server configurations, local machine compromise, or social engineering.
  4. With the extracted credentials, the attacker can impersonate the legitimate user and gain unauthorized access to their Google Merchant Center account and potentially Google Cloud Vision API.
  5. This unauthorized access allows the attacker to perform malicious actions such as viewing, modifying, or deleting product listings, exfiltrating sensitive business data, manipulating product information, and consuming Vision API quota, depending on the scope of the granted OAuth permissions.

- **Impact:**
  - **Unauthorized Access to Google Merchant Center:** An attacker gains full control over the victim's Google Merchant Center account.
    - **Data Breach:**  Exfiltration of product listings, pricing, customer data, and other sensitive business information.
    - **Data Manipulation:** Malicious modifications to product listings, leading to incorrect product information, disapproved offers, or suspension of the Merchant Center account, causing reputational and financial damage.
    - **Business Disruption:** Deletion of product listings, causing business disruption and potential financial loss.
  - **Unauthorized Access to Google Cloud Vision API:**  If Vision API is used, attacker gains access to the victim's Google Cloud Vision API project.
    - **Financial Impact:** Consumption of the victim's Vision API quota, potentially incurring unexpected costs.
    - **Potential Data Breaches:**  If the attacker uses the Vision API to process and exfiltrate sensitive data.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
  - None. The project, as currently designed and documented, encourages and facilitates the insecure storage of credentials in plaintext within the `rubik.yaml` file. There are no built-in security measures to protect these credentials.

- **Missing Mitigations:**
  - **Secure Credential Storage Mechanisms:** Implement secure alternatives to plaintext storage for OAuth 2.0 credentials.
    - **Environment Variables:** Store `client_id` and `client_secret` as environment variables. Explore secure storage solutions for access and refresh tokens, possibly using OS-level credential storage or encrypted files.
    - **Operating System Credential Storage:** Utilize OS-level credential managers (like Credential Manager on Windows, Keychain on macOS, or Secret Service API on Linux) to store credentials securely.
    - **Encrypted Configuration File:** Encrypt the `rubik.yaml` file or at least the sections containing sensitive credentials. Employ strong encryption algorithms and consider using user-provided passphrases or keys for decryption.
    - **Dedicated Secrets Management Solutions:** Integrate with dedicated secrets management services (like HashiCorp Vault, Google Cloud Secret Manager) to store and retrieve credentials securely, especially for more complex deployments.
    - **Prompt for Secret at Runtime:**  For desktop applications, consider prompting the user to enter the Client Secret each time the application runs, instead of persistent storage.
  - **File System Permissions:** Advise users to restrict file system permissions on `rubik.yaml` to ensure only authorized users can access it, regardless of the chosen storage method.
  - **Documentation and Warnings:**
    - **Security Risk Documentation:** Clearly and prominently document the severe security risks associated with storing credentials in plaintext.
    - **Strong Recommendations:** Strongly recommend users adopt secure credential management practices and explicitly discourage plaintext storage.
    - **README and Setup Guide Warnings:** Include prominent warnings in the README, setup guides, and any relevant documentation about the critical importance of protecting the `rubik.yaml` file and the dangers of plaintext credential storage. Guide users on secure alternatives like environment variables.

- **Preconditions:**
  - The user must follow the project's instructions and store their OAuth Desktop `client_id`, `client_secret`, `access_token`, and `refresh_token` in the `rubik.yaml` file.
  - The attacker must gain unauthorized read access to the `rubik.yaml` file. This could occur if:
    - The user's local machine or server where `rubik.yaml` is stored is compromised (malware, remote access tools, physical access, etc.).
    - The system where Rubik is deployed has insecure access controls.
    - The user accidentally commits `rubik.yaml` to a public version control repository (e.g., GitHub).
    - The user inadvertently shares the `rubik.yaml` file with an attacker through social engineering or other means.
    - Insecure server configuration where the application is deployed, allowing unauthorized file access.

- **Source Code Analysis:**
  1. **`rubik.yaml`**: This file is intended as the configuration file and is explicitly designed to store sensitive OAuth credentials (`client_id`, `client_secret`, `access_token`, `refresh_token`) in plaintext YAML format. Example content demonstrates placeholders for these credentials.
  2. **`config/read.py`**: The `read_from_yaml` function is responsible for parsing the `rubik.yaml` file. It uses the `PyYAML` library to load the YAML content into a Python dictionary without any decryption or security measures.
    ```python
    def read_from_yaml(file_name="rubik.yaml"):
        logger().info(f"Attempting to read YAML: {file_name}")
        try:
            with open(file_name) as f:
                data = yaml.load(f, Loader=SafeLoader) # Loads YAML content into data dict without decryption
            logger().debug("Read yaml with data: " + str(data))
            return data # Returns dictionary with all yaml content, including plaintext credentials
        except Exception as ex:
            logger().error("Error when attempting to read yaml: " + str(ex))
            raise ex
    ```
  3. **`main.py`**: The `Rubik` class constructor calls `read_from_yaml` to load the configuration, including the plaintext credentials, from `rubik.yaml`. These credentials are then stored in `rubik_options` and passed directly to other components like `MerchantCenterUpdaterDoFn` and potentially `VisionProcessorDoFn` (if Vision API is used).
    ```python
    class Rubik:
        def __init__(self, config_file):
            config = read_from_yaml(config_file) # Reads plaintext config
            pipeline_options = PipelineOptions()
            rubik_options = config # rubik_options now contains the plaintext credentials
            # ... rubik_options passed to other components
    ```
  4. **`merchant/merchant_center_uploader.py`**: The `MerchantCenterUpdaterDoFn` class receives the plaintext credentials in its constructor. These credentials, originating from the plaintext `rubik.yaml`, are used to create `google.oauth2.credentials.Credentials` for authentication with the Google Content API in the `_get_merchant_center_service` method.  Similarly, `VisionProcessorDoFn` in `/code/vision/vision.py` (if applicable) would also receive and use the plaintext credentials.
    ```python
    class MerchantCenterUpdaterDoFn(beam.DoFn):
        def __init__(
            self,
            client_id: ValueProvider, # client_id from rubik.yaml
            client_secret: ValueProvider, # client_secret from rubik.yaml
            access_token: ValueProvider, # access_token from rubik.yaml
            refresh_token: ValueProvider, # refresh_token from rubik.yaml
            custom_label: ValueProvider,
        ) -> None:
            super().__init__()
            self.client_id = client_id
            self.client_secret = client_secret
            self.access_token = access_token
            self.refresh_token = refresh_token
            self.custom_label = custom_label

        def _get_merchant_center_service(self):
            credentials = Credentials(
                token=self.access_token, # Using access_token from rubik.yaml
                refresh_token=self.refresh_token, # Using refresh_token from rubik.yaml
                client_id=self.client_id, # Using client_id from rubik.yaml
                client_secret=self.client_secret, # Using client_secret from rubik.yaml
                token_uri="https://accounts.google.com/o/oauth2/token",
                scopes=["https://www.googleapis.com/auth/content"],
            )
            # ...
    ```
  5. **`generate_token.py`**: This script, used to generate access and refresh tokens, explicitly requires and uses `client_id` and `client_secret` as command-line arguments, further highlighting the expectation that these sensitive values are accessible and used in plaintext.

- **Security Test Case:**
  1. **Prerequisites:**
     - Set up the Rubik project environment as described in the `README.md`, including installing dependencies and enabling necessary Google Cloud APIs (Content API, Vision API if applicable).
     - Create OAuth Desktop Client credentials in Google Cloud Console.
     - Configure the `rubik.yaml` file with the created `client_id`, `client_secret`, a generated `access_token`, and `refresh_token`. Obtain `access_token` and `refresh_token` by running `generate_token.py` as described in `README.md`.
  2. **Simulate Attacker Access:**
     - Assume an attacker gains read access to the `rubik.yaml` file. Simulate this by copying the `rubik.yaml` file to a different location accessible to the attacker.
  3. **Extract Credentials:**
     - Open the copied `rubik.yaml` file with a text editor and manually extract the plaintext values for `client_id`, `client_secret`, `access_token`, and `refresh_token`.
  4. **Attempt Unauthorized API Access (Merchant Center API):**
     - Use a tool like `curl` or a Python script with the `google-api-python-client` library to make a request to the Google Content API.
     - Use the extracted `access_token` to authenticate the API request. For example, using `curl`:
       ```bash
       # Replace with your stolen access_token and merchant ID
       ACCESS_TOKEN="YOUR_STOLEN_ACCESS_TOKEN"
       MERCHANT_ID="YOUR_MERCHANT_ID"

       curl -X GET \
         -H "Authorization: Bearer ${ACCESS_TOKEN}" \
         "https://content.googleapis.com/content/v2.1/${MERCHANT_ID}/products"
       ```
  5. **Attempt Unauthorized API Access (Vision API - if applicable):**
     -  Similarly, use the extracted credentials to attempt unauthorized access to the Google Cloud Vision API, if the Rubik project utilizes it.
  6. **Verify Successful Unauthorized Access:**
     - If the API request is successful (HTTP 200 OK) and returns data from the Merchant Center account (e.g., product data) or Vision API, it confirms that the attacker, using the stolen credentials from `rubik.yaml`, has successfully gained unauthorized access. This demonstrates the vulnerability.