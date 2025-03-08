### Vulnerability 1: Plaintext Storage of OAuth 2.0 Credentials in Configuration File

- Description:
    1. The Rubik application stores sensitive OAuth 2.0 credentials directly in the `rubik.yaml` configuration file in plaintext. These credentials include:
        - `client_id`: The OAuth 2.0 Client ID for the Google Cloud Project.
        - `client_secret`: The OAuth 2.0 Client Secret for the Google Cloud Project.
        - `access_token`: The user-specific OAuth 2.0 access token for accessing the Google Merchant Center API.
        - `refresh_token`: The user-specific OAuth 2.0 refresh token for obtaining new access tokens.
    2. An attacker gains unauthorized read access to the `rubik.yaml` file.
    3. The attacker opens the `rubik.yaml` file and extracts the plaintext credentials.
    4. The attacker can now use these extracted credentials to authenticate as the legitimate user and interact with the Google Merchant Center API.

- Impact:
    - Unauthorized access to the victim's Google Merchant Center account.
    - Malicious modifications to product listings, potentially leading to incorrect product information, disapproved offers, or suspension of the Merchant Center account.
    - Data exfiltration from the Merchant Center account.
    - Financial losses due to manipulation of product listings or unauthorized actions within the Merchant Center account.

- Vulnerability Rank: High

- Currently implemented mitigations:
    - None. The application is designed to read credentials directly from the `rubik.yaml` file without any built-in security measures for credential protection.

- Missing mitigations:
    - **Secure Credential Storage:** Implement secure storage mechanisms for OAuth 2.0 credentials instead of plaintext files. Consider:
        - **Environment Variables:** Store `client_id` and `client_secret` as environment variables, and explore secure storage for tokens.
        - **Secret Management Systems:** Integrate with Google Secret Manager or other secure vault solutions to store and retrieve credentials.
        - **Encrypted Configuration Files:** Encrypt the `rubik.yaml` file or specific sections containing sensitive data.
    - **File System Permissions:**  Advise users to restrict file system permissions on `rubik.yaml` to ensure only authorized users can access it.
    - **Documentation and Warnings:**
        - Clearly document the security risks associated with storing credentials in plaintext.
        - Strongly recommend users to adopt secure credential management practices.
        - Include warnings in the README and any setup guides about the importance of protecting the `rubik.yaml` file.

- Preconditions:
    - The attacker must gain unauthorized read access to the `rubik.yaml` file. This could happen if:
        - The user's local machine where `rubik.yaml` is stored is compromised.
        - The system where Rubik is deployed has insecure access controls.
        - The user inadvertently shares the `rubik.yaml` file with an attacker.

- Source code analysis:
    1. **`/code/rubik.yaml`**: This file serves as the configuration file and is intended to store credentials in plaintext as indicated by the example content:
        ```yaml
        client_id: <client_id>
        client_secret: <client_secret>
        access_token: <access_token>
        refresh_token: <refresh_token>
        ...
        ```
    2. **`/code/config/read.py`**: The `read_from_yaml` function is responsible for reading the `rubik.yaml` file. It uses the `PyYAML` library to parse the YAML file and load its contents into a Python dictionary.
        ```python
        def read_from_yaml(file_name="rubik.yaml"):
            logger().info(f"Attempting to read YAML: {file_name}")
            try:
                with open(file_name) as f:
                    data = yaml.load(f, Loader=SafeLoader)
                logger().debug("Read yaml with data: " + str(data))
                return data
            except Exception as ex:
                logger().error("Error when attempting to read yaml: " + str(ex))
                raise ex
        ```
    3. **`/code/main.py`**: The `Rubik` class in `main.py` initializes the application by calling `read_from_yaml` to load the configuration from `rubik.yaml`. The constructor then passes the credential values directly from the configuration dictionary to the `MerchantCenterUpdaterDoFn`.
        ```python
        class Rubik:
            def __init__(self, config_file):
                config = read_from_yaml(config_file)
                pipeline_options = PipelineOptions()
                rubik_options = config
                ...
                (
                    process
                    | "Upload to Merchant Center"
                    >> beam.ParDo(
                        MerchantCenterUpdaterDoFn(
                            rubik_options["client_id"],
                            rubik_options["client_secret"],
                            rubik_options["access_token"],
                            rubik_options["refresh_token"],
                            rubik_options["rubik_custom_label"],
                        )
                    )
                )
        ```
    4. **`/code/merchant/merchant_center_uploader.py`**: The `MerchantCenterUpdaterDoFn` class receives the plaintext credentials in its `__init__` method and uses them to create `google.oauth2.credentials.Credentials` for authenticating with the Google Merchant Center API in the `_get_merchant_center_service` method.
        ```python
        class MerchantCenterUpdaterDoFn(beam.DoFn):
            def __init__(
                self,
                client_id: ValueProvider,
                client_secret: ValueProvider,
                access_token: ValueProvider,
                refresh_token: ValueProvider,
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
                    token=self.access_token,
                    refresh_token=self.refresh_token,
                    client_id=self.client_id,
                    client_secret=self.client_secret,
                    token_uri="https://accounts.google.com/o/oauth2/token",
                    scopes=["https://www.googleapis.com/auth/content"],
                )
                service = build("content", "v2.1", credentials=credentials)
                return service
        ```
    This analysis clearly shows that the application reads and uses the credentials directly from the `rubik.yaml` file without any security measures to protect them from unauthorized access if the file itself is compromised.

- Security test case:
    1. **Prerequisites:**
        - Install Python and the required libraries as specified in `requirements.txt`.
        - Obtain OAuth 2.0 Client ID and Client Secret for a Google Cloud Project with the necessary APIs enabled (Content API, Vision API if used).
        - Generate OAuth 2.0 Access Token and Refresh Token for your Google Merchant Center account using `generate_token.py`.
        - Create a `rubik.yaml` file and populate it with the obtained `client_id`, `client_secret`, `access_token`, `refresh_token`, and other necessary configurations (e.g., BigQuery details or CSV file path).
    2. **Step 1: Access the `rubik.yaml` file.**
        - As an attacker, gain read access to the `rubik.yaml` file. For a local test, this simply means opening the file using a text editor. In a real-world scenario, this could involve exploiting system vulnerabilities or social engineering.
    3. **Step 2: Extract Credentials.**
        - Open `rubik.yaml` and locate the following lines:
            ```yaml
            client_id: <your_client_id>
            client_secret: <your_client_secret>
            access_token: <your_access_token>
            refresh_token: <your_refresh_token>
            ```
        - Copy the values of `client_id`, `client_secret`, `access_token`, and `refresh_token`.
    4. **Step 3: Authenticate and Access Merchant Center API using Extracted Credentials.**
        - Use a tool like `curl` or a Python script with the `google-api-python-client` library.
        - Example using `curl` to list products (replace placeholders with extracted values and your merchant ID):
            ```bash
            ACCESS_TOKEN="<your_access_token>"
            MERCHANT_ID="<your_merchant_id>"
            curl -X GET \
                -H "Authorization: Bearer ${ACCESS_TOKEN}" \
                "https://content.googleapis.com/content/v2.1/${MERCHANT_ID}/products"
            ```
        - Or using a Python script:
            ```python
            from googleapiclient.discovery import build
            from google.oauth2.credentials import Credentials

            client_id = "<your_client_id>"
            client_secret = "<your_client_secret>"
            access_token = "<your_access_token>"
            refresh_token = "<your_refresh_token>"
            merchant_id = "<your_merchant_id>" # Replace with your merchant ID

            credentials = Credentials(
                token=access_token,
                refresh_token=refresh_token,
                client_id=client_id,
                client_secret=client_secret,
                token_uri="https://accounts.google.com/o/oauth2/token",
                scopes=["https://www.googleapis.com/auth/content"],
            )

            service = build("content", "v2.1", credentials=credentials)

            try:
                request = service.products().list(merchantId=merchant_id)
                response = request.execute()
                print("Products:")
                for product in response.get('resources', []):
                    print(product)
            except Exception as e:
                print(f"An error occurred: {e}")
            ```
        - Replace `<your_client_id>`, `<your_client_secret>`, `<your_access_token>`, `<your_refresh_token>`, and `<your_merchant_id>` with the values extracted from `rubik.yaml`.
    5. **Step 4: Verify Successful API Access.**
        - If the `curl` command or Python script successfully executes and returns a list of products or other Merchant Center data without authentication errors, it confirms that the extracted credentials are valid and can be used to access the Merchant Center API. This demonstrates the vulnerability of plaintext credential storage.