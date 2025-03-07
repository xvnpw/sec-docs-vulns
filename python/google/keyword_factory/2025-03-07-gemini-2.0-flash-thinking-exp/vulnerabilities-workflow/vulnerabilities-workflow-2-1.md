- Vulnerability Name: Insecure Storage of Google Ads API OAuth Refresh Token
- Description:
    - The application stores Google Ads API OAuth refresh tokens in plain text within a YAML configuration file named `config.yaml`.
    - During the initial setup or when users update their credentials via the web interface, the application saves these credentials, including the refresh token, into the `config.yaml` file.
    - This `config.yaml` file is then stored in a Google Cloud Storage bucket associated with the project, specifically under the path `gs://[PROJECT_ID]-keyword_factory/config.yaml`.
    - An attacker who gains unauthorized access to this Google Cloud Storage bucket can download the `config.yaml` file.
    - By reading the `config.yaml` file, the attacker can extract the plain text refresh token along with other OAuth credentials (client ID, client secret, developer token, MCC ID).
    - With these stolen credentials, the attacker can impersonate the legitimate user and gain unauthorized access to their Google Ads account.
    - Once authenticated as the user, the attacker can manipulate the victim's advertising campaigns, potentially leading to financial loss, data breaches, or reputational damage for the victim.
- Impact:
    - **Unauthorized Access to Google Ads Account:** An attacker can gain full control over the victim's Google Ads account.
    - **Advertising Campaign Manipulation:** The attacker can modify or create advertising campaigns, potentially wasting the victim's advertising budget or redirecting traffic to malicious sites.
    - **Data Exfiltration:** The attacker might be able to access sensitive data within the Google Ads account, such as campaign performance data, customer lists (if uploaded), and billing information.
    - **Reputational Damage:** If malicious campaigns are run through the compromised account, it can damage the victim's reputation.
    - **Financial Loss:** Unauthorized advertising spend and potential fines for policy violations can lead to financial losses for the victim.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The application currently stores refresh tokens in plain text without any encryption or secure storage mechanisms.
- Missing Mitigations:
    - **Encryption at Rest:** The refresh token should be encrypted before being stored in the `config.yaml` file or any storage medium.
    - **Secure Storage Mechanism:** Instead of storing refresh tokens in a simple YAML file in GCS, a more secure storage mechanism should be used, such as:
        - **Google Cloud KMS:**  Encrypt the refresh token using Cloud KMS and store the encrypted token. The application can then decrypt it at runtime using its service account permissions.
        - **Secret Manager:** Store the refresh token in Google Cloud Secret Manager, which is designed for managing sensitive data like API keys and passwords. The application can retrieve the refresh token securely at runtime.
    - **Access Control to GCS Bucket:** Implement strict Identity and Access Management (IAM) policies on the Google Cloud Storage bucket to limit access only to authorized service accounts and administrators. Follow the principle of least privilege. Regularly review and audit bucket access logs.
- Preconditions:
    1. The Keyword Factory application must be deployed on Google Cloud Platform (GCP).
    2. A user must have successfully configured their Google Ads API credentials through the application's web interface and saved them. This action triggers the storage of the refresh token in the `config.yaml` file within the GCS bucket.
    3. An attacker must gain unauthorized access to the Google Cloud Storage bucket associated with the deployed Keyword Factory project. This could be due to:
        - Misconfigured IAM policies on the GCS bucket, allowing overly permissive access.
        - Compromised GCP credentials (e.g., service account keys, administrator accounts) that have read access to the GCS bucket.
        - A vulnerability in the GCP infrastructure itself (less likely but still a possibility).
- Source Code Analysis:
    - File: `/code/utils/config.py`
        ```python
        class Config:
            # ...
            def save_to_file(self):
                try:
                    with smart_open.open(self.file_path, 'w') as f:
                        yaml.dump(self.to_dict(), f) # [VULNERABILITY] refresh_token is included in to_dict() and saved in plain text by yaml.dump
                    logging.info(f"Configurations updated in {self.file_path}")
                except Exception as e:
                    logging.error(f"Could not write configurations to {self.file_path} file: {str(e)}")
                    raise e

            def to_dict(self) -> Dict[str, str]:
                """ Return the core attributes of the object as dict"""
                return {
                        "client_id": self.client_id,
                        "client_secret": self.client_secret,
                        "refresh_token": self.refresh_token, # refresh_token is included in the dictionary
                        "developer_token": self.developer_token,
                        "login_customer_id": self.login_customer_id,
                        "spreadsheet_url": self.spreadsheet_url
                }
        ```
        - The `Config.save_to_file()` method in `/code/utils/config.py` is responsible for saving the application's configuration to a file.
        - It calls `self.to_dict()` to get a dictionary of configuration parameters, which includes the `refresh_token`.
        - `yaml.dump(self.to_dict(), f)` then serializes this dictionary into YAML format and writes it to the file specified by `self.file_path`.
        - The `self.file_path` is determined by `_config_file_path_set()`, which, in a GCP environment, resolves to a path within a Google Cloud Storage bucket (`gs://{project_id}-keyword_factory/config.yaml`).
        - Therefore, the refresh token, in plain text, is written into the `config.yaml` file and stored in the GCS bucket.

    - File: `/code/setup.sh`
        ```bash
        CONFIG_PATH=$GCS_BUCKET/config.yaml

        deploy_files() {
          echo -e "${COLOR}Uploading files to GCS...${NC}"
          gsutil cp config.yaml.template $CONFIG_PATH # config.yaml is copied to GCS
          echo -e "${COLOR}Files were deployed to ${GCS_BUCKET}${NC}"
        }
        ```
        - The `setup.sh` script confirms that the `config.yaml` file, where the refresh token is stored, is indeed placed in the Google Cloud Storage bucket during deployment.

- Security Test Case:
    1. **Deploy Application:** Deploy the Keyword Factory application to a Google Cloud project by following the instructions in the `README.md` file, specifically using the "Run on Google Cloud" button.
    2. **Configure Credentials:** Access the deployed application URL in a web browser. Navigate to the "Authentication" tab. Enter valid Google Ads API OAuth credentials (Client ID, Client Secret, Refresh Token, Developer Token, MCC ID). Click "Save". This action will save the credentials, including the refresh token, to the `config.yaml` file in the GCS bucket.
    3. **Identify GCS Bucket:** Determine the name of the Google Cloud Storage bucket used by the application. This is typically in the format `[PROJECT_ID]-keyword_factory`. You can find your Project ID in the Google Cloud Console.
    4. **Access GCS Bucket (Simulate Attacker):** As an attacker with assumed compromised GCP access (or in a controlled test environment with appropriate permissions), use the `gsutil` command-line tool or the Google Cloud Console to access the identified GCS bucket. For example:
        ```bash
        gsutil ls gs://[PROJECT_ID]-keyword_factory/
        ```
    5. **Download `config.yaml`:** Download the `config.yaml` file from the GCS bucket to your local machine:
        ```bash
        gsutil cp gs://[PROJECT_ID]-keyword_factory/config.yaml ./
        ```
    6. **Inspect `config.yaml`:** Open the downloaded `config.yaml` file with a text editor.
    7. **Verify Plain Text Refresh Token:** Observe that the `refresh_token` value is present in the file and is stored in plain text, along with other credentials like `client_id`, `client_secret`, and `developer_token`.
    8. **Exploit (Optional):**  Using the extracted `refresh_token`, `client_id`, `client_secret`, and `developer_token`, you can now write a script or use a Google Ads API client library to authenticate and access the Google Ads account associated with the stolen refresh token, proving successful unauthorized access. For example, you could use the Python Google Ads API client library to instantiate a client using the stolen credentials and perform actions on the victim's Google Ads account.