## Vulnerability Report

### Insecure Storage of OAuth Refresh Token

- **Vulnerability Name:** Insecure Storage of OAuth Refresh Token
- **Description:**
    - The application stores sensitive OAuth refresh tokens in plain text within a YAML configuration file named `config.yaml`. This file is used to persist Google Ads API and Google Sheets API credentials.
    - During the initial setup or when users update their credentials via the web interface, the application saves these credentials, including the refresh token, into the `config.yaml` file.
    - This `config.yaml` file is then stored in a Google Cloud Storage bucket associated with the project, specifically under the path `gs://[PROJECT_ID]-keyword_factory/config.yaml`.
    - An attacker who gains unauthorized access to this Google Cloud Storage bucket can download the `config.yaml` file. Access could be gained through:
        - Misconfigured IAM policies on the GCS bucket, allowing overly permissive access.
        - Compromised GCP credentials (e.g., service account keys, administrator accounts) that have read access to the GCS bucket.
        - Phishing attacks leading users to enter credentials which are then stored in a similar insecure manner.
    - By reading the `config.yaml` file, the attacker can extract the plain text refresh token along with other OAuth credentials (client ID, client secret, developer token, MCC ID).
    - With these stolen credentials, the attacker can impersonate the legitimate user and gain unauthorized access to their Google Ads and Google Sheets accounts.
    - Once authenticated as the user, the attacker can manipulate the victim's advertising campaigns, access sensitive data in Google Ads and Google Sheets, potentially leading to financial loss, data breaches, or reputational damage for the victim.
- **Impact:**
    - **Critical:** If exploited, attackers can gain full unauthorized access to the victim's Google Ads and Google Sheets accounts.
    - **Unauthorized Access to Google Ads and Google Sheets Account:** An attacker can gain full control over the victim's Google Ads and Google Sheets accounts.
    - **Advertising Campaign Manipulation:** The attacker can modify or create advertising campaigns, potentially wasting the victim's advertising budget or redirecting traffic to malicious sites.
    - **Data Exfiltration:** The attacker might be able to access sensitive data within the Google Ads account, such as campaign performance data, customer lists (if uploaded), and billing information, as well as sensitive data stored in Google Sheets.
    - **Reputational Damage:** If malicious campaigns are run through the compromised account, or sensitive data is leaked, it can damage the victim's reputation.
    - **Financial Loss:** Unauthorized advertising spend and potential fines for policy violations can lead to financial losses for the victim.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    - None. The application currently stores refresh tokens in plain text without any encryption or secure storage mechanisms. The application relies on default GCS bucket privacy, which is insufficient.
- **Missing Mitigations:**
    - **Encryption at Rest:** The refresh token and other sensitive credentials should be encrypted before being stored in the `config.yaml` file or any storage medium.
    - **Secure Storage Mechanism:** Instead of storing refresh tokens in a simple YAML file in GCS, a more secure storage mechanism should be used, such as:
        - **Google Cloud KMS:** Encrypt the refresh token using Cloud KMS and store the encrypted token. The application can then decrypt it at runtime using its service account permissions.
        - **Secret Manager:** Store the refresh token in Google Cloud Secret Manager, which is designed for managing sensitive data like API keys and passwords. The application can retrieve the refresh token securely at runtime.
    - **Access Control to GCS Bucket:** Implement strict Identity and Access Management (IAM) policies on the Google Cloud Storage bucket to limit access only to authorized service accounts and administrators. Follow the principle of least privilege. Regularly review and audit bucket access logs.
    - **Protection against Phishing (Indirect Mitigation):** While not directly mitigating insecure storage, measures to enhance application authenticity and user awareness can reduce the likelihood of credentials being compromised through phishing and subsequently stored insecurely.
- **Preconditions:**
    1. The Keyword Factory application must be deployed on Google Cloud Platform (GCP).
    2. A user must have successfully configured their Google Ads API credentials through the application's web interface and saved them. This action triggers the storage of the refresh token in the `config.yaml` file within the GCS bucket.
    3. An attacker must gain unauthorized access to the Google Cloud Storage bucket associated with the deployed Keyword Factory project, or trick a user into providing credentials which are then insecurely stored. This could be due to:
        - Misconfigured IAM policies on the GCS bucket, allowing overly permissive access.
        - Compromised GCP credentials (e.g., service account keys, administrator accounts) that have read access to the GCS bucket.
        - Users being tricked into entering credentials into a fake application, leading to credential theft and potential insecure storage by the attacker.
- **Source Code Analysis:**
    - **File: `/code/utils/config.py`**
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

    - **File: `/code/setup.sh`**
        ```bash
        CONFIG_PATH=$GCS_BUCKET/config.yaml

        deploy_files() {
          echo -e "${COLOR}Uploading files to GCS...${NC}"
          gsutil cp config.yaml.template $CONFIG_PATH # config.yaml is copied to GCS
          echo -e "${COLOR}Files were deployed to ${GCS_BUCKET}${NC}"
        }
        ```
        - The `setup.sh` script confirms that the `config.yaml` file, where the refresh token is stored, is indeed placed in the Google Cloud Storage bucket during deployment.

- **Security Test Case:**
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
    8. **Exploit (Optional):**  Using the extracted `refresh_token`, `client_id`, `client_secret`, and `developer_token`, you can now write a script or use a Google Ads API client library to authenticate and access the Google Ads account associated with the stolen refresh token, proving successful unauthorized access.

### Cross-Site Scripting (XSS) in Spreadsheet URL Display

- **Vulnerability Name:** Cross-Site Scripting (XSS) in Spreadsheet URL Display
- **Description:**
    - An attacker could potentially manipulate the application to inject malicious JavaScript code into the generated Google Sheets URL.
    - When a user successfully generates keywords, the application displays a success message containing a link to the Google Sheets results page.
    - If the application fails to properly sanitize the `spreadsheet_url` before rendering it in the success message, a crafted URL containing malicious JavaScript could be inserted.
    - When a user clicks on the seemingly legitimate link, or if the link is automatically opened or rendered in a webview, the injected JavaScript code will be executed in the user's browser in the context of the application's origin.
    - This could allow the attacker to perform actions on behalf of the user, including stealing sensitive information such as OAuth2 credentials if they are accessible in the application's context.
- **Impact:**
    - **High:** Successful exploitation could lead to credential theft and unauthorized access to user accounts.
    - **OAuth2 Credential Theft:** If successful, the attacker can steal the user's OAuth2 credentials used to access Google Ads and Google Sheets.
    - **Unauthorized Access to Google Ads and Google Sheets:** With stolen credentials, the attacker can gain unauthorized access to the user's Google Ads and Google Sheets accounts.
    - **Data Breach:** Access to Google Ads and Google Sheets can expose sensitive advertising data, campaign performance data, and potentially other data stored in Google Sheets.
    - **Account Hijacking:** The attacker can take full control of the user's advertising campaigns.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - Based on the provided code, there is **no explicit sanitization** of the `config.spreadsheet_url` before rendering it in the success message in `app.py`. Streamlit's markdown rendering *might* provide some default protection, but it's not guaranteed.
- **Missing Mitigations:**
    - **Output Sanitization:** Implement proper output sanitization for the `spreadsheet_url` before rendering it. Use a library to escape HTML entities and JavaScript-sensitive characters in the URL.
    - **Content Security Policy (CSP):** Implement a strict Content Security Policy to limit the impact of XSS by controlling resource loading and script execution.
- **Preconditions:**
    - **Successful Keyword Generation:** The user must successfully complete keyword generation to reach the vulnerable success message.
    - **Attacker's Ability to Inject Malicious URL:** An attacker needs to find a way to inject a malicious URL into the `config.spreadsheet_url`. This is a significant precondition, potentially requiring compromising backend configuration or another vulnerability.
- **Source Code Analysis:**
    - **File: `/code/app.py`**
        ```python
        if st.session_state.generation_finished:
            st.success(f'Keyword generation completed successfully. [Open in Google Sheets]({config.spreadsheet_url})', icon="✅")
        ```
        - `config.spreadsheet_url` is directly embedded within a markdown link in the `st.success` message without sanitization.
- **Security Test Case:**
    1. **Precondition Setup:** Manually modify the `config.yaml` file to set `spreadsheet_url` to a malicious URL like `javascript:alert('XSS')` or a URL with HTML injection.
    2. **Steps:**
        a. Deploy the application and ensure the modified `config.yaml` is used.
        b. Access the application and configure credentials.
        c. Run keyword generation to reach the success message.
        d. Click the "Open in Google Sheets" link in the success message.
    3. **Expected Result:** If vulnerable, clicking the link will execute the injected JavaScript (e.g., display an alert box).
    4. **Note:**  Direct `javascript:` URLs might be blocked by browsers or Streamlit. More complex payloads or HTML injection might be necessary to fully demonstrate XSS depending on browser and framework handling.