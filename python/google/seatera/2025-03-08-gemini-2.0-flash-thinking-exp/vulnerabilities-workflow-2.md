### High Severity Vulnerabilities

- **Vulnerability Name:** Inherent Phishing Susceptibility due to Credential Input Requirement
  - **Vulnerability Rank:** High
  - **Description:**
    1. An attacker sets up a malicious instance of SeaTera, mimicking the legitimate application.
    2. The attacker distributes phishing emails or links to advertisers, enticing them to use the malicious SeaTera instance.
    3. Unsuspecting advertisers, believing they are interacting with the legitimate tool, enter their Google Ads API credentials (Client ID, Client Secret, Refresh Token, Developer Token, MCC ID) into the malicious SeaTera instance through the "Authentication" tab in the UI.
    4. The malicious SeaTera instance captures these credentials.
    5. The attacker now has unauthorized access to the advertiser's Google Ads accounts and Google Sheets, using the stolen credentials.
  - **Impact:**
    - Complete compromise of the victim's Google Ads account and potentially associated Google Sheets data.
    - Attackers can manipulate ad campaigns, access sensitive advertising data, incur unauthorized ad spend, and potentially exfiltrate or modify data in connected Google Sheets.
    - Reputational damage to the victim's business and financial loss.
  - **Currently implemented mitigations:**
    - Disclaimer in README.md: "This is not an officially supported Google product." This provides a weak warning but doesn't actively prevent phishing.
    - OAuth 2.0 flow with refresh token: While OAuth 2.0 is used, the application design still necessitates users entering and storing sensitive credentials, making it vulnerable to phishing regardless of the OAuth implementation itself.
  - **Missing mitigations:**
    - Explicit and prominent warnings within the application UI about the phishing risks associated with entering credentials, especially on unofficial instances.
    - Guidance and best practices for users to verify the legitimacy of the SeaTera instance they are using (e.g., checking the URL, official deployment channels).
    - Consider alternative authentication methods that reduce the need for users to directly input and manage long-lived credentials, if feasible for the application's functionality. However, given the current project scope and API requirements, this might be a significant architectural change.
  - **Preconditions:**
    - An attacker needs to deploy a malicious instance of SeaTera.
    - Attackers need to successfully phish advertisers into using the malicious instance and entering their credentials.
    - Advertisers must have Google Ads API credentials and OAuth2 credentials, and be willing to input them into the SeaTera application.
  - **Source code analysis:**
    1. **frontend.py:** The `frontend.py` file contains the UI elements for credential input in the "Authentication" tab.
       ```python
       with st.expander("**Authentication**", expanded=not st.session_state.valid_config):
           if not st.session_state.valid_config:
               client_id = st.text_input("Client ID", value=value_placeholder(config.client_id))
               client_secret = st.text_input("Client Secret", value=value_placeholder(config.client_secret))
               refresh_token = st.text_input("Refresh Token", value=value_placeholder(config.refresh_token))
               developer_token = st.text_input("Developer Token", value=value_placeholder(config.developer_token))
               mcc_id = st.text_input("MCC ID", value=value_placeholder(config.login_customer_id))
               login_btn = st.button("Save", type='primary',on_click=authenticate, args=[{...}])
       ```
       This code block shows that the application directly prompts users for all necessary Google Ads API and OAuth2 credentials through text input fields in the UI.
    2. **frontend.py:** The `authenticate` function in `frontend.py` handles saving these credentials.
       ```python
       def authenticate(config_params):
           st.session_state.config.client_id = config_params['client_id']
           st.session_state.config.client_secret = config_params['client_secret']
           st.session_state.config.refresh_token = config_params['refresh_token']
           st.session_state.config.developer_token = config_params['developer_token']
           st.session_state.config.login_customer_id = config_params['login_customer_id']

           st.session_state.config.check_valid_config()
           st.session_state.valid_config = True
           st.session_state.config.save_to_file()
       ```
       The `authenticate` function takes the credential parameters and saves them to the `Config` object and then persists them to the `config.yaml` file using `st.session_state.config.save_to_file()`.
    3. **utils/config.py:** The `Config.save_to_file()` function in `utils/config.py` saves the credentials to the `config.yaml` file in Google Cloud Storage.
       ```python
       def save_to_file(self):
           try:
               config = deepcopy(self.to_dict())
               blob = self.bucket.blob(CONFIG_FILE_NAME)
               with blob.open('w') as f:
                   yaml.dump(config, f)
               print(f"Configurations updated in {self.file_path}")
           except Exception as e:
               print(f"Could not write configurations to {self.file_path} file")
               print(e)
       ```
       This function demonstrates how the user-provided credentials, entered in the frontend, are ultimately stored. This mechanism, while functional, makes the application inherently susceptible to phishing attacks because users are required to input and the application stores these sensitive credentials.
  - **Security test case:**
    1. Deploy a malicious instance of SeaTera on a publicly accessible platform (e.g., using the "Run on Google Cloud" button but under attacker's GCP project).
    2. Create a phishing email that mimics a legitimate communication about SeaTera, enticing advertisers to use the tool. The email should contain a link to the attacker's malicious SeaTera instance URL.
    3. Send the phishing email to target advertisers.
    4. If a target advertiser clicks the link and accesses the malicious SeaTera instance, instruct them (within the test scenario) to enter valid, but *test* Google Ads API credentials into the "Authentication" tab and click "Save".
    5. After the advertiser enters the credentials, the attacker (as the operator of the malicious instance) should be able to access the `config.yaml` file in their GCP storage bucket associated with the malicious SeaTera instance.
    6. Verify that the `config.yaml` file contains the *test* credentials that the advertiser entered.
    7. Using these stolen *test* credentials, attempt to access the advertiser's *test* Google Ads account via the Google Ads API or Google Sheets API to confirm successful credential theft and unauthorized access.

- **Vulnerability Name:** Credentials Exposure via Cloud Storage Misconfiguration
  - **Vulnerability Rank:** High
  - **Description:**
    1. The application stores OAuth 2.0 client ID, client secret, developer token, login customer ID, and refresh token in a `config.yaml` file.
    2. During deployment, the `setup/prebuild.sh` script uploads this `config.yaml` file to a Google Cloud Storage bucket.
    3. If the Google Cloud Storage bucket permissions are misconfigured (e.g., set to public read access), an attacker could potentially access and download the `config.yaml` file.
    4. By obtaining the `config.yaml` file, the attacker gains access to sensitive credentials, including the OAuth 2.0 refresh token.
    5. With the refresh token, the attacker can impersonate the legitimate user and gain unauthorized access to their Google Ads and Google Sheets data through the Google Ads and Google Sheets APIs.
  - **Impact:**
    - High. An attacker gaining access to the credentials can completely compromise the user's Google Ads and Google Sheets accounts linked to SeaTerA. This allows the attacker to:
        - Access and exfiltrate sensitive advertising data and Google Sheets data.
        - Modify Google Ads campaigns, potentially leading to financial loss or reputational damage for the advertiser.
        - Modify Google Sheets data, potentially corrupting important business information.
  - **Currently implemented mitigations:**
    - The application relies on Google Cloud Storage's default bucket permissions.
    - The `setup/prebuild.sh` script creates a bucket but does not explicitly set any restrictive permissions beyond default.
  - **Missing mitigations:**
    - **Principle of Least Privilege for Cloud Storage Bucket:** Implement strict access control on the Cloud Storage bucket to ensure only the SeaTerA application and authorized GCP services have access. This should include:
        - Using IAM roles to grant minimal necessary permissions.
        - Avoiding public read or write access to the bucket.
        - Regularly reviewing and auditing bucket permissions.
    - **Secure Credential Management:** Consider using more secure credential management practices instead of storing sensitive information in a static YAML file in Cloud Storage. Options include:
        - Google Cloud Secret Manager: Store credentials securely in Secret Manager and retrieve them programmatically during application runtime.
        - Environment Variables (for sensitive data that can be managed this way in GCP Run): Pass sensitive credentials as environment variables to the Cloud Run service instead of storing them in a file.
  - **Preconditions:**
    - The Google Cloud Storage bucket created by `setup/prebuild.sh` must have misconfigured permissions allowing unauthorized read access.
    - The attacker needs to know or guess the bucket name, which is somewhat predictable (`<GOOGLE_CLOUD_PROJECT>-seatera`).
  - **Source code analysis:**
    1. **`setup/prebuild.sh`**:
       ```sh
       echo "Creating cloud storage bucket..."
       gcloud alpha storage buckets create gs://${GOOGLE_CLOUD_PROJECT}-seatera --project=${GOOGLE_CLOUD_PROJECT}

       echo "Uploading config.yaml to cloud storage..."
       gcloud alpha storage cp ./config.yaml gs://${GOOGLE_CLOUD_PROJECT}-seatera
       ```
       - This script creates a Cloud Storage bucket named `${GOOGLE_CLOUD_PROJECT}-seatera` and uploads `config.yaml` to it.
       - It uses `gcloud alpha storage buckets create` which by default creates buckets with project-private access. However, there is no explicit permission setting to enforce this or prevent accidental misconfiguration later.

    2. **`utils/config.py`**:
       ```python
       BUCKET_NAME = os.getenv('bucket_name')
       CONFIG_FILE_NAME = 'config.yaml'
       CONFIG_FILE_PATH = BUCKET_NAME +  '/' + CONFIG_FILE_NAME

       class Config:
           def __init__(self) -> None:
               self.file_path = CONFIG_FILE_PATH
               self.storage_client = storage.Client()
               self.bucket = self.storage_client.bucket(BUCKET_NAME)
               config = self.load_config_from_file()
               ...
           def load_config_from_file(self):
               try:
                   blob = self.bucket.blob(CONFIG_FILE_NAME)
                   with blob.open() as f:
                       config = yaml.load(f, Loader=SafeLoader)
               except Exception as e:
                   print(str(e))
                   return None
               return config
       ```
       - The `Config` class in `utils/config.py` is responsible for loading the configuration from the `config.yaml` file stored in the Cloud Storage bucket.
       - It retrieves the bucket name from the `bucket_name` environment variable, which is set in `setup/postcreate.sh`.
       - The `load_config_from_file` method directly accesses the Cloud Storage bucket and reads the `config.yaml` file. If the bucket is publicly accessible, this file can be downloaded by anyone.

       ```
       [Attacker] --> Internet --> [Publicly Accessible GCS Bucket] --> Download config.yaml (credentials)
       ```

  - **Security test case:**
    1. **Precondition**:  Assume a deployed instance of SeaTerA on Google Cloud Run, and the attacker knows the GCP project ID (can be often inferred or found). Intentionally misconfigure the GCS bucket permissions to be publicly readable. This is to simulate a real-world misconfiguration. In a real test, you would attempt to access without changing permissions first to check default setup.
    2. **Identify the bucket name**: Construct the bucket name using the GCP project ID: `<GOOGLE_CLOUD_PROJECT>-seatera`.
    3. **Attempt to access the bucket**: Use `gsutil ls gs://<GOOGLE_CLOUD_PROJECT>-seatera` command or browse to `https://storage.googleapis.com/<GOOGLE_CLOUD_PROJECT>-seatera` in a web browser (if directory listing is enabled, which is often not by default but bucket might be readable if ACLs are wrong).
    4. **Attempt to download `config.yaml`**: If bucket access is confirmed, try to download the `config.yaml` file using `gsutil cp gs://<GOOGLE_CLOUD_PROJECT>-seatera/config.yaml ./config.yaml`. Or access via browser: `https://storage.googleapis.com/<GOOGLE_CLOUD_PROJECT>-seatera/config.yaml`.
    5. **Analyze `config.yaml`**: If the download is successful, examine the `config.yaml` file. It should contain sensitive credentials like `client_id`, `client_secret`, `refresh_token`, `developer_token`, and `login_customer_id`.
    6. **Exploit refresh token**: Use the obtained `refresh_token`, `client_id`, `client_secret`, `developer_token`, and `login_customer_id` to create a Google Ads API client or Google Sheets API client outside of the SeaTerA application.
    7. **Verify unauthorized access**: Successfully access Google Ads or Google Sheets API using the stolen credentials, proving unauthorized access to the victim's data. For example, use a simple Python script with `google-ads` or `google-api-python-client` to fetch data from Google Ads or Google Sheets using the stolen credentials.