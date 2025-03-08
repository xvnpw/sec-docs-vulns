- Vulnerability Name: Credentials Exposure via Cloud Storage Misconfiguration
- Description:
    1. The application stores OAuth 2.0 client ID, client secret, developer token, login customer ID, and refresh token in a `config.yaml` file.
    2. During deployment, the `setup/prebuild.sh` script uploads this `config.yaml` file to a Google Cloud Storage bucket.
    3. If the Google Cloud Storage bucket permissions are misconfigured (e.g., set to public read access), an attacker could potentially access and download the `config.yaml` file.
    4. By obtaining the `config.yaml` file, the attacker gains access to sensitive credentials, including the OAuth 2.0 refresh token.
    5. With the refresh token, the attacker can impersonate the legitimate user and gain unauthorized access to their Google Ads and Google Sheets data through the Google Ads and Google Sheets APIs.
- Impact:
    - High. An attacker gaining access to the credentials can completely compromise the user's Google Ads and Google Sheets accounts linked to SeaTerA. This allows the attacker to:
        - Access and exfiltrate sensitive advertising data and Google Sheets data.
        - Modify Google Ads campaigns, potentially leading to financial loss or reputational damage for the advertiser.
        - Modify Google Sheets data, potentially corrupting important business information.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - The application relies on Google Cloud Storage's default bucket permissions.
    - The `setup/prebuild.sh` script creates a bucket but does not explicitly set any restrictive permissions beyond default.
- Missing Mitigations:
    - **Principle of Least Privilege for Cloud Storage Bucket:** Implement strict access control on the Cloud Storage bucket to ensure only the SeaTerA application and authorized GCP services have access. This should include:
        - Using IAM roles to grant minimal necessary permissions.
        - Avoiding public read or write access to the bucket.
        - Regularly reviewing and auditing bucket permissions.
    - **Secure Credential Management:** Consider using more secure credential management practices instead of storing sensitive information in a static YAML file in Cloud Storage. Options include:
        - Google Cloud Secret Manager: Store credentials securely in Secret Manager and retrieve them programmatically during application runtime.
        - Environment Variables (for sensitive data that can be managed this way in GCP Run): Pass sensitive credentials as environment variables to the Cloud Run service instead of storing them in a file.
- Preconditions:
    - The Google Cloud Storage bucket created by `setup/prebuild.sh` must have misconfigured permissions allowing unauthorized read access.
    - The attacker needs to know or guess the bucket name, which is somewhat predictable (`<GOOGLE_CLOUD_PROJECT>-seatera`).
- Source Code Analysis:
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

    **Visualization:**

    ```
    [Attacker] --> Internet --> [Publicly Accessible GCS Bucket] --> Download config.yaml (credentials)
    ```

- Security Test Case:
    1. **Precondition**:  Assume a deployed instance of SeaTerA on Google Cloud Run, and the attacker knows the GCP project ID (can be often inferred or found). Intentionally misconfigure the GCS bucket permissions to be publicly readable. This is to simulate a real-world misconfiguration. In a real test, you would attempt to access without changing permissions first to check default setup.
    2. **Identify the bucket name**: Construct the bucket name using the GCP project ID: `<GOOGLE_CLOUD_PROJECT>-seatera`.
    3. **Attempt to access the bucket**: Use `gsutil ls gs://<GOOGLE_CLOUD_PROJECT>-seatera` command or browse to `https://storage.googleapis.com/<GOOGLE_CLOUD_PROJECT>-seatera` in a web browser (if directory listing is enabled, which is often not by default but bucket might be readable if ACLs are wrong).
    4. **Attempt to download `config.yaml`**: If bucket access is confirmed, try to download the `config.yaml` file using `gsutil cp gs://<GOOGLE_CLOUD_PROJECT>-seatera/config.yaml ./config.yaml`. Or access via browser: `https://storage.googleapis.com/<GOOGLE_CLOUD_PROJECT>-seatera/config.yaml`.
    5. **Analyze `config.yaml`**: If the download is successful, examine the `config.yaml` file. It should contain sensitive credentials like `client_id`, `client_secret`, `refresh_token`, `developer_token`, and `login_customer_id`.
    6. **Exploit refresh token**: Use the obtained `refresh_token`, `client_id`, `client_secret`, `developer_token`, and `login_customer_id` to create a Google Ads API client or Google Sheets API client outside of the SeaTerA application.
    7. **Verify unauthorized access**: Successfully access Google Ads or Google Sheets API using the stolen credentials, proving unauthorized access to the victim's data. For example, use a simple Python script with `google-ads` or `google-api-python-client` to fetch data from Google Ads or Google Sheets using the stolen credentials.