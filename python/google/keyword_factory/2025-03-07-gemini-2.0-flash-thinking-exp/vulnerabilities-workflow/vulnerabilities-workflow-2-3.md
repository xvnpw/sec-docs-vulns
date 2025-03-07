### Vulnerability List

- Vulnerability Name: Insecure Storage of OAuth Refresh Token in GCS Bucket
- Description:
    - The OAuth refresh token, which grants persistent access to Google Ads and Google Sheets APIs, is stored in plain text within the `config.yaml` file.
    - This `config.yaml` file is uploaded to a Google Cloud Storage (GCS) bucket during the application setup process via the `setup.sh` script.
    - If the GCS bucket permissions are misconfigured or overly permissive, unauthorized users could potentially gain access to the `config.yaml` file.
    - By downloading the `config.yaml` file, attackers can extract the refresh token and impersonate the legitimate user.
    - Using the stolen refresh token, attackers can gain unauthorized access to the victim's Google Ads and Google Sheets accounts.
- Impact:
    - Critical. If exploited, attackers can gain unauthorized access to the victim's Google Ads and Google Sheets accounts. This allows them to:
        - Access and modify sensitive campaign data in Google Ads.
        - Steal confidential business information from Google Sheets.
        - Run malicious campaigns or manipulate existing ones, leading to financial loss or reputational damage for the user.
        - Access and potentially exfiltrate sensitive data stored in Google Sheets.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The application relies on the default privacy settings of Google Cloud Storage (GCS) buckets, which are private by default. However, this is not a sufficient mitigation as bucket permissions can be misconfigured by users or administrators. There is no explicit access control or encryption implemented in the application code for the refresh token or the configuration file.
- Missing Mitigations:
    - **Encryption of the refresh token:** The refresh token should be encrypted before being stored in the `config.yaml` file and in the GCS bucket. This would prevent attackers from using the token even if they gain access to the `config.yaml` file.
    - **Restrict GCS bucket access:** Implement more restrictive Identity and Access Management (IAM) policies on the GCS bucket to limit access to only authorized service accounts or users. This would reduce the attack surface by ensuring only the application itself and authorized administrators can access the configuration file.
    - **User guidance on secure GCS configuration:** Provide clear documentation and instructions to users on how to properly configure GCS bucket permissions to ensure the configuration file and refresh token are protected. This includes emphasizing the principle of least privilege when granting access.
- Preconditions:
    - The Keyword Factory application must be deployed on Google Cloud Platform (GCP) using the provided deployment button and setup scripts.
    - The GCS bucket created for storing the application's configuration (`config.yaml`) must have misconfigured or overly permissive access controls, allowing unauthorized access to the bucket contents. This could happen due to accidental misconfiguration or a lack of understanding of GCP IAM best practices.
- Source Code Analysis:
    1. **`utils/config.py`**: The `Config` class is responsible for loading and saving the application's configuration, including OAuth credentials.
        ```python
        class Config:
            def __init__(self, ok_if_not_exists = False) -> None:
                # ...
                self.refresh_token = config.get('refresh_token', '')
                # ...

            def save_to_file(self):
                try:
                    with smart_open.open(self.file_path, 'w') as f:
                        yaml.dump(self.to_dict(), f) # Saves config including refresh_token in plain text
                    logging.info(f"Configurations updated in {self.file_path}")
                except Exception as e:
                    logging.error(f"Could not write configurations to {self.file_path} file: {str(e)}")
                    raise e
        ```
        - The `refresh_token` attribute of the `Config` class stores the OAuth refresh token in plaintext.
        - The `save_to_file` method serializes the entire configuration, including the plaintext `refresh_token`, into a YAML file (`config.yaml`) using `yaml.dump`.
        - This `config.yaml` file is intended to be stored in a GCS bucket, as defined by `_CONFIG_PATH`.

    2. **`setup.sh`**: The `deploy_files()` function copies the `config.yaml.template` to the designated GCS bucket path.
        ```bash
        deploy_files() {
          echo -e "${COLOR}Uploading files to GCS...${NC}"
          gsutil cp config.yaml.template $CONFIG_PATH # Copies config.yaml.template to GCS
          echo -e "${COLOR}Files were deployed to ${GCS_BUCKET}${NC}"
        }
        ```
        - The `deploy_files` function uses `gsutil cp` to copy the `config.yaml.template` file to the GCS bucket path defined by `$CONFIG_PATH`.
        - Critically, this script and the application do not implement any mechanism to encrypt the `config.yaml` file or the refresh token before storing it in GCS.

- Security Test Case:
    1. **Deploy the application**: Use the "Run on Google Cloud" button in `README.md` to deploy the Keyword Factory application to a GCP project. Follow the installation instructions to set up the application.
    2. **Identify the GCS bucket**: After deployment, determine the name of the GCS bucket created for the project. The bucket name is typically in the format `gs://[PROJECT_ID]-keyword_factory`.
    3. **Simulate misconfigured permissions (Optional for testing, but reflects real risk)**: To simulate a misconfigured bucket for testing purposes, you can intentionally weaken the permissions of the GCS bucket.  In a real-world scenario, an attacker would look for buckets that are already misconfigured.
        ```bash
        # Warning: This command weakens security for testing purposes only.
        # In a real attack, the attacker would find already misconfigured buckets.
        gsutil iam ch allUsers:objectViewer gs://[YOUR_PROJECT_ID]-keyword_factory
        ```
    4. **Attempt to access the config file**: From a separate GCP account or a local machine (configured with different GCP credentials than the deployed application), use `gsutil` to attempt to download the `config.yaml` file from the GCS bucket.
        ```bash
        gsutil cp gs://[YOUR_PROJECT_ID]-keyword_factory/config.yaml local_config.yaml
        ```
    5. **Verify plaintext refresh token**: Open the downloaded `local_config.yaml` file using a text editor. Verify that the `refresh_token` is present in the file and stored in plaintext.
    6. **Attempt unauthorized API access**: Using a separate Python script or tool, use the extracted `refresh_token`, along with the `client_id`, `client_secret`, `developer_token`, and `login_customer_id` from the `local_config.yaml`, to create a Google Ads API client or Google Sheets API client.
        ```python
        from google.ads.googleads.client import GoogleAdsClient

        config = {
            "client_id": "[YOUR_CLIENT_ID]", # Replace with extracted values
            "client_secret": "[YOUR_CLIENT_SECRET]",
            "refresh_token": "[YOUR_REFRESH_TOKEN]",
            "developer_token": "[YOUR_DEVELOPER_TOKEN]",
            "login_customer_id": "[YOUR_LOGIN_CUSTOMER_ID]",
            "use_proto_plus": True,
        }

        ads_client = GoogleAdsClient.load_from_dict(config, version="v14")

        try:
            # Attempt a simple Google Ads API operation, e.g., listing accessible customers
            customer_service = ads_client.get_service("CustomerService")
            accessible_customers = customer_service.list_accessible_customers()
            print("Successfully accessed Google Ads API with stolen refresh token.")
            for customer_resource in accessible_customers.resource_names:
                print(customer_resource)

        except Exception as e:
            print(f"Failed to access Google Ads API: {e}")
        ```
    7. **Confirm successful unauthorized access**: If the script in step 6 successfully authenticates and performs Google Ads API operations (or similarly for Google Sheets API), it confirms that an attacker who obtains the `refresh_token` from the misconfigured GCS bucket can gain unauthorized access to the victim's Google Ads and Google Sheets accounts.