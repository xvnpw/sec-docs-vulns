- Vulnerability Name: Insecure Storage of Service Account Credentials
- Description:
    1. The project setup instructions guide users to download a service account JSON key file.
    2. Users are then instructed to place this sensitive JSON key file directly into the project code directory, specifically `/code/`.
    3. The `config.json` file is configured to point to this location for service account authentication.
    4. If an attacker gains access to the project code directory, for example through misconfiguration of the Cloud Run service, a publicly exposed repository, or by compromising the Cloud Shell environment, they can easily locate and retrieve the service account JSON key file.
    5. With the service account JSON key file, the attacker can impersonate the service account.
    6. Using the impersonated service account, the attacker can gain unauthorized access to Google Cloud resources that the service account is authorized to access, including Google Merchant Center data, BigQuery datasets, and Google Sheets.
- Impact:
    - Critical. Successful exploitation of this vulnerability allows an attacker to gain unauthorized access to sensitive Google Cloud resources.
    - The attacker can access and exfiltrate Google Merchant Center product data, potentially including confidential business information.
    - The attacker could modify or delete Merchant Center data, disrupting operations and potentially causing financial loss.
    - The attacker can access and manipulate the generated Google Studio feeds, leading to misinformation or malicious advertising campaigns.
    - Depending on the specific permissions granted to the service account, the attacker might be able to pivot and gain access to other Google Cloud resources within the project.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None. The project's setup instructions explicitly encourage insecure storage of the service account key file within the project directory.
- Missing Mitigations:
    - Secure Key Storage: Implement secure storage for the service account key, such as using Google Cloud Secret Manager. Alternatively, the key file should be stored outside the application's code directory on the instance and accessed through secure environment variables or configuration mechanisms.
    - Principle of Least Privilege:  Configure the service account with the minimum necessary permissions required for the application to function. Avoid granting overly broad roles that could increase the impact of key compromise.
    - Secure Configuration Practices Documentation: Update the project documentation to strongly discourage storing the service account key file in the project directory. Provide clear guidance and best practices for secure key management, including using Secret Manager or alternative secure storage solutions.
- Preconditions:
    - The user must follow the project setup instructions and create a service account JSON key.
    - The user must place the downloaded service account JSON key file in the `/code/` directory as instructed in the setup documentation.
    - The Cloud Run service or the project's code repository must be accessible to an attacker. This could occur due to misconfigurations, accidental public exposure, or a compromise of the Cloud Shell environment.
- Source Code Analysis:
    1. **/code/README.md & /code/CONTRIBUTING.md:** These files contain the setup instructions. Step 14 of the "Set up" section clearly states: "Download the Service Account authentication JSON and configure the project to use it... Download the JSON file with the keys... Upload the JSON to the directory where Cartesian project was downloaded... Update the config.json adding the name of the JSON file in the “service_account_credentials” variable." This instruction directly leads users to store the sensitive key file in an insecure location.
    2. **/code/config.json:** This file is used to store project configuration parameters. The `service_account_credentials_path` parameter within this file is intended to store the path to the service account JSON key file. As per the setup instructions, this path will point to the key file located in the `/code/` directory.
    3. **/code/service_account_authenticator.py:** This Python script is responsible for authenticating the service account.
        ```python
        params = Utilities.load_config('config.json')
        json_name=str(params["service_account_credentials_path"])

        class Service_Account_Authenticator:

          def __init__(self,scope:list):

            self.credentials_json=json_name # Vulnerable: Reads key path from config
            self.scope=scope
            self.service_account_credentials=self.authenticate()

          def authenticate(self):
            credentials = ServiceAccountCredentials.from_json_keyfile_name(self.credentials_json, self.scope) # Vulnerable: Loads key from insecure path
            return credentials
        ```
        The `Service_Account_Authenticator` class in `service_account_authenticator.py` reads the `service_account_credentials_path` from the `config.json` file (loaded via `Utilities.load_config`). It then uses this path (`self.credentials_json`) in the `authenticate` method to load the service account credentials using `ServiceAccountCredentials.from_json_keyfile_name`. This directly utilizes the insecurely stored key file.
    4. **/code/utilities.py:** This script provides utility functions, including `load_config`.
        ```python
        class Utilities:

          def load_config(config_file_name):
            """Loads the configuration data from the given path.
            ...
            """
            config_file_path = './' + config_file_name # Path is relative to the code directory
            with open(config_file_path, 'r') as config_file: # Opens config.json from the code directory
              return json.load(config_file)
        ```
        The `load_config` function in `utilities.py` constructs the path to `config.json` relative to the current directory (`'./' + config_file_name`). This means it expects `config.json` (and consequently, the service account key file) to be located within the same directory as the application code.
    5. **/code/main.py:** The main application script utilizes the `Utilities` and `Service_Account_Authenticator` classes, indirectly leading to the insecure loading and use of the service account key.
        ```python
        params = Utilities.load_config('config.json') # Loads config, including key path
        ...
        from service_account_authenticator import Service_Account_Authenticator
        ...
        bq = BigqueryHelper( # BigqueryHelper will use Service_Account_Authenticator
            gcp_project_id=str(params["gcp_project_id"]),
            dataset_name=str(params["bigquery_dataset"]),
            bucket_name=str(params["bucket_name"]),
            table_name_prefix=str(params["table_name_prefix"])
        )
        ```
        `main.py` loads the configuration using `Utilities.load_config` and then instantiates `BigqueryHelper`, which internally uses `Service_Account_Authenticator` for authentication, thus completing the chain of insecure key usage.

- Security Test Case:
    1. Deploy Project Cartesian to Google Cloud Run following the setup instructions in `README.md`. Ensure you download the service account JSON key file and place it in the `/code/` directory, updating `config.json` with the correct filename as instructed.
    2. Once deployed, access the Cloud Run service. For the purpose of this test, you can use `kubectl` in Cloud Shell to gain shell access to the running container instance.
        ```bash
        export GCP_PROJECT=$(gcloud config get-value project)
        export GCP_REGION=$(gcloud config get-value region)
        export CLOUD_RUN_SERVICE_NAME=$(gcloud run services describe projectcartesian --platform managed --region $GCP_REGION --format 'value(name)') # Replace 'projectcartesian' if you used a different service name

        # Get the pod name
        export POD_NAME=$(kubectl get pods -n cloud-run-system -l run.googleapis.com/service=$CLOUD_RUN_SERVICE_NAME -o jsonpath='{.items[0].metadata.name}')

        # Get shell access to the container
        kubectl exec -it $POD_NAME -n cloud-run-system -c user-container -- /bin/bash
        ```
        *(Note: In a real attack scenario, an attacker would need to find an alternative method to gain shell access if direct `kubectl` access is not available. This step is for demonstration and testing purposes.)*
    3. Inside the container shell, navigate to the application directory:
        ```bash
        cd /app
        ```
    4. List the files in the current directory:
        ```bash
        ls -l
        ```
        You should see the service account JSON key file listed here (the filename will be what you configured in `config.json` for `service_account_credentials_path`).
    5. Read the contents of the service account JSON key file using `cat`:
        ```bash
        cat <YOUR_SERVICE_ACCOUNT_JSON_FILE_NAME>.json
        ```
        Replace `<YOUR_SERVICE_ACCOUNT_JSON_FILE_NAME>.json` with the actual filename. You will see the contents of the JSON key file, including the private key and other sensitive information.
    6. Copy the entire JSON key content. Exit the Cloud Run container shell.
    7. On your local machine or in a separate Cloud Shell session (outside the Cloud Run container), set the `GOOGLE_APPLICATION_CREDENTIALS` environment variable to the copied JSON key content. For example, in a Linux/macOS environment:
        ```bash
        export GOOGLE_APPLICATION_CREDENTIALS_JSON='<PASTE_THE_COPIED_JSON_KEY_CONTENT_HERE>'
        ```
    8. Use `gcloud` or a Google Cloud client library to attempt to access resources that the service account should have access to. For example, try listing BigQuery datasets in the project:
        ```bash
        gcloud bq datasets list --project=$GCP_PROJECT
        ```
        If successful, this command will list the BigQuery datasets, proving that you have successfully authenticated as the service account using the compromised key and gained unauthorized access.

This test case demonstrates that storing the service account key file in the project directory allows an attacker with access to the Cloud Run instance to easily retrieve the key and gain unauthorized access to Google Cloud resources.