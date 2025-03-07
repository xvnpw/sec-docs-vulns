### Vulnerability List

- Vulnerability Name: Insecure Storage and Exposure of GCP Service Account Key

- Description:
    1. The `installer.py` script downloads a GCP service account key (`key.json`) and stores it within the `backend` directory of the application code.
    2. The `app.yaml` configuration file for Google App Engine deployment is set to include this `key.json` file in the deployed application package by referencing it via the `DQM_SERVICE_ACCOUNT_FILE_PATH` environment variable.
    3. During deployment to Google App Engine, the `key.json` file is uploaded along with the application code.
    4. Once deployed, the application code, specifically in `backend/helpers/analytics.py`, uses this `key.json` file to authenticate with Google Cloud services.
    5. An attacker who gains unauthorized access to the deployed App Engine instance or the source code repository can potentially retrieve the `key.json` file.
    6. With the `key.json` file, the attacker can impersonate the service account and gain unauthorized access to the associated GCP project and its resources, as the service account likely has broad permissions to access GCP services like Cloud SQL and Google Analytics.

- Impact:
    - **Critical:** Unauthorized access to the GCP project.
    - Full control over GCP resources within the project, including databases (Cloud SQL), Google Analytics data, and potentially other GCP services depending on the permissions granted to the service account.
    - Data exfiltration, modification, or deletion within the GCP project.
    - Potential for further lateral movement within the GCP infrastructure if the service account has broader permissions.
    - Financial impact due to unauthorized usage of GCP resources.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - **None:** The provided code and documentation do not include any mitigations for securely managing or storing the service account key. The `key.json` file is explicitly downloaded and deployed with the application. The documentation only recommends enabling GCP Identity-Aware Proxy (IAP) for access restriction, which is not a mitigation for key exposure but rather an access control mechanism for the application itself.

- Missing Mitigations:
    - **Secure Key Management System:** Implement a secure key management system like Google Cloud KMS (Key Management Service) or HashiCorp Vault to store and manage the service account key instead of directly including it in the application code.
    - **Workload Identity Federation:** Utilize Workload Identity Federation to allow the application running on App Engine to authenticate as a service account without needing to store and manage a key file. This eliminates the need for `key.json` altogether.
    - **Principle of Least Privilege:** Review and restrict the permissions granted to the service account to the minimum necessary for the application to function. This limits the potential impact if the key is compromised.
    - **Secret Manager:** Consider using Google Cloud Secret Manager to store the service account key as a secret and retrieve it at runtime. This is more secure than including it directly in the deployment package, although Workload Identity Federation is generally a more modern and secure approach for this scenario on GCP.

- Preconditions:
    - The application must be deployed to Google App Engine using the provided installation instructions, which involve downloading and deploying the `key.json` file.
    - An attacker must gain unauthorized access to the deployed App Engine instance or the source code repository.

- Source Code Analysis:
    1. **`installer.py`**:
        ```python
        def create_sa_keys() -> None:
          if input(color_text('Next step -> Download service account key file ([Y]es/[s]kip) ')).lower() != 's':
            subprocess.check_output(['gcloud', 'iam', 'service-accounts', 'keys', 'create', './key.json', '--iam-account', f'{project_id}@appspot.gserviceaccount.com'], cwd='dqm/backend')
        ```
        - This function downloads the service account key as `key.json` and places it in the `backend` directory.

    2. **`backend/app.yaml`**:
        ```yaml
        env_variables:
          #...
          DQM_SERVICE_ACCOUNT_FILE_PATH: "key.json"
        ```
        - This configuration sets the environment variable `DQM_SERVICE_ACCOUNT_FILE_PATH` to `key.json`, indicating the path to the service account key file within the deployed application.

    3. **`backend/project/settings/base.py`**:
        ```python
        SERVICE_ACCOUNT_FILE = os.getenv('DQM_SERVICE_ACCOUNT_FILE_PATH', 'key.json')
        ```
        - This line reads the `DQM_SERVICE_ACCOUNT_FILE_PATH` environment variable and sets the `SERVICE_ACCOUNT_FILE` setting, which is used to locate the key file.

    4. **`backend/dqm/helpers/analytics.py`**:
        ```python
        def get_service(api: str, version: str) -> None:
          """Build a service to access GA API.
          ...
          """
          credentials = ServiceAccountCredentials.from_json_keyfile_name(
            settings.SERVICE_ACCOUNT_FILE, SCOPES)
          return build(api, version, credentials=credentials)
        ```
        - This code snippet shows that the application uses `settings.SERVICE_ACCOUNT_FILE` to load the service account credentials using `ServiceAccountCredentials.from_json_keyfile_name()`. This function expects a path to the `key.json` file, which is now part of the deployed application.

    **Visualization:**

    ```
    installer.py --> downloads key.json --> backend/
    backend/app.yaml --> includes key.json in deployment package
    Deployment to App Engine --> key.json deployed with application
    backend/project/settings/base.py --> reads DQM_SERVICE_ACCOUNT_FILE_PATH env var --> SERVICE_ACCOUNT_FILE setting
    backend/dqm/helpers/analytics.py --> uses settings.SERVICE_ACCOUNT_FILE --> loads key.json for authentication
    Attacker access App Engine instance/repo --> potential key.json retrieval --> GCP access
    ```

- Security Test Case:
    1. Deploy the DQM application to Google App Engine following the provided installation instructions, ensuring that the `key.json` file is included in the `backend` directory before deployment.
    2. After successful deployment, access the deployed application URL in a web browser.
    3. Attempt to access the App Engine instance's file system. **Note:** Direct file system access to a running App Engine instance from outside is typically restricted. However, if there's a vulnerability allowing code execution or file retrieval within the application (which is not evident in the provided code but is a potential attack vector in web applications in general), an attacker might be able to access the file system.
    4. **Alternative Test (Simulating Internal Access or Repository Access):** Assume an attacker has gained access to the application's deployment package (e.g., through a compromised internal system or by gaining access to the source code repository where the deployment package might be stored or built).
    5. Within the deployment package or the deployed application directory (if accessible), locate the `backend` directory.
    6. Verify the presence of the `key.json` file within the `backend` directory.
    7. Download or copy the `key.json` file.
    8. Using the Google Cloud SDK (gcloud CLI) configured with the attacker's credentials, attempt to authenticate as the service account using the downloaded `key.json` file:
       ```bash
       gcloud auth activate-service-account --key-file=path/to/key.json
       ```
    9. After successful authentication, attempt to access GCP resources within the project associated with the service account. For example, try to list Cloud SQL instances:
       ```bash
       gcloud sql instances list --project=[YOUR_GCP_PROJECT_ID]
       ```
    10. If the attacker can successfully list Cloud SQL instances or access other GCP resources, it confirms that the exposed `key.json` file allows unauthorized access to the GCP project.

This test case demonstrates that if the `key.json` file is retrievable (either through direct access to the deployed instance or access to the deployment package or repository), it can be used to gain unauthorized access to the GCP project.