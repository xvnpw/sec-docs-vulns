### 1. Vulnerability Name: Cloud Function Service Account Over-Permissive IAM Roles

- Description:
    1. The `install.sh` script automatically creates a service account (`report2bq@<PROJECT>.iam.gserviceaccount.com`) for Cloud Functions and grants it the `roles/editor` role (`${DRY_RUN} gcloud projects add-iam-policy-binding ${PROJECT} --member=serviceAccount:${USER} --role=roles/editor`).
    2. The `roles/editor` role is a highly permissive IAM role that grants broad access to Google Cloud resources within the project.
    3. If an attacker were to compromise the Cloud Functions (e.g., through a hypothetical vulnerability in the Cloud Functions runtime or by exploiting a misconfiguration), they would inherit the permissions of this service account.
    4. This overly broad `roles/editor` permission would allow the attacker to access and modify almost any resource within the Google Cloud project, going far beyond the intended scope of accessing advertising reports in BigQuery.

- Impact:
    - **Critical**. Full project compromise. An attacker could gain complete control over the Google Cloud project, including:
        - Accessing and exfiltrating sensitive data from any Google Cloud service within the project (e.g., databases, storage buckets, other applications).
        - Modifying or deleting critical infrastructure and data.
        - Using project resources for malicious purposes (e.g., crypto mining, launching further attacks).
        - Impersonating other service accounts or users within the project.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - None. The `install.sh` script explicitly grants the overly permissive `roles/editor` role.

- Missing Mitigations:
    - **Principle of Least Privilege**: Replace the `roles/editor` role with a custom IAM role that grants only the necessary permissions for the Cloud Functions to operate. This custom role should be restricted to:
        - Writing data to the designated BigQuery dataset.
        - Reading secrets from Secret Manager (for API keys and OAuth credentials).
        - Publishing messages to Pub/Sub topics.
        - Potentially logging and monitoring permissions.
    - **Regular Security Audits**: Implement regular reviews of IAM roles and permissions to identify and rectify any instances of over-permissioning.

- Preconditions:
    - Successful deployment of Report2BQ using the `install.sh` script with the `--create-service-account` option, or manual creation of the service account with `roles/editor` role.
    - Hypothetical compromise of the Cloud Functions runtime environment or exploitation of a misconfiguration leading to service account key exposure.

- Source Code Analysis:
    - File: `/code/application/install.sh`
    ```bash
    if [ ${CREATE_SERVICE_ACCOUNT} -eq 1 ]; then
      USER=report2bq@${PROJECT}.iam.gserviceaccount.com
      ${DRY_RUN} gcloud --project ${PROJECT} iam service-accounts create report2bq --description "Report2BQ Service Account" \
      && ${DRY_RUN} gcloud --project ${PROJECT} iam service-accounts keys create "report2bq@${PROJECT}.iam.gserviceaccount.com.json" --iam-account ${USER}
      ${DRY_RUN} gcloud projects add-iam-policy-binding ${PROJECT} --member=serviceAccount:${USER} --role=roles/editor
    fi
    ```
    - The code snippet clearly shows the assignment of `roles/editor` to the service account.
    - Visualization:
        ```
        install.sh --> gcloud iam service-accounts create report2bq
                   --> gcloud iam service-accounts keys create
                   --> gcloud projects add-iam-policy-binding --role=roles/editor
        ```

- Security Test Case:
    1. Deploy Report2BQ using `install.sh --project=<YOUR_PROJECT_ID> --dataset=<DATASET_NAME> --api-key=<API_KEY> --create-service-account --activate-apis --deploy-all`.
    2. Identify the service account email address created by the script (report2bq@<YOUR_PROJECT_ID>.iam.gserviceaccount.com).
    3. In the Google Cloud Console, navigate to "IAM & Admin" > "IAM".
    4. Search for the service account email address.
    5. Observe that the service account has the "Editor" role assigned at the project level.
    6. **Simulate Cloud Function Compromise (for testing purposes only in a controlled environment):**
        -  Assume you have gained access to the Cloud Function's execution environment (this step is for demonstration and is not intended to be a real exploit).
        -  Within the Cloud Function environment, use the service account credentials to attempt to access other Google Cloud resources in the project, such as:
            - List storage buckets: `gsutil ls gs://`
            - List BigQuery datasets: `bq ls`
            - Read secrets from Secret Manager: `gcloud secrets versions access latest --secret=<SOME_SECRET>`
        -  If successful, this demonstrates that the `roles/editor` role grants excessive permissions, allowing an attacker to move laterally within the Google Cloud project and access resources far beyond the intended scope of Report2BQ.

---
### 2. Vulnerability Name: API Key Exposure in Client-Side Code (App Engine)

- Description:
    1. The `auth-appengine/app.yaml` configuration file is designed to store the API Key directly within the environment variables of the App Engine application:
        ```yaml
        env_variables:
          # Insert an API key with access to the Cloud Scheduler API here
          API_KEY: ""
        ```
    2. While App Engine environment variables are not directly exposed to the public internet, they are accessible to anyone who can access the App Engine instance's runtime environment.
    3. If an attacker were to gain unauthorized access to the App Engine instance (e.g., through a vulnerability in the App Engine runtime or a misconfiguration), they could potentially retrieve the API Key from the environment variables.
    4. This API Key, intended for securing Cloud Scheduler API access, could then be misused to perform unauthorized actions against the Cloud Scheduler API, potentially disrupting or manipulating scheduled jobs.

- Impact:
    - **Medium to High**.  Unauthorized access and potential manipulation of Cloud Scheduler jobs. An attacker could:
        - List, modify, delete, or create Cloud Scheduler jobs associated with the Report2BQ project.
        - Disrupt report fetching and loading processes by disabling or deleting jobs.
        - Potentially create malicious jobs to further compromise the system or resources.
        - While less severe than full project compromise, it could still lead to significant disruption and data integrity issues.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None. The `app.yaml` file explicitly encourages storing the API Key as an environment variable.

- Missing Mitigations:
    - **Secure Secret Storage**: Instead of storing the API Key directly in App Engine environment variables, utilize Google Cloud Secret Manager to store and manage the API Key securely.
    - **Restrict API Key Scope**:  Limit the scope of the API Key to the Cloud Scheduler API only. Ensure it does not have broader permissions that are not necessary for the App Engine application's functionality.
    - **IAM for App Engine**: Enforce strict IAM policies for the App Engine service account itself, limiting access to only authorized users and services.

- Preconditions:
    - Deployment of the `auth-appengine` application using `gcloud app deploy`.
    - Successful configuration of the `API_KEY` environment variable in `auth-appengine/app.yaml`.
    - Hypothetical unauthorized access to the App Engine instance's runtime environment.

- Source Code Analysis:
    - File: `/code/auth-appengine/app.yaml`
    ```yaml
    runtime: python310

    env_variables:
      # Insert an API key with access to the Cloud Scheduler API here
      API_KEY: ""
    ```
    - The `app.yaml` file clearly indicates the intention to store the API Key in environment variables.
    - File: `/code/auth-appengine/classes/scheduler.py`
    ```python
    class Scheduler(Fetcher):
      ...
      @decorators.lazy_property
      def service(self):
        """Creates the Scheduler service.

        Returns:
            googleapiclient.discovery.Resource: the service
        """
        return service_builder.build_service(service=services.Service.CLOUDSCHEDULER,
                                             key=self.credentials.credentials,
                                             api_key=os.environ['API_KEY'])
      ...
    ```
    - The `Scheduler` class in `scheduler.py` retrieves the `API_KEY` from environment variables using `os.environ['API_KEY']` to initialize the Cloud Scheduler service.

- Security Test Case:
    1. Deploy the `auth-appengine` application using `gcloud app deploy --project <YOUR_PROJECT>`.
    2. Configure the `API_KEY` in `auth-appengine/app.yaml` with a valid API Key.
    3. **Simulate App Engine Instance Access (for testing purposes only in a controlled environment):**
        -  Assume you have gained access to the App Engine instance's shell or runtime environment (this step is for demonstration and is not intended to be a real exploit).
        -  Access the environment variables of the App Engine instance. The method to do this depends on the specific App Engine environment, but might involve techniques like examining process environment variables or using App Engine-specific tools.
        -  Retrieve the value of the `API_KEY` environment variable.
    4. **Misuse the API Key:**
        - Using the retrieved API Key, attempt to perform unauthorized actions against the Cloud Scheduler API, such as:
            - Listing Cloud Scheduler jobs for the project: `gcloud scheduler jobs list --project=<YOUR_PROJECT> --api-key=<RETRIEVED_API_KEY>`
            - Attempting to delete a Cloud Scheduler job (if you can identify one): `gcloud scheduler jobs delete <JOB_NAME> --project=<YOUR_PROJECT> --api-key=<RETRIEVED_API_KEY>`
        - If successful, this demonstrates that the API Key is exposed within the App Engine environment and can be misused to interact with the Cloud Scheduler API without proper authorization.

---
### 4. Vulnerability Name: Potential for Postprocessor Code Injection via GCS Bucket

- Description:
    1. The Report2BQ postprocessor feature allows users to upload custom Python code to a designated GCS bucket (`[project]-report2bq-postprocessor`).
    2. The `report2bq-postprocessor` Cloud Function dynamically loads and executes Python files from this bucket based on the `--message` parameter provided during job creation.
    3. If an attacker gains write access to the `[project]-report2bq-postprocessor` bucket, they could upload malicious Python code.
    4. When a Report2BQ job with a `--message` parameter corresponding to the attacker's malicious file is executed, the `report2bq-postprocessor` function will load and execute the attacker's code.
    5. Since postprocessors have "full access to the system," as documented in `POSTPROCESSOR.md`, this code injection vulnerability could allow an attacker to execute arbitrary code within the Cloud Functions environment, potentially escalating to broader project compromise if combined with overly permissive IAM roles (Vulnerability #1).

- Impact:
    - **High to Critical**. Remote Code Execution (RCE). An attacker could:
        - Execute arbitrary Python code within the Cloud Functions environment.
        - Potentially gain access to sensitive data and resources within the Google Cloud project, depending on the permissions of the Cloud Function's service account (Vulnerability #1 exacerbates this).
        - Modify or delete data and infrastructure.
        - Use the compromised Cloud Function environment for further attacks.
        - The severity depends heavily on the permissions of the Cloud Function's service account and the extent of access the attacker can gain to other resources.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - **Documentation Warning**: The `POSTPROCESSOR.md` documentation includes a warning: "`Postprocessor`s have full access to the system, so should be treated with care...". However, this is a weak mitigation as it relies on users' awareness and diligence.

- Missing Mitigations:
    - **Restrict Bucket Write Access**: Implement strict IAM policies on the `[project]-report2bq-postprocessor` bucket, limiting write access to only highly trusted and authorized users or service accounts. General users should not have write access to this bucket.
    - **Code Review and Scanning**: Establish a process for reviewing and scanning postprocessor code before it is uploaded to the bucket. This could involve manual code review or automated static analysis security testing (SAST) tools.
    - **Input Validation and Sandboxing (Partial Mitigation)**: While full sandboxing of dynamically loaded Python code is complex, consider implementing basic input validation or security checks within the `report2bq-postprocessor` function to mitigate some common code injection attack vectors. However, this should not be considered a primary mitigation against malicious code uploaded by a determined attacker.
    - **Principle of Least Privilege (Reiteration)**: Ensure that the Cloud Functions service account running `report2bq-postprocessor` has the least privilege necessary to perform its intended tasks. Avoid granting it overly broad roles like `roles/editor` (see Vulnerability #1).

- Preconditions:
    - Report2BQ installation with the postprocessor feature enabled.
    - Write access to the `[project]-report2bq-postprocessor` GCS bucket for the attacker.
    - Creation of a Report2BQ job (e.g., using `create_fetcher.sh`) with the `--message` parameter set to the name of the attacker's malicious Python file in the bucket.

- Source Code Analysis:
    - File: `/code/application/POSTPROCESSOR.md`
    ```markdown
    `Postprocessor`s have full access to the system, so should be treated with care,
    but they can be a powerful addition to your Report2BQ installation.
    ...
    ## DEPLOYING A `POSTPROCESSOR`

    Copy the python file to the `[project]-report2bq-postprocessor` bucket.

    ## CALLING THE DEPLOYED `POSTPROCESSOR`

    Create your `fetcher` job with the `--message` parameter. The value of
    `--message` should be the name of the python file, without the extension.
    ```
    - The documentation explicitly states that postprocessors have "full access to the system" and instructs users to deploy them by copying Python files to the GCS bucket.
    - File: `/code/application/main.py`
    ```python
    def post_processor(event: Dict[str, Any], context=None) -> None:
      """Runs the post processor function.
      ...
      if event_data := event.get('data'):
        module_name = base64.b64decode(event_data).decode('utf-8')
        logging.info('Loading and running %s', module_name)

        if attributes := event.get('attributes'):
          processor = PostProcessor.install(module_name=module_name,
                                            class_name='Processor',
                                            storage=dynamic.CloudStorage,
                                            bucket='report2bq-postprocessor')
          try:
            processor().run(context=context, **attributes)
          ...
    ```
    - The `post_processor` Cloud Function retrieves the postprocessor module name from the Pub/Sub event data, decodes it, and then dynamically loads and executes code from the `[project]-report2bq-postprocessor` bucket using `PostProcessor.install()` and `processor().run()`.

- Security Test Case:
    1. **Gain Write Access to GCS Bucket (for testing purposes only in a controlled environment):**
        -  Assume you have obtained write access to the `[project]-report2bq-postprocessor` GCS bucket (this step is for demonstration and is not intended to be a real exploit). In a real-world scenario, this would represent a serious misconfiguration or vulnerability.
    2. **Create Malicious Postprocessor Code:**
        - Create a Python file (e.g., `malicious_postprocessor.py`) with malicious code. For example, code that attempts to read a secret from Secret Manager and log it:
            ```python
            import logging
            import os
            from classes.postprocessor import PostProcessor
            from google.cloud import secretmanager

            class Processor(PostProcessor):
              def run(self, context=None, **attributes: Mapping[str, str]) -> Dict[str, Any]:
                logging.info("Malicious Postprocessor Running!")
                try:
                  client = secretmanager.SecretManagerServiceClient()
                  secret_name = "projects/<YOUR_PROJECT>/secrets/<YOUR_SECRET>/versions/latest" # Replace with a secret in your project
                  response = client.access_secret_version(request={"name": secret_name})
                  payload = response.payload.data.decode("UTF-8")
                  logging.error(f"Secret Value: {payload}") # In real attack, exfiltrate, don't just log
                except Exception as e:
                  logging.error(f"Error accessing secret: {e}")
                return {}
            ```
        - **Replace `<YOUR_PROJECT>` and `<YOUR_SECRET>` with your Google Cloud project ID and the name of a Secret Manager secret you have created for testing (or use a dummy secret for safety).**
    3. **Upload Malicious Code to GCS Bucket:**
        - Use `gsutil cp malicious_postprocessor.py gs://<YOUR_PROJECT>-report2bq-postprocessor/` to upload the malicious Python file to the designated GCS bucket.
    4. **Create Report2BQ Job with Malicious Postprocessor:**
        - Use `create_fetcher.sh` or `create_runner.sh` to create a Report2BQ job, specifying the `--message` parameter with the name of your malicious file (e.g., `--message malicious_postprocessor`).
        ```bash
        ./create_fetcher.sh --project=<YOUR_PROJECT_ID> --email="test@example.com" --report-id="12345" --message malicious_postprocessor
        ```
    5. **Trigger Report2BQ Job:**
        - Trigger the Report2BQ job (e.g., wait for the scheduled run, or manually trigger it if possible).
    6. **Check Cloud Function Logs:**
        - After the job executes, check the logs for the `report2bq-postprocessor` Cloud Function in the Google Cloud Console (Cloud Logging).
        - If the malicious code was successfully injected and executed, you should see log entries from your malicious code (e.g., "Malicious Postprocessor Running!" and potentially the secret value if you used a real secret for testing).
    7. This test case demonstrates that an attacker with write access to the postprocessor bucket can achieve Remote Code Execution by uploading and triggering malicious postprocessor code.