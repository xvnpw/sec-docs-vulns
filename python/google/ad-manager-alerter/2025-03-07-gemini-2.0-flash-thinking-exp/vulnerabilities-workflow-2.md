## Combined Vulnerability List

### Vulnerability: Service Account Credential Exposure and Abuse

- **Description:** The project utilizes a Google Cloud Service Account for accessing Google Cloud services like Google Ad Manager API, Google Cloud Storage (GCS), and BigQuery. If the service account credentials are compromised, attackers could gain unauthorized access to these services. Potential compromise vectors include IAM misconfigurations, credential leakage (less likely in GCP but possible), and insider threats.  Compromised credentials could be used to exfiltrate Ad Manager reports, manipulate BigQuery data, disrupt anomaly detection, and potentially access other GCP resources.

    **Step-by-step trigger:**
    1. An attacker gains access to the Google Cloud project, potentially through compromised user credentials or misconfigured IAM roles.
    2. The attacker identifies the service account associated with the Cloud Function.
    3. The attacker exploits a vulnerability or misconfiguration to retrieve the service account's access token or private key (e.g., through metadata server access with compromised instance, or leaked credentials).
    4. Using the compromised service account credentials, the attacker authenticates to Google Cloud services like Ad Manager API, GCS, or BigQuery.
    5. The attacker performs unauthorized actions, such as downloading sensitive reports, modifying data, or disrupting services, depending on the permissions granted to the compromised service account.

- **Impact:** A compromised service account can lead to significant data breaches, service disruptions, financial losses, and reputational damage due to unauthorized access to sensitive data in Ad Manager reports and BigQuery datasets. The impact is critical due to the potential exposure of sensitive business data.

- **Vulnerability rank:** Critical

- **Currently implemented mitigations:**
    - Google-managed Service Account usage.
    - OIDC Authentication for Workflow.
    - Metadata Server Token Retrieval in `report_downloader.py`.

- **Missing mitigations:**
    - Principle of Least Privilege for Service Account Roles.
    - Regular Audit of Service Account Permissions.
    - Monitoring Service Account Activity.
    - IAM Policy Controls.
    - VPC Service Controls (if applicable).

- **Preconditions:**
    - Google Cloud Service Account compromise due to IAM misconfiguration, credential leakage, or insider threat.

- **Source code analysis:**
    - **Service Account Usage:** The code uses the service account in `report_downloader.py` to retrieve access tokens from the metadata server and interact with Ad Manager API and GCS. `ml_builder.py` and `anomaly_detector.py` use `bigquery.Client()` for BigQuery interactions, implicitly using the service account context when deployed as a Cloud Function.

    ```python
    # report_downloader.py - Token retrieval
    def get_access():
        url = (f"{METADATA_URL}instance/service-accounts/" +
               f"{SERVICE_ACCOUNT}/token?scopes={SCOPES}")
        r = requests.get(url, headers=METADATA_HEADERS, timeout=60)
        return r.json()
    ```

    ```python
    # report_downloader.py - Ad Manager client initialization
    def get_ad_manager_client():
        oauth2_client = get_oauth2_client_access_token(get_access())
        ad_manager_client = ad_manager.AdManagerClient(oauth2_client,
                                                        APPLICATION_NAME,
                                                        network_code=NETWORK_CODE)
        return ad_manager_client
    ```

    ```python
    # report_downloader.py - GCS client initialization
    def upload_to_gcs(filename, gcs_filename):
        client = storage.Client() # Implicitly uses service account
        bucket = client.get_bucket(BUCKET)
        blob = bucket.blob(gcs_filename)
        blob.upload_from_filename(filename)
    ```

    ```python
    # ml_builder.py and anomaly_detector.py - BigQuery client initialization
    from google.cloud import bigquery
    client = bigquery.Client() # Implicitly uses service account
    ```

- **Security test case:**
    1. Identify the service account associated with the Cloud Function.
    2. Review the IAM roles granted to the service account for overly permissive roles.
    3. Simulate service account compromise (conceptually or by impersonation in a test environment).
    4. Attempt unauthorized access to GCS, BigQuery, and Ad Manager API using the service account's assumed credentials.
    5. Verify if unauthorized access to sensitive resources is successful, confirming the potential impact of service account compromise due to overly broad permissions.

---

### Vulnerability: SendGrid API Key Exposure through Environment Variables

- **Description:** The SendGrid API key, used for sending email alerts, is stored as an environment variable (`SENDGRID_API_KEY`) in the Cloud Function.  An attacker gaining unauthorized access to the Cloud Function's environment variables can retrieve this API key. Access to environment variables can be achieved through various attack vectors including compromising the GCP project, exploiting deployment pipeline vulnerabilities, or insider threats. Once obtained, the API key can be used to send emails through the project's SendGrid account.

    **Step-by-step trigger:**
    1. An attacker compromises the Google Cloud project or gains unauthorized access to the Cloud Function's configuration or runtime environment.
    2. The attacker accesses the Cloud Function's environment variables through the Google Cloud Console, Cloud Functions API, misconfigured logging, or other means.
    3. The attacker retrieves the value of the `SENDGRID_API_KEY` environment variable.
    4. Using the compromised SendGrid API key, the attacker authenticates with the SendGrid API from any location.
    5. The attacker sends spoofed emails, distributes malicious content, or abuses the SendGrid account for their own purposes.

- **Impact:**  Exposure of the SendGrid API key allows attackers to send spoofed emails, distribute malicious content, and abuse the SendGrid account, potentially leading to phishing attacks, damage to project reputation, and unexpected costs. The vulnerability is ranked high due to the potential for significant misuse.

- **Vulnerability rank:** High

- **Currently implemented mitigations:**
    - Using environment variables for API key storage is a partial mitigation compared to hardcoding.

- **Missing mitigations:**
    - Secret Management System (e.g., Google Cloud Secret Manager).
    - Principle of Least Privilege for accessing environment variables and secrets.
    - Regular Key Rotation.
    - Monitoring and Alerting for SendGrid API Abuse.

- **Preconditions:**
    - Application deployed as a Cloud Function using SendGrid for email alerts.
    - SendGrid API key configured as `SENDGRID_API_KEY` environment variable.
    - Attacker gains unauthorized access to the Cloud Function's environment variables.

- **Source code analysis:**
    - **config.example.py:** Shows API key retrieval from environment variable.
    ```python
    SENDGRID_API_KEY = os.environ["SENDGRID_API_KEY"]
    ```
    - **anomaly_detector.py:** Uses `SENDGRID_API_KEY` to initialize SendGrid client and send emails.
    ```python
    from config import SENDGRID_API_KEY
    ...
    sg = SendGridAPIClient(SENDGRID_API_KEY)
    ...
    sg.send(message)
    ```
    - The code directly uses the API key from the environment variable for sending emails, making its exposure a direct security risk.

- **Security test case:**
    1. Deploy the Cloud Function with SendGrid configured and `SENDGRID_API_KEY` environment variable set.
    2. Access the Google Cloud Console and navigate to the Cloud Function's environment variables (or simulate retrieval through other means).
    3. Obtain (or assume to obtain) the `SENDGRID_API_KEY` value.
    4. Using the compromised API key, execute a script (e.g., Python with SendGrid library) from an external system to send a spoofed email.
    5. Verify that the email is successfully sent through the project's SendGrid account, confirming the API key exposure vulnerability.

---

### Vulnerability: Overly Permissive Service Account Permissions

- **Description:** The project documentation instructs users to grant overly broad permissions to the service account, specifically "BigQuery Data Owner" and "Executive" role in Google Ad Manager. These roles grant excessive control over BigQuery datasets and Ad Manager, respectively, beyond what is strictly necessary for the application. If an attacker compromises the service account credentials, these excessive permissions can be exploited to access, modify, or delete sensitive data and configurations within the victim's Google Cloud and Ad Manager accounts.

    **Step-by-step trigger:**
    1. A user follows the project documentation and grants the service account overly permissive roles like "BigQuery Data Owner" and "Executive" in Ad Manager.
    2. An attacker gains access to the service account's credentials (through methods outside the scope of this specific vulnerability, but assuming misconfiguration or broader compromise).
    3. The attacker leverages the "BigQuery Data Owner" role to access, modify, or delete any data within the BigQuery dataset, including potentially sensitive advertising data.
    4. The attacker utilizes the "Executive" role in Ad Manager to access and exfiltrate sensitive advertising reports and potentially modify Ad Manager settings, depending on the exact permissions of the "Executive" role.

- **Impact:** Overly permissive service account permissions can lead to unauthorized access and exfiltration of sensitive advertising data from Google Ad Manager, potential data breaches within BigQuery datasets, and unauthorized modification or deletion of critical data. The impact is high due to the potential for significant data exposure and manipulation.

- **Vulnerability rank:** High

- **Currently implemented mitigations:**
    - None in the project code itself. The project relies on user-configured permissions.

- **Missing mitigations:**
    - Principle of Least Privilege Documentation (strongly recommend least privilege roles).
    - Clarification of Required Permissions (document specific permissions, not just roles).
    - Security Best Practices Warning in README.

- **Preconditions:**
    1. User deploys the project and follows documentation instructions.
    2. User grants "BigQuery Data Owner" and "Executive" roles to the service account as per documentation.
    3. Attacker gains knowledge of the service account and compromises its credentials (or gains access through other means assuming overly permissive roles are granted).

- **Source code analysis:**
    - **README.md:**  Documentation explicitly instructs users to grant overly permissive roles: "BigQuery Data Owner" and "Executive" in Ad Manager.
    ```markdown
    **Important!** Make sure you grant access for the service account to run queries on this data set. You can do this by adding them as a Principal with the role **"Big Query Data Owner"**.
    ...
    2. [Add the service account email to Ad Manager](https://support.google.com/admanager/answer/6078734?hl=en) with rights to run reports. (Eg. role "[Executive](https://support.google.com/admanager/answer/177403?hl=en)")
    ```
    - **config.example.py & report_downloader.py:** Highlight service account usage, emphasizing the importance of its permissions.

- **Security test case:**
    1. Deploy the project and grant "BigQuery Data Owner" and "Executive" roles to the service account as per the documentation in a test environment.
    2. Simulate attacker access by impersonating the service account within the GCP project (requires project access for testing purposes).
    3. As the impersonated service account, attempt to:
        - Query and view sensitive data in the BigQuery dataset.
        - Attempt to delete BigQuery tables or the dataset.
        - Access and download reports and explore settings in Ad Manager.
    4. Verify that the overly permissive roles allow unauthorized access and actions, confirming the vulnerability.