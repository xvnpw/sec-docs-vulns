### Vulnerability List:

- Vulnerability Name: Owner permission granted to Compute Engine Default Service Account
- Description:
    1. The `Initial Setup` section in `README.md` instructs users to grant 'Owner' role to the Compute Engine default service account using the command:
    ```bash
    gcloud projects add-iam-policy-binding $GCP_PROJECT_ID \
      --member="serviceAccount:${GCP_PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
      --role='roles/owner'
    ```
    2. This command grants the 'Owner' role at the project level to the Compute Engine default service account.
    3. The 'Owner' role is overly permissive, granting broad access to all Google Cloud resources within the project.
    4. An attacker who gains access to any VM instance running as the Compute Engine default service account can leverage these excessive permissions to compromise the entire Google Cloud project.
- Impact:
    - Critical. Full project compromise. An attacker can gain complete control over all Google Cloud resources within the project, including data access, modification, deletion, and resource manipulation. This can lead to severe data breaches, financial loss, and disruption of services.
- Vulnerability Rank: critical
- Currently Implemented Mitigations:
    - None. The setup guide explicitly instructs users to grant this overly permissive role.
- Missing Mitigations:
    - **Principle of Least Privilege**: Instead of granting 'Owner', implement the principle of least privilege by granting only the necessary IAM roles to the Compute Engine default service account.  Specifically, the application likely only needs roles to interact with Dataflow, Composer, BigQuery, AutoML and Storage.  More granular roles like `roles/dataflow.developer`, `roles/composer.worker`, `roles/bigquery.user`, `roles/automl.serviceAgent`, `roles/storage.objectAdmin` should be considered, depending on the actual operations performed by the compute instances.
    - **Service Account Scoping**:  Instead of relying on project-level IAM, use service account scopes when launching Compute Engine instances. This further restricts the permissions available to the instance.
    - **Avoid Default Service Account**: Instead of using the Compute Engine default service account, create a dedicated service account with only the necessary permissions and attach it to the Compute Engine instances.
- Preconditions:
    - The user must follow the `Initial Setup` instructions in `README.md` and execute the command to grant 'Owner' role to the Compute Engine default service account.
    - An attacker needs to gain access to a Compute Engine VM running under the default Compute Engine service account. This could be achieved through various VM instance compromise techniques (e.g., exploiting vulnerabilities in applications running on the VM, gaining access to VM credentials, etc.).
- Source Code Analysis:
    - `/code/README.md`: The setup instructions clearly state to grant the 'Owner' role.
    ```markdown
    ### Grant service account permissions

    - Grant Owner permissions to the default compute service account:

        ```bash
          gcloud projects add-iam-policy-binding $GCP_PROJECT_ID \
            --member="serviceAccount:${GCP_PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
            --role='roles/owner'
        ```
    ```
    - This instruction is directly copy-pasteable and encourages users to create a highly insecure configuration.
- Security Test Case:
    1. Deploy the Blockbuster project on GCP following the `Initial Setup` instructions in `README.md`, specifically granting the 'Owner' role to the Compute Engine default service account.
    2. Create a Compute Engine VM instance in the same project, ensuring it uses the default Compute Engine service account.
    3. SSH into the newly created Compute Engine VM instance.
    4. From within the VM instance, use the Google Cloud SDK (pre-installed) to attempt to list all GCS buckets in the project:
    ```bash
    gcloud storage buckets list
    ```
    5. If the vulnerability exists, the command will successfully list all GCS buckets in the project, demonstrating unauthorized access due to the 'Owner' role.
    6. Further escalate the test by attempting to read data from a bucket, create a new BigQuery dataset, or perform other privileged actions to confirm the full extent of the 'Owner' role's impact.

- Vulnerability Name: BigQuery Data Editor permission granted to AutoML Service Account in the data storage project
- Description:
    1. The `Initial Setup` section in `README.md` instructs users to grant 'BigQuery Data Editor' role to the AutoML service account in the `$DATA_STORAGE_PROJECT` using the command:
    ```bash
      gcloud projects add-iam-policy-binding $DATA_STORAGE_PROJECT \
        --member="serviceAccount:service-${GCP_PROJECT_NUMBER}@gcp-sa-automl.iam.gserviceaccount.com" \
        --role='roles/bigquery.dataEditor'
    ```
    2.  While less permissive than 'Owner', 'BigQuery Data Editor' still grants significant write access to BigQuery datasets within the `$DATA_STORAGE_PROJECT`.
    3.  If `$DATA_STORAGE_PROJECT` is a sensitive project containing more than just the blockbuster working dataset (which is plausible in real-world scenarios where a single data storage project is reused for multiple applications), granting 'BigQuery Data Editor' broadly could allow the AutoML service account (and potentially compromised AutoML pipelines) to modify or delete data in other datasets within that project.
- Impact:
    - Medium. Potential unauthorized data modification or deletion in BigQuery datasets within the `$DATA_STORAGE_PROJECT`. The impact is medium because it is limited to BigQuery data and depends on the configuration of `$DATA_STORAGE_PROJECT`.
- Vulnerability Rank: medium
- Currently Implemented Mitigations:
    - None. The setup guide explicitly instructs users to grant this permission.
- Missing Mitigations:
    - **Principle of Least Privilege**: Grant the 'BigQuery Data Editor' role specifically to the `$GCP_BQ_WORKING_DATASET` dataset instead of the entire `$DATA_STORAGE_PROJECT`. This can be achieved using dataset-level IAM policies instead of project-level policies.  The command should be modified to target the dataset:
    ```bash
      bq --location=${BQ_LOCATION} add-dataset-access \
        --role roles/bigquery.dataEditor \
        --user serviceAccount:service-${GCP_PROJECT_NUMBER}@gcp-sa-automl.iam.gserviceaccount.com \
        ${GCP_PROJECT_ID}:${GCP_BQ_WORKING_DATASET}
    ```
    - **Dedicated Project**: If highly sensitive data is involved, consider using a dedicated Google Cloud project solely for the Blockbuster application's working dataset, minimizing the potential impact of compromised permissions within a broader data storage project.
- Preconditions:
    - The user must follow the `Initial Setup` instructions in `README.md` and execute the command to grant 'BigQuery Data Editor' role to the AutoML service account at the project level.
    - `$DATA_STORAGE_PROJECT` is configured to be a project containing datasets beyond just the Blockbuster working dataset, and those datasets contain sensitive information.
- Source Code Analysis:
    - `/code/README.md`: The setup instructions clearly state to grant the 'BigQuery Data Editor' role at project level to the AutoML Service Account.
    ```markdown
      gcloud projects add-iam-policy-binding $DATA_STORAGE_PROJECT \
        --member="serviceAccount:service-${GCP_PROJECT_NUMBER}@gcp-sa-automl.iam.gserviceaccount.com" \
        --role='roles/bigquery.dataEditor'
    ```
    - This instruction, while not as critical as the 'Owner' role, still encourages a broader permission grant than necessary.
- Security Test Case:
    1. Deploy the Blockbuster project on GCP following the `Initial Setup` instructions in `README.md`, specifically granting the 'BigQuery Data Editor' role to the AutoML service account in `$DATA_STORAGE_PROJECT`.
    2. Assume you have another BigQuery dataset named `sensitive_dataset` within the same `$DATA_STORAGE_PROJECT`, alongside the Blockbuster working dataset (`$GCP_BQ_WORKING_DATASET`).
    3. Obtain credentials for the AutoML service account (e.g., by accessing a Cloud Composer environment where the service account might be used or through other means if service account keys are mismanaged - although key mismanagement is not directly assessed here, broad permissions increase the risk if keys are ever exposed).
    4. Using the AutoML service account credentials, attempt to delete a table within the `sensitive_dataset` in BigQuery using the `bq` command-line tool or BigQuery API.
    ```bash
    bq --location=${BQ_LOCATION} rm -f ${DATA_STORAGE_PROJECT}:sensitive_dataset.sensitive_table
    ```
    5. If the vulnerability exists, the command will succeed in deleting the table from `sensitive_dataset`, demonstrating unauthorized modification capabilities within the broader `$DATA_STORAGE_PROJECT` due to the overly broad 'BigQuery Data Editor' permission.