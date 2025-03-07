- Vulnerability Name: Owner Role to Default Compute Service Account
- Description:
    1. An attacker leverages publicly available setup instructions for the Blockbuster project.
    2. Following the "Grant service account permissions" section in `/code/README.md`, the project owner executes the command:
       ```bash
       gcloud projects add-iam-policy-binding $GCP_PROJECT_ID \
         --member="serviceAccount:${GCP_PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
         --role='roles/owner'
       ```
    3. This command grants the highly privileged 'Owner' role to the default Compute Engine service account for the GCP project.
    4. An attacker, by compromising any Compute Engine instance running under this default service account (which is possible through various attack vectors outside the scope of this project, such as exploiting vulnerabilities in third-party libraries within the Cloud Composer environment or through social engineering to gain access to a VM), would automatically inherit the 'Owner' role permissions.
- Impact:
    - Complete project takeover. With the 'Owner' role, the attacker gains unrestricted access to all GCP services and data within the project.
    - Data breach. The attacker can access and exfiltrate all data stored in Google Cloud Storage buckets, BigQuery datasets, Datastore, and other services. This includes potentially sensitive marketing analytics data.
    - Data manipulation and deletion. The attacker can modify or delete critical data, leading to data integrity issues and business disruption.
    - Resource hijacking. The attacker can create, modify, and delete any GCP resources, including virtual machines, Cloud Composer environments, Dataflow jobs, and Cloud AutoML models. This can lead to denial of service, resource abuse for cryptocurrency mining, or further attacks on other systems.
    - Service disruption. By manipulating or deleting infrastructure components, the attacker can completely disrupt the marketing analytics pipelines and related services.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None. The provided project, being a template and example, lacks built-in mitigations for this IAM over-permissioning issue. The README itself contains the vulnerable command.
- Missing Mitigations:
    - Principle of Least Privilege: Replace the 'Owner' role assignment with more restrictive and granular IAM roles.
        - For Cloud Composer worker nodes, the `roles/composer.worker` role should be sufficient.
        - For Dataflow worker nodes, the `roles/dataflow.worker` role should be used.
        - For accessing Google Cloud Storage buckets, roles like `roles/storage.objectAdmin` or even more restricted roles based on specific access needs should be granted.
        - For BigQuery access, roles like `roles/bigquery.dataEditor` (if data modification is needed) or `roles/bigquery.dataViewer` (for read-only access) and `roles/bigquery.jobUser` should be used.
    - Workload Identity: Implement Workload Identity to bind Kubernetes service accounts in the Cloud Composer cluster to specific IAM service accounts with limited permissions. This would further restrict the permissions of workloads running in Composer and reduce the blast radius of a potential compromise.
    - IAM Policy Auditing and Monitoring: Implement regular audits of IAM policies to detect and remediate overly permissive configurations. Set up monitoring and alerting for unusual IAM activity.
    - Security Best Practices Documentation: The project documentation should be updated to explicitly warn against granting the 'Owner' role and provide clear guidance on implementing least privilege IAM configurations.
- Preconditions:
    - The victim project owner must follow the vulnerable setup instructions in `/code/README.md` and execute the command to grant the 'Owner' role to the default compute service account.
    - The attacker needs to find a way to compromise a Compute Engine instance running under the default compute service account within the GCP project. This could be achieved through various means, including exploiting vulnerabilities in the Cloud Composer environment, misconfigurations, or other attack vectors targeting Compute Engine VMs.
- Source Code Analysis:
    - `/code/README.md`: The file explicitly instructs users to execute the vulnerable command:
        ```markdown
        ### Grant service account permissions

        - Grant Owner permissions to the default compute service account:

        ```bash
          gcloud projects add-iam-policy-binding $GCP_PROJECT_ID \
            --member="serviceAccount:${GCP_PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
            --role='roles/owner'
        ```
        ```
    - The command directly uses `--role='roles/owner'`, clearly indicating the intention to grant the 'Owner' role. There is no other code in the provided files that mitigates or addresses this IAM over-permissioning issue.
- Security Test Case:
    1. **Project Setup**: Deploy the Blockbuster project to a new GCP project, strictly following the instructions in `/code/README.md`, including the step to grant 'Owner' permissions to the default Compute Engine service account.
    2. **Cloud Composer Environment Access**: Access the Cloud Composer environment created as part of the setup. Obtain SSH access to a worker node within the Cloud Composer environment. This step simulates an attacker gaining access to a VM running under the default compute service account. (Note: In a real-world scenario, an attacker might use various techniques to gain access, such as exploiting software vulnerabilities or misconfigurations, which are outside the scope of this test case but represent realistic attack vectors.)
    3. **Verify IAM Permissions**: Once SSHed into the Cloud Composer worker node, which operates under the default Compute Engine service account, use the Google Cloud SDK (gcloud) to verify the assigned IAM permissions. Execute the command:
       ```bash
       gcloud projects get-iam-policy <YOUR_GCP_PROJECT_ID> --filter="bindings.role=roles/owner AND bindings.members:serviceAccount:$(gcloud config get-value project)-compute@developer.gserviceaccount.com"
       ```
       This command should return the IAM policy binding confirming that the 'Owner' role is assigned to the default Compute Engine service account.
    4. **Attempt Resource Listing**: Attempt to list Compute Engine instances within the project using the gcloud SDK from within the compromised VM:
       ```bash
       gcloud compute instances list --project <YOUR_GCP_PROJECT_ID>
       ```
       Successful execution of this command demonstrates the ability to manage Compute Engine resources due to the 'Owner' role.
    5. **Attempt Data Access**: Attempt to list the contents of the Google Cloud Storage bucket created for the project:
       ```bash
       gsutil ls gs://<YOUR_GCS_BUCKET_NAME>
       ```
       Successful execution of this command demonstrates unauthorized access to data stored in Google Cloud Storage due to the 'Owner' role.

This security test case confirms that granting the 'Owner' role to the default Compute Engine service account, as instructed in the README, creates a critical vulnerability allowing a compromised VM to gain full control over the GCP project.