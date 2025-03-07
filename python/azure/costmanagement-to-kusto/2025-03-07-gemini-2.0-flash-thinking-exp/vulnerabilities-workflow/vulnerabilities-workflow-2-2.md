#### 1. Overly Permissive Storage Account Permissions

- **Description:**
    1. The deployment guide instructs users to grant the Azure Data Factory (ADF) System Assigned Managed Identity (MSI) the "Storage Blob Data Reader" role on the storage account container named "usage-preliminary".
    2. While "Storage Blob Data Reader" is necessary for ADF to read the exported cost data blobs from this container, this role might grant broader permissions than strictly required for the intended data ingestion process.
    3. Specifically, "Storage Blob Data Reader" grants read access to all blobs within the storage account, and potentially list access to containers. If an attacker were to compromise the ADF MSI, they could potentially leverage these overly broad permissions to access other data within the storage account, beyond the intended cost data in the "usage-preliminary" container.
    4. An attacker could exploit compromised ADF MSI credentials to explore the storage account, list containers, and access or download any blob they have read access to due to the "Storage Blob Data Reader" role assignment. This could expose sensitive data if the storage account is not exclusively used for cost data exports.

- **Impact:**
    - Unauthorized access to sensitive data within the storage account. If the storage account is used for more than just cost data exports, a compromised ADF MSI could grant an attacker access to other potentially sensitive information stored in the same storage account. The impact is increased if the storage account contains other sensitive data beyond cost management exports.

- **Vulnerability Rank:** Medium

- **Currently Implemented Mitigations:**
    - None explicitly implemented in the project to restrict storage account access beyond the "Storage Blob Data Reader" role. The documentation focuses on granting the necessary permissions for the data pipeline to function.

- **Missing Mitigations:**
    - **Implement Least Privilege:** Restrict the ADF MSI's access to the minimum necessary permissions. Instead of "Storage Blob Data Reader" on the entire storage account or container, explore more granular permissions. Ideally, the permission should be limited to *only* reading blobs within the "usage-preliminary" container, and prevent listing containers or accessing other blobs.  Consider using more specific Azure RBAC roles or custom roles if available to achieve this granularity.
    - **Consider Shared Access Signatures (SAS):** Evaluate the feasibility of using Shared Access Signatures (SAS) with read-only permissions scoped to the specific blobs or blob prefixes expected by ADF. This would provide a more narrowly scoped permission compared to "Storage Blob Data Reader". However, SAS key management would need to be addressed.
    - **Storage Account Isolation Recommendation:** Strongly recommend in the documentation that users dedicate a separate storage account specifically for Azure Cost Management exports. This practice would significantly limit the potential blast radius if the ADF MSI were compromised, as the attacker's access would be confined to the cost data storage account and not other potentially sensitive data.

- **Preconditions:**
    - An attacker gains unauthorized access to the Azure Data Factory System Assigned Managed Identity credentials. This could be achieved through various methods, such as exploiting vulnerabilities within ADF itself, the wider Azure environment, or through credential leakage if not properly managed.
    - The storage account is not dedicated solely to cost data exports and contains other potentially sensitive information in addition to the cost data.

- **Source Code Analysis:**
    - The provided source code does not directly introduce this vulnerability. The vulnerability stems from the permissions recommended in the deployment documentation (`/code/docs/step2-5.md` and `/code/docs/manual_deployment.md`) for granting ADF MSI access to the storage account.
    - The documentation guides users to grant the "Storage Blob Data Reader" role, which, while enabling the functionality, may provide broader read access than strictly necessary.
    - No code within the project files attempts to enforce or validate least privilege principles for storage account access.

- **Security Test Case:**
    1. **Prerequisites:** Deploy the solution using the manual deployment guide, ensuring a storage account is created and the ADF MSI is granted "Storage Blob Data Reader" on the "usage-preliminary" container as instructed. Assume you have credentials that allow you to act as the ADF MSI or simulate its permissions. For this test, let's assume you have administrative access to the Azure subscription for easier validation.
    2. **Identify ADF MSI Principal ID:** Locate the deployed Azure Data Factory instance in the Azure portal. Navigate to "Identity" settings and note down the "Principal ID" of the System Assigned Managed Identity.
    3. **Identify Storage Account Name:** Note down the name of the storage account created during the deployment.
    4. **Create Test Container and Blob (Optional but Recommended):**  Within the storage account, create a new container named "test-container". Inside "test-container", upload a test blob file (e.g., "sensitive-data.txt") containing some dummy sensitive data. This step is to confirm access to other containers beyond "usage-preliminary".
    5. **Attempt to List Containers using ADF MSI Identity:** Using Azure CLI, attempt to list containers in the storage account, authenticating as the ADF MSI. You can simulate this by using your own credentials and specifying the ADF MSI's principal ID for identity-based authentication.
        ```bash
        ADF_MSI_PRINCIPAL_ID="<ADF_MSI_PRINCIPAL_ID>"
        STORAGE_ACCOUNT_NAME="<YOUR_STORAGE_ACCOUNT_NAME>"
        az storage container list --account-name $STORAGE_ACCOUNT_NAME --auth-mode identity --identity $ADF_MSI_PRINCIPAL_ID
        ```
        If this command successfully lists containers (including "test-container" and potentially others besides "usage-preliminary"), it indicates broader container listing access.
    6. **Attempt to Download Blob from "test-container" using ADF MSI Identity:** Using Azure CLI, attempt to download the "sensitive-data.txt" blob from the "test-container", again authenticating as the ADF MSI.
        ```bash
        ADF_MSI_PRINCIPAL_ID="<ADF_MSI_PRINCIPAL_ID>"
        STORAGE_ACCOUNT_NAME="<YOUR_STORAGE_ACCOUNT_NAME>"
        CONTAINER_NAME="test-container"
        BLOB_NAME="sensitive-data.txt"
        az storage blob download --account-name $STORAGE_ACCOUNT_NAME --container-name $CONTAINER_NAME --name $BLOB_NAME --file downloaded_sensitive_data.txt --auth-mode identity --identity $ADF_MSI_PRINCIPAL_ID
        ```
        If this command successfully downloads "downloaded_sensitive_data.txt", it confirms that the ADF MSI, with "Storage Blob Data Reader" permissions, can read blobs outside of the intended "usage-preliminary" container.
    7. **Verification:** If steps 5 and 6 are successful, it validates the vulnerability of overly permissive storage account permissions. The ADF MSI, intended only to read cost data from "usage-preliminary", can potentially access and read data from other containers within the storage account due to the "Storage Blob Data Reader" role.