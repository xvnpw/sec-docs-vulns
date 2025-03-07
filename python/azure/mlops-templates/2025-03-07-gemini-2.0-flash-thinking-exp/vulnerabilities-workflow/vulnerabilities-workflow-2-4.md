### Vulnerability List

#### 1. Potential Command Injection in Azure CLI Scripts
* Description:
    1. An attacker could potentially inject malicious commands into parameters used within Azure CLI scripts.
    2. For example, in `create-deployment.yml`, the `deployment_name` parameter is directly incorporated into the `az ml $(endpoint_type)-deployment create --name ${{ parameters.deployment_name }} ...` command.
    3. If `parameters.deployment_name` is derived from an external, untrusted source and not properly sanitized, an attacker could inject additional commands.
    4. Although the provided files don't directly show user-controlled input, in a real-world scenario, these parameters might be dynamically generated or passed from external systems, opening up this potential attack vector.
* Impact:
    - Successful command injection could allow an attacker to execute arbitrary Azure CLI commands with the permissions of the Azure DevOps service connection.
    - This could lead to unauthorized access to Azure resources, data exfiltration, resource modification, or even complete compromise of the MLOps environment.
* Vulnerability Rank: High
* Currently Implemented Mitigations: None evident in the provided files. The templates assume trusted input for parameters.
* Missing Mitigations:
    - Input validation and sanitization for all parameters used in Azure CLI scripts, especially those that could be derived from external sources.
    - Principle of least privilege for Azure DevOps service connections. Grant only the necessary permissions required for each task.
* Preconditions:
    - A scenario where parameters used in Azure CLI scripts are derived from external, untrusted sources.
    - Lack of input validation and sanitization in the scripts.
* Source Code Analysis:
    - Files like `/code/templates/aml-cli-v2/create-deployment.yml`, `/code/templates/aml-cli-v2/allocate-traffic.yml`, `/code/templates/aml-cli-v2/register-data.yml`, `/code/templates/aml-cli-v2/create-endpoint.yml`, `/code/templates/aml-cli-v2/create-compute.yml`, `/code/templates/aml-cli-v2/register-environment.yml`, `/code/templates/aml-cli-v2/test-deployment.yml`, `/code/templates/aml-cli-v2/run-pipeline.yml` and many other files within `/code/templates` use `AzureCLI@2` task with `inlineScript`.
    - Parameters like `deployment_name`, `traffic_allocation`, `data_name`, `endpoint_name`, `cluster_name`, `environment_name`, `pipeline_file`, etc. are directly embedded into the `inlineScript` using `${{ parameters.<parameter_name> }}` syntax.
    - If these parameters are not properly validated and sanitized before being passed to the Azure DevOps pipeline, and if their values are derived from untrusted sources, command injection is possible.
* Security Test Case:
    1. Setup: Deploy the MLOps environment using the provided templates. Assume a scenario where the `deployment_name` parameter in `create-deployment.yml` is controllable by an attacker (e.g., through a web interface or API that triggers the pipeline).
    2. Attack: As an attacker, provide a malicious `deployment_name` parameter value like: `test-deployment; az account show > injected_output.txt`.  This attempts to inject the command `az account show > injected_output.txt` after the intended `az ml ... deployment create ...` command. The output of `az account show` which contains sensitive account information will be redirected to `injected_output.txt`.
    3. Execution: Trigger the Azure DevOps pipeline with the malicious `deployment_name`.
    4. Verification: After the pipeline execution, check the logs of the `Create deployment` task in the Azure DevOps pipeline. Look for execution of the injected command (`az account show > injected_output.txt`).  Also, attempt to access `injected_output.txt` in the workspace's storage account (if accessible) or look for side effects of the injected command. If `az account show` was executed successfully, it proves command injection vulnerability.

#### 2. Overly Permissive Azure Resource Group Service Connection
* Description:
    1. Many Azure DevOps pipeline templates in this project use a service connection named `ado_service_connection_rg`.
    2. This service connection is used to execute Azure CLI tasks at the Resource Group level, as indicated by the `azureSubscription: $(ado_service_connection_rg)` input in tasks like creating compute, endpoints, deployments, etc.
    3. If this service connection is configured with overly broad permissions at the Resource Group scope (e.g., the "Contributor" role), it grants the pipeline and potentially attackers (if they can compromise the pipeline or service connection) excessive privileges.
    4. Attackers could leverage these permissions to perform unauthorized actions within the Resource Group or even the entire subscription, such as modifying critical resources, accessing sensitive data, or launching denial-of-service attacks.
* Impact:
    - Unauthorized access and modification of Azure resources within the Resource Group and potentially the subscription.
    - Data breaches through unauthorized access to storage accounts or databases.
    - Denial of service by deleting or misconfiguring critical resources.
    - Lateral movement to other Azure resources if the service principal has broader permissions.
* Vulnerability Rank: Medium to High (depending on the actual permissions granted to the service connection)
* Currently Implemented Mitigations: None evident in the project files. The templates rely on the user to configure the service connection appropriately.
* Missing Mitigations:
    - Principle of least privilege: Document and enforce the requirement to grant the `ado_service_connection_rg` service connection only the minimum necessary permissions. Ideally, use custom roles with granular permissions instead of built-in roles like "Contributor".
    - Clearly document the required permissions for each service connection in the project's README or security documentation.
    - Consider using separate service connections with more restricted scopes for different tasks if possible.
* Preconditions:
    - The `ado_service_connection_rg` Azure DevOps service connection is configured with overly permissive roles at the Resource Group level (e.g., "Contributor" or "Owner").
    - An attacker gains access to the Azure DevOps pipeline (e.g., through compromised credentials or pipeline misconfiguration) or the service connection's credentials (less likely but possible if secrets are mismanaged).
* Source Code Analysis:
    - Multiple files across `/code/templates/aml-cli-v2` and `/code/templates/python-sdk-v*` folders consistently use `azureSubscription: $(ado_service_connection_rg)` for AzureCLI@2 tasks.
    - Examples: `create-deployment.yml`, `allocate-traffic.yml`, `register-data.yml`, `create-endpoint.yml`, `create-compute.yml`, `register-environment.yml`, `test-deployment.yml`, `run-pipeline.yml`, `create-compute-instance.yml`, `create-compute.yml`.
    - The use of `ado_service_connection_rg` implies operations are performed using the permissions associated with this service connection, and its scope is at least Resource Group level.
    - The files themselves do not restrict the permissions of this service connection, making it vulnerable if misconfigured with excessive privileges.
* Security Test Case:
    1. Setup: Deploy the MLOps environment. Configure `ado_service_connection_rg` with the "Contributor" role at the Resource Group level.
    2. Attack: As an attacker with access to the Azure DevOps project (e.g., as a compromised internal user or through a pipeline vulnerability), attempt to modify or delete a resource in the Resource Group that is not directly related to the MLOps environment but is within the scope of the "Contributor" role. For example, try to delete a different storage account or virtual machine within the same Resource Group using an Azure CLI task in a modified pipeline or a new pipeline using the same service connection.
    3. Execution: Create or modify an Azure DevOps pipeline to include an Azure CLI task that attempts to delete an unrelated resource in the same Resource Group using `ado_service_connection_rg`. For example:
       ```yaml
       steps:
         - task: AzureCLI@2
           displayName: 'Attempt to Delete Unrelated Resource'
           inputs:
             azureSubscription: $(ado_service_connection_rg)
             scriptType: bash
             scriptLocation: inlineScript
             inlineScript: |
               az resource delete --resource-group $(resource_group) --name unrelated-resource --resource-type Microsoft.Storage/storageAccounts --api-version 2021-04-01
       ```
       Replace `unrelated-resource` and `Microsoft.Storage/storageAccounts` with actual resource details present in the Resource Group but not part of the MLOps stack.
    4. Verification: Run the modified pipeline. If the unrelated resource is successfully deleted, it confirms that the `ado_service_connection_rg` has overly permissive permissions, allowing actions beyond the intended scope of MLOps deployment and management.

#### 3. Insecure Storage of Terraform State
* Description:
    1. The `templates/infra` directory contains files for deploying infrastructure using Terraform.
    2. `run-terraform-init.yml` configures Terraform to use an Azure Storage Account as the backend for storing Terraform state.
    3. If the configured Storage Account or Container is not properly secured, the Terraform state file could be exposed.
    4. Terraform state files can contain sensitive information, including:
        - Secrets and credentials embedded in Terraform configurations.
        - Configuration details of Azure resources, including network configurations, storage account keys (potentially if managed by Terraform, although best practice is to avoid this), and other sensitive settings.
        - Metadata about the infrastructure, which can aid attackers in reconnaissance.
    5. Exposure of Terraform state could allow attackers to gain unauthorized access to the infrastructure, understand its configuration for further attacks, or potentially modify the infrastructure.
* Impact:
    - Information disclosure of sensitive infrastructure configuration details and potentially secrets.
    - Unauthorized access to and modification of the Azure infrastructure managed by Terraform.
    - Increased attack surface and easier reconnaissance for attackers.
* Vulnerability Rank: Medium to High (depending on the sensitivity of data in the state and the ease of access to the state file)
* Currently Implemented Mitigations: Partially mitigated by using Azure Storage Account as a backend, which is generally more secure than local state.
* Missing Mitigations:
    - **Private Storage Account:** Ensure the Storage Account used for Terraform state is private and not publicly accessible.
    - **Access Control:** Implement strict access control on the Storage Account and Container. Use Azure RBAC to grant access only to authorized users and service principals.  Specifically, the service principal used by Terraform should have minimal necessary permissions (ideally, a custom role).
    - **Encryption:** While Azure Storage is encrypted at rest by default, verify that encryption is enabled and consider using customer-managed keys for enhanced control.
    - **Network Security:** Consider restricting network access to the Storage Account to only allow access from trusted networks (e.g., Azure DevOps agents' IP ranges or specific virtual networks).
    - **State File Secrets Management:** Best practice is to avoid storing secrets directly in Terraform state. Utilize secure secret management solutions (like Azure Key Vault) and reference secrets in Terraform configurations instead of hardcoding them.
* Preconditions:
    - Terraform state backend is configured to use an Azure Storage Account (which is the case in the provided templates).
    - The Storage Account or Container used for Terraform state is misconfigured with overly permissive access controls (e.g., public access or broad RBAC roles).
    - An attacker gains access to the Storage Account or Container, either through compromised credentials, misconfigurations, or vulnerabilities in Azure Storage.
* Source Code Analysis:
    - `templates/infra/run-terraform-init.yml` configures Terraform backend using Azure Storage Account.
    - Inputs: `backendAzureRmResourceGroupName`, `backendAzureRmStorageAccountName`, `backendAzureRmContainerName`, `backendAzureRmKey`.
    - `create-storage-account.yml` creates the storage account for Terraform state, but there is no explicit configuration of access control or network security in these templates.
    - The templates focus on functionality but lack explicit security hardening for the Terraform state storage.
* Security Test Case:
    1. Setup: Deploy the MLOps environment, including the Terraform infrastructure components. Misconfigure the Storage Account used for Terraform state by setting the Container's access level to "Public read access for blobs". (This is a deliberate misconfiguration for testing purposes; in a real-world scenario, public access should be avoided).
    2. Attack: As an external attacker, attempt to anonymously access the Terraform state file in the Storage Account Container. Construct the URL to access the blob directly using the Storage Account name, Container name, and state file key (which might be predictable or discoverable).
       - URL format: `https://<storage_account_name>.blob.core.windows.net/<container_name>/<terraform_st_key>`
    3. Execution: Use a web browser or `curl` to access the constructed URL.
    4. Verification: If the Terraform state file is successfully downloaded without authentication, it confirms that the Storage Account Container is publicly accessible and insecurely configured. Examine the downloaded state file (`terraform.tfstate`) for sensitive information. If sensitive data (secrets, configuration details) is found in the state file, it demonstrates the information disclosure vulnerability.