## Combined Vulnerability List

### Vulnerability Name: Overly Permissive External Location Permissions
* Description:
    * Step 1: The Infrastructure-as-Code (IaC) scripts, specifically `iac-adb-360/helpers/create-ms-externlocation.sh` and `iac-adb-360/helpers/create-ms-catalognschema-sepstor.sh`, are used to create Unity Catalog external locations.
    * Step 2: These scripts, by default, grant `ALL_PRIVILEGES` on the newly created external locations to the `devcat-admins` group using the command `databricks grants update external_location $extlocationname --json '{ "changes": [{"principal": "devcat-admins", "add" : ["ALL_PRIVILEGES"]}] }'`.
    * Step 3: If the `devcat-admins` group in Unity Catalog is misconfigured or contains users or service principals with overly broad access, it can lead to unauthorized access to the underlying storage account associated with the external location.
    * Step 4: An attacker, if part of or able to compromise a member of the `devcat-admins` group, could leverage these permissions to bypass intended access controls and directly access, modify, or exfiltrate data in the linked storage account. This is because `ALL_PRIVILEGES` on an external location grants full control over the storage paths defined within that external location.
* Impact:
    * Unauthorized access to sensitive data stored in the linked storage accounts.
    * Potential data exfiltration, modification, or deletion by unauthorized users who are members of the `devcat-admins` group.
    * Violation of data confidentiality and integrity.
* Vulnerability Rank: High
* Currently Implemented Mitigations:
    * The project uses Unity Catalog for access control, which is a mitigation in itself compared to workspace-level ACLs.
    * The principle of least privilege should be applied when managing `devcat-admins` group membership, but this is not enforced by the IaC code itself.
* Missing Mitigations:
    * **Least Privilege Principle for Group Permissions:** The IaC should not grant `ALL_PRIVILEGES` by default. Instead, it should grant only the necessary minimal permissions required for the intended use case, such as `READ_FILES` or `WRITE_FILES`, and only when truly necessary.
    * **Documentation and Guidance:**  The documentation should explicitly warn administrators about the risks of granting `ALL_PRIVILEGES` and provide guidance on how to configure more restrictive permissions and manage `devcat-admins` group membership securely.
    * **Security Test Cases:** Include automated security tests that verify the principle of least privilege is applied to external locations and storage credentials.
* Preconditions:
    * The IaC pipelines have been executed to create the Databricks workspace and Unity Catalog objects.
    * The `devcat-admins` group in Unity Catalog exists.
    * An attacker is able to gain membership or compromise an existing member of the `devcat-admins` group.
* Source Code Analysis:
    * File: `/code/iac-adb-360/helpers/create-ms-externlocation.sh`
    ```bash
    databricks grants update external_location $extlocationname --json '{ "changes": [{"principal": "devcat-admins", "add" : ["ALL_PRIVILEGES"]}] }'
    ```
    * File: `/code/iac-adb-360/helpers/create-ms-catalognschema-sepstor.sh`
    ```bash
    databricks grants update external_location $extlocationname --json '{ "changes": [{"principal": "devcat-admins", "add" : ["ALL_PRIVILEGES"]}] }'
    ```
    * These lines in the scripts directly grant `ALL_PRIVILEGES` to the `devcat-admins` group on the created external locations.
    * There is no configuration option within these scripts to modify these permissions to be more restrictive.
    * An administrator running these scripts without understanding the implications will inadvertently configure overly permissive access to the underlying storage.

    ```mermaid
    graph LR
    A[IaC Script: create-ms-externlocation.sh] --> B{Databricks CLI: grants update external_location}
    B --> C[Unity Catalog Metastore]
    C --> D{External Location Permissions}
    D --> E[devcat-admins group gets ALL_PRIVILEGES]
    E --> F[Unauthorized Storage Access if devcat-admins misconfigured]
    ```
* Security Test Case:
    1. **Pre-requisites:**
        * Deploy the Databricks lakehouse solution using the provided IaC.
        * Ensure the `devcat-admins` group exists in Unity Catalog.
        * Add a test user (attacker) to the `devcat-admins` group.
        * Identify the name of the external location created by the IaC (e.g., `bronzextlocdev`).
    2. **Steps:**
        * As the test user (attacker), log in to the Databricks workspace.
        * Use the Databricks CLI or a notebook to list the files within the external location. For example, using Databricks CLI:
            ```bash
            databricks fs ls dbfs:/external_locations/<external_location_name>/
            ```
            Replace `<external_location_name>` with the actual name of the external location (e.g., `bronzextlocdev`).
        * Attempt to read the content of a file within the external location. For example, using Databricks CLI:
            ```bash
            databricks fs head dbfs:/external_locations/<external_location_name>/<some_file.parquet>
            ```
        * Attempt to write a new file to the external location. For example, using Databricks CLI:
            ```bash
            echo "test data" | databricks fs cp - dbfs:/external_locations/<external_location_name>/test_attacker_file.txt
            ```
    3. **Expected Result:**
        * The test user (attacker), being a member of `devcat-admins` group with `ALL_PRIVILEGES`, should be able to successfully list files, read file content, and write new files to the external location.
        * This demonstrates that the default permissions are overly permissive and allow unauthorized data access and modification if the `devcat-admins` group is not strictly managed.


### Vulnerability Name: Potential Secret Exposure in Variable Groups and Pipelines
* Description:
    * Step 1: Azure DevOps (ADO) Variable Groups are used to manage sensitive information like service principal secrets and GitHub Personal Access Tokens (PATs).
    * Step 2: Pipelines in this project, such as `iac-adb-360/pipelines/azure/deploy-postmetastore.yml` and `bundle_adb_360/pipelines/azure/init-pipeline.yml`, are configured to access these Variable Groups.
    * Step 3: While Variable Groups offer a "secret" type for variables, which masks the values in the UI and logs, the secrets are still accessible to anyone with "read" access to the pipeline and variable group, or "contributor" access to the Azure DevOps project.
    * Step 4: An attacker gaining unauthorized read access to the Azure DevOps project, or through compromised credentials of a user with read pipeline permissions, could potentially view or exfiltrate these secrets.
    * Step 5: These secrets, particularly the service principal client secrets (`clientsecret`) and GitHub PAT (`ghpat`), are used to authenticate to Azure and GitHub, respectively. Exposure of these secrets would grant an attacker the ability to impersonate the service principal or GitHub user.
    * Step 6: For example, the `bundle-deploy.sh` script uses these secrets to authenticate to Azure Databricks workspace and deploy bundles. If an attacker obtains these secrets, they could deploy malicious bundles or perform other unauthorized actions within the Databricks environment.
* Impact:
    * **High Impact:** If an attacker gains access to the secrets stored in the Variable Group, they can:
        * **Unauthorized Access to Azure Databricks:** Use the `adb-sc` service principal secret to access and control the Azure Databricks workspace, potentially gaining access to data, executing arbitrary code, or disrupting operations.
        * **Unauthorized Access to GitHub Repository:** Use the `gh-sc` GitHub PAT to access the project's GitHub repository. This could allow the attacker to modify code, introduce backdoors, or leak sensitive repository information.
        * **Lateral Movement:** Depending on the permissions granted to the service principals, the attacker might be able to use these compromised credentials to move laterally to other Azure resources or systems.
* Vulnerability Rank: High
* Currently Implemented Mitigations:
    * **Secret Variable Type in Azure DevOps:** Azure DevOps provides a "secret" variable type for Variable Groups. When used, the values are masked in the UI and logs. This is implemented for `clientsecret` and `ghpat` in `iac-adb-360/helpers/vargroup-create.sh`.
    * **Service Principal Least Privilege (Partial):** The service principals are intended to have Contributor rights on the resource groups, which is generally considered least privilege for infrastructure deployment. However, the potential impact of compromised credentials remains high.
* Missing Mitigations:
    * **Azure Key Vault Integration for Secrets Management:** Instead of storing secrets directly in Azure DevOps Variable Groups, integrate with Azure Key Vault. Store secrets in Key Vault and grant Azure DevOps pipelines managed identity access to retrieve secrets at runtime. This reduces the risk of secrets exposure within Azure DevOps itself.
    * **Azure DevOps Access Control Review:** Implement strict access control within Azure DevOps, ensuring only necessary personnel have "read" access to pipelines and Variable Groups. Regularly review and audit Azure DevOps permissions.
    * **Just-In-Time (JIT) Access for Azure DevOps:** Consider implementing JIT access for Azure DevOps administrative tasks, further limiting persistent access.
    * **Regular Secret Rotation:** Implement a policy for regular rotation of service principal secrets and GitHub PATs to minimize the window of opportunity if a secret is compromised.
* Preconditions:
    * An attacker needs to gain unauthorized access to the Azure DevOps project, either through compromised user credentials with read pipeline permissions or by exploiting a vulnerability in Azure DevOps itself (less likely in this context).
* Source Code Analysis:
    * **Variable Group Creation Script (`iac-adb-360/helpers/vargroup-create.sh`):**
        ```bash
        az pipelines variable-group variable create \
            --id $groupid \
            --name 'clientsecret' \
            --secret true \
            --org https://dev.azure.com/hdikram \
            --project $project \
            --value $clientsecret

        az pipelines variable-group variable create \
            --id $groupid \
            --name 'ghpat' \
            --secret true \
            --org https://dev.azure.com/hdikram \
            --project $project \
            --value $ghpat
        ```
        This script correctly uses `--secret true` when creating `clientsecret` and `ghpat` variables in the Variable Group, which is a basic mitigation. However, it does not prevent access to authorized users or compromised accounts.

    * **Pipeline Definitions (`iac-adb-360/pipelines/azure/deploy-postmetastore.yml`, `bundle_adb_360/pipelines/azure/init-pipeline.yml`, etc.):**
        ```yaml
        variables:
        - group: vgdevadb360
        ```
        Pipelines reference the Variable Group `vgdevadb360` (or `vgprdadb360`), making the variables, including secrets, available to the pipeline execution context.

    * **Bundle Deployment Script (`bundle_adb_360/helpers/bundle-deploy.sh`):**
        ```bash
        export ARM_CLIENT_ID=$clientid
        export ARM_CLIENT_SECRET=$clientsecret
        export ARM_TENANT_ID=$tenantid
        export DATABRICKS_AZURE_RESOURCE_ID=$workspaceId

        cd bundle_adb_360
        databricks bundle deploy -t $env
        ```
        This script uses environment variables `ARM_CLIENT_SECRET`, `ARM_CLIENT_ID`, and `ARM_TENANT_ID`, which are populated from the Variable Group secrets during pipeline execution, to authenticate with Azure Databricks.
* Security Test Case:
    1. **Precondition:** Assume you have "read" access to the Azure DevOps project (e.g., as a member of the "Readers" group or through individual permissions).
    2. **Step 1:** Navigate to the Azure DevOps project in a web browser.
    3. **Step 2:** Go to "Pipelines" -> "Library" -> "Variable groups".
    4. **Step 3:** Locate and select the Variable Group used by the IaC pipelines (e.g., `vgdevadb360`).
    5. **Step 4:** Click on the "Variables" tab.
    6. **Step 5:** Observe the variables listed. Variables of type "secret" will have their values masked.
    7. **Step 6:** Edit any pipeline that uses this variable group (e.g., `iac-adb-360/pipelines/azure/deploy-postmetastore.yml`).
    8. **Step 7:** Add a new task (e.g., "Bash" task) to the pipeline definition.
    9. **Step 8:** In the inline script of the new task, add commands to print the secret variables as environment variables (e.g., `echo "Client Secret: $ARM_CLIENT_SECRET"`).
    10. **Step 9:** Save and run the pipeline.
    11. **Step 10:** After the pipeline run completes, examine the logs of the newly added task.
    12. **Expected Result:** Although the variables are defined as "secret", the pipeline execution logs will reveal the values of the secret variables, demonstrating that users with "read" access to the pipeline can effectively retrieve the secrets.


### Vulnerability Name: Hardcoded Service Principal Secret in Helper Scripts and Pipeline Configurations
* Description:
    * Step 1: The project utilizes Azure DevOps pipelines and helper scripts (Bash) to automate the deployment and management of Azure Databricks infrastructure and Databricks Asset Bundles.
    * Step 2: Several helper scripts, such as `bundle-deploy.sh`, `bundle-destroy.sh`, `create-ms-catalognschema-sepstor.sh`, `create-ms-externlocation.sh`, etc., are designed to be called from Azure DevOps pipelines.
    * Step 3: These scripts are parameterized to accept sensitive information, including the `clientsecret` of the `adb-sc` service principal, as command-line arguments.
    * Step 4: Pipeline definitions like `bundle_adb_360/pipelines/azure/init-pipeline.yml` and `iac-adb-360/pipelines/azure/bootstrap-ucdbs.yml` pass variables from variable groups as arguments to these shell scripts via `AzureCLI@2` task.
    * Step 5: While variable groups are intended to securely manage secrets in Azure DevOps, the practice of passing secrets as command-line arguments to shell scripts introduces a risk of exposure.
    * Step 6: An attacker with access to the Azure DevOps project's pipeline execution logs or with the ability to intercept the execution environment could potentially retrieve the service principal secret.
    * Step 7: Gain unauthorized access to the Azure DevOps project, specifically to the pipeline execution history.
    * Step 8: Inspect the logs of any pipeline execution that uses the `AzureCLI@2` task and calls one of the vulnerable helper scripts (e.g., `bundle-deploy.sh`, `create-ms-catalognschema-sepstor.sh`).
    * Step 9: Search the logs for the command-line arguments passed to the script.
    * Step 10: If the pipeline is misconfigured or logging is overly verbose, the service principal secret (`clientsecret`) might be logged as part of the arguments to the shell script execution.
* Impact:
    * **High Impact**: If the service principal secret (`clientsecret` for `adb-sc`) is exposed, an attacker can use these credentials to authenticate as the `adb-sc` service principal.
    * This service principal is used for interacting with the Azure Databricks workspace and account, as indicated in `/iac-adb-360/README.md`.
    * With these credentials, an attacker could gain unauthorized access to the Databricks workspace, potentially:
        * Accessing and manipulating data stored in Databricks and connected storage accounts.
        * Modifying Databricks configurations and settings.
        * Deploying malicious code or bundles within the Databricks environment.
        * Elevating privileges within the Databricks environment if the service principal has excessive permissions.
        * Potentially pivoting to other Azure resources if the service principal has broader permissions than intended.
* Vulnerability Rank: High
* Currently Implemented Mitigations:
    * **Usage of Azure DevOps Variable Groups**: The project uses Azure DevOps variable groups (e.g., `vgdevadb360`, `vgprdadb360`) to manage secrets like `clientsecret`. This is a standard practice for secret management in Azure DevOps and prevents hardcoding secrets directly in pipeline YAML files. (See files like `/iac-adb-360/pipelines/azure/deploy-postmetastore.yml` and `/bundle_adb_360/pipelines/azure/init-pipeline.yml`).
    * **Secret Variable Type in Variable Groups**: Azure DevOps allows defining variables as "secret," which masks their values in the UI and potentially in logs (depending on logging verbosity). It's assumed that `clientsecret` is configured as a secret variable in the variable groups. (See `/code/walkthroughs/09_crete-var-group.md` step 2).
* Missing Mitigations:
    * **Avoid Passing Secrets as Command-Line Arguments**: The most significant missing mitigation is avoiding the practice of passing secrets as command-line arguments to shell scripts. Even with secret variables in Azure DevOps, passing them as arguments makes them potentially visible in execution logs and process listings.
    * **Secure Logging Practices**: Implement stricter logging practices in Azure DevOps pipelines to ensure that even if secrets are inadvertently passed in arguments, they are not logged in plain text. Review pipeline settings to minimize log verbosity where possible, especially for tasks that handle secrets.
    * **Least Privilege for Service Principal**: While not directly related to secret exposure in logs, ensure the `adb-sc` service principal is granted only the minimum necessary permissions to perform its intended tasks. Overly broad permissions amplify the impact of secret exposure. Regularly review and refine service principal role assignments.
    * **Azure Key Vault for Secret Management**: Consider using Azure Key Vault to manage service principal secrets. Pipelines can securely retrieve secrets from Key Vault at runtime without exposing them as command-line arguments or storing them directly in variable groups. Azure DevOps has built-in tasks for interacting with Key Vault.
* Preconditions:
    * **Azure DevOps Project Access**: An attacker needs some level of unauthorized access to the Azure DevOps project. This could be read-only access to view pipeline execution history or more privileged access to modify pipeline definitions or execution environments.
    * **Misconfigured Pipeline Logging or Interceptable Execution Environment**: The vulnerability is more easily exploitable if pipeline logging is configured to be verbose, or if the attacker can intercept the execution environment where the shell script is running to capture the command-line arguments.
* Source Code Analysis:
    * **Helper Scripts Accepting `clientsecret` as Argument**:
        * Examine scripts in `/code/iac-adb-360/helpers/` and `/code/bundle_adb_360/helpers/`.
        * Scripts like `bundle-deploy.sh`, `create-ms-catalognschema-sepstor.sh`, `create-cluster.sh`, etc., take parameters as `$1`, `$2`, `$3`, `$4`...
        *  The parameter order in these scripts corresponds to the arguments passed from the pipeline definitions.
        *  For example, in `bundle-deploy.sh`:
        ```bash
        clientsecret=$4 #'<<none>>'
        ```
        * This line clearly indicates that the 4th argument passed to the script is intended to be the `clientsecret`.

    * **Pipeline Definitions Passing Secrets as Arguments**:
        * Examine pipeline YAML files in `/code/iac-adb-360/pipelines/azure/` and `/code/bundle_adb_360/pipelines/azure/`.
        * Files like `bundle_adb_360/pipelines/azure/init-pipeline.yml` and `iac-adb-360/pipelines/azure/bootstrap-ucdbs.yml` use the `AzureCLI@2` task to execute shell scripts.
        * Within the `inputs: arguments:` section of the `AzureCLI@2` task, variables from variable groups (e.g., `$(resourceGroupName)`, `$(tenantId)`, `$(clientId)`, `$(clientSecret)`, `$(env)`) are passed as arguments to the shell scripts.
        * Example from `bundle_adb_360/pipelines/azure/init-pipeline.yml`:
        ```yaml
            - task: AzureCLI@2
              displayName: 'call script to deploy bundle'
              inputs:
                azureSubscription: 'adb-sc'
                scriptType: 'bash'
                scriptLocation: 'scriptPath'
                scriptPath: './bundle_adb_360/helpers/bundle-deploy.sh'
                arguments: '$(resourceGroupName) $(tenantId) $(clientId) $(clientSecret) $(env)'
        ```
        *  Here, `$(clientSecret)` variable, which is assumed to be a secret variable from the variable group, is passed as the 4th argument to `bundle-deploy.sh`.

    ```mermaid
    graph LR
        ADO_Pipeline[Azure DevOps Pipeline Definition (YAML)] --> AzureCLI_Task[AzureCLI@2 Task];
        AzureCLI_Task --> Helper_Script[Helper Script (e.g., bundle-deploy.sh)];
        AzureCLI_Task -- arguments: '$(clientSecret)' --> Helper_Script;
        Helper_Script -- Parameter $4 is clientsecret --> Vulnerability[Potential Secret Exposure in Logs/Environment];
    ```
* Security Test Case:
    1. **Prerequisites**:
        * Access to an Azure DevOps project where the pipelines from the provided project files are configured and running. You need at least "Read" permissions on pipelines to view execution history and logs. If you have "Write" permissions, you can modify pipeline definitions for testing.
        * Identify a pipeline execution that calls a vulnerable helper script (e.g., `bundle_adb_360/pipelines/azure/init-pipeline.yml` execution that calls `bundle-deploy.sh`).
    2. **Steps**:
        * Navigate to the Azure DevOps project and go to the "Pipelines" section.
        * Find a recent execution of a pipeline that calls a vulnerable helper script (e.g., `init-pipeline`).
        * Open the pipeline execution details and navigate to the task that executes the `AzureCLI@2` task (e.g., "call script to deploy bundle").
        * Examine the logs for this task. Look for the command-line execution details, which often include the full command with arguments passed to the Azure CLI and the shell script.
        * Search within the logs for the string `clientSecret=` or any similar indication of the `clientSecret` variable being passed as an argument.
        * If the logging is verbose enough or if the secret masking is not effective, you might find the `clientSecret` value logged in plain text as part of the command-line arguments.
    3. **Expected Result**:
        * **Vulnerable**: If the `clientSecret` value is found in the pipeline execution logs (even partially masked or in a verbose log), the vulnerability is confirmed. This demonstrates that the secret is being passed as a command-line argument and is potentially exposed.
        * **Not Vulnerable (Mitigated - if masking is effective in logs but still passing as argument is bad practice)**: If the `clientSecret` is not found in the logs (properly masked in logs by Azure DevOps), the immediate risk of log exposure is mitigated by Azure DevOps secret masking. However, the underlying practice of passing secrets as command-line arguments is still a security concern and should be addressed by changing the approach to secret handling. In this case, the vulnerability is partially mitigated by Azure DevOps features but not fully addressed in the project's design.