### Vulnerability List

- Vulnerability Name: Potential Secret Exposure in Variable Groups and Pipelines
- Description:
    1. Azure DevOps (ADO) Variable Groups are used to manage sensitive information like service principal secrets and GitHub Personal Access Tokens (PATs).
    2. Pipelines in this project, such as `iac-adb-360/pipelines/azure/deploy-postmetastore.yml` and `bundle_adb_360/pipelines/azure/init-pipeline.yml`, are configured to access these Variable Groups.
    3. While Variable Groups offer a "secret" type for variables, which masks the values in the UI and logs, the secrets are still accessible to anyone with "read" access to the pipeline and variable group, or "contributor" access to the Azure DevOps project.
    4. An attacker gaining unauthorized read access to the Azure DevOps project, or through compromised credentials of a user with read pipeline permissions, could potentially view or exfiltrate these secrets.
    5. These secrets, particularly the service principal client secrets (`clientsecret`) and GitHub PAT (`ghpat`), are used to authenticate to Azure and GitHub, respectively. Exposure of these secrets would grant an attacker the ability to impersonate the service principal or GitHub user.
    6. For example, the `bundle-deploy.sh` script uses these secrets to authenticate to Azure Databricks workspace and deploy bundles. If an attacker obtains these secrets, they could deploy malicious bundles or perform other unauthorized actions within the Databricks environment.
- Impact:
    - **High Impact:** If an attacker gains access to the secrets stored in the Variable Group, they can:
        - **Unauthorized Access to Azure Databricks:** Use the `adb-sc` service principal secret to access and control the Azure Databricks workspace, potentially gaining access to data, executing arbitrary code, or disrupting operations.
        - **Unauthorized Access to GitHub Repository:** Use the `gh-sc` GitHub PAT to access the project's GitHub repository. This could allow the attacker to modify code, introduce backdoors, or leak sensitive repository information.
        - **Lateral Movement:** Depending on the permissions granted to the service principals, the attacker might be able to use these compromised credentials to move laterally to other Azure resources or systems.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - **Secret Variable Type in Azure DevOps:** Azure DevOps provides a "secret" variable type for Variable Groups. When used, the values are masked in the UI and logs. This is implemented for `clientsecret` and `ghpat` in `iac-adb-360/helpers/vargroup-create.sh`.
    - **Service Principal Least Privilege (Partial):** The service principals are intended to have Contributor rights on the resource groups, which is generally considered least privilege for infrastructure deployment. However, the potential impact of compromised credentials remains high.
- Missing Mitigations:
    - **Azure Key Vault Integration for Secrets Management:** Instead of storing secrets directly in Azure DevOps Variable Groups, integrate with Azure Key Vault. Store secrets in Key Vault and grant Azure DevOps pipelines managed identity access to retrieve secrets at runtime. This reduces the risk of secrets exposure within Azure DevOps itself.
    - **Azure DevOps Access Control Review:** Implement strict access control within Azure DevOps, ensuring only necessary personnel have "read" access to pipelines and Variable Groups. Regularly review and audit Azure DevOps permissions.
    - **Just-In-Time (JIT) Access for Azure DevOps:** Consider implementing JIT access for Azure DevOps administrative tasks, further limiting persistent access.
    - **Regular Secret Rotation:** Implement a policy for regular rotation of service principal secrets and GitHub PATs to minimize the window of opportunity if a secret is compromised.
- Preconditions:
    - An attacker needs to gain unauthorized access to the Azure DevOps project, either through compromised user credentials with read pipeline permissions or by exploiting a vulnerability in Azure DevOps itself (less likely in this context).
- Source Code Analysis:
    - **Variable Group Creation Script (`iac-adb-360/helpers/vargroup-create.sh`):**
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

    - **Pipeline Definitions (`iac-adb-360/pipelines/azure/deploy-postmetastore.yml`, `bundle_adb_360/pipelines/azure/init-pipeline.yml`, etc.):**
        ```yaml
        variables:
        - group: vgdevadb360
        ```
        Pipelines reference the Variable Group `vgdevadb360` (or `vgprdadb360`), making the variables, including secrets, available to the pipeline execution context.

    - **Bundle Deployment Script (`bundle_adb_360/helpers/bundle-deploy.sh`):**
        ```bash
        export ARM_CLIENT_ID=$clientid
        export ARM_CLIENT_SECRET=$clientsecret
        export ARM_TENANT_ID=$tenantid
        export DATABRICKS_AZURE_RESOURCE_ID=$workspaceId

        cd bundle_adb_360
        databricks bundle deploy -t $env
        ```
        This script uses environment variables `ARM_CLIENT_SECRET`, `ARM_CLIENT_ID`, and `ARM_TENANT_ID`, which are populated from the Variable Group secrets during pipeline execution, to authenticate with Azure Databricks.

- Security Test Case:
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

    **Note:** For a more realistic test scenario, an attacker might compromise a user account with pipeline read permissions or gain access through other means to the Azure DevOps project. This test case simplifies the access assumption to focus on secret exposure within the platform itself.