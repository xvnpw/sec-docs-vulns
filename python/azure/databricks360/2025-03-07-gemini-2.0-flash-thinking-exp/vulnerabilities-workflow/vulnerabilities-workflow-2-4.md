* Vulnerability Name: Hardcoded Service Principal Secret in Helper Scripts and Pipeline Configurations
* Description:
    * The project utilizes Azure DevOps pipelines and helper scripts (Bash) to automate the deployment and management of Azure Databricks infrastructure and Databricks Asset Bundles.
    * Several helper scripts, such as `bundle-deploy.sh`, `bundle-destroy.sh`, `create-ms-catalognschema-sepstor.sh`, `create-ms-externlocation.sh`, etc., are designed to be called from Azure DevOps pipelines.
    * These scripts are parameterized to accept sensitive information, including the `clientsecret` of the `adb-sc` service principal, as command-line arguments.
    * Pipeline definitions like `bundle_adb_360/pipelines/azure/init-pipeline.yml` and `iac-adb-360/pipelines/azure/bootstrap-ucdbs.yml` pass variables from variable groups as arguments to these shell scripts via `AzureCLI@2` task.
    * While variable groups are intended to securely manage secrets in Azure DevOps, the practice of passing secrets as command-line arguments to shell scripts introduces a risk of exposure.
    * An attacker with access to the Azure DevOps project's pipeline execution logs or with the ability to intercept the execution environment could potentially retrieve the service principal secret.
    * Step-by-step to trigger vulnerability:
        1. Gain unauthorized access to the Azure DevOps project, specifically to the pipeline execution history.
        2. Inspect the logs of any pipeline execution that uses the `AzureCLI@2` task and calls one of the vulnerable helper scripts (e.g., `bundle-deploy.sh`, `create-ms-catalognschema-sepstor.sh`).
        3. Search the logs for the command-line arguments passed to the script.
        4. If the pipeline is misconfigured or logging is overly verbose, the service principal secret (`clientsecret`) might be logged as part of the arguments to the shell script execution.

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

    * **Visualization:**

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