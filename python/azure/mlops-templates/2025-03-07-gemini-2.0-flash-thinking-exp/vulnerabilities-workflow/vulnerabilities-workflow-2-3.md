#### 1. Misconfigured Azure DevOps Service Connections Leading to Unauthorized Azure Resource Access
* Description:
    1. Several Azure DevOps pipeline templates in this project rely on Azure Service Connections (e.g., `ado_service_connection_aml_ws`, `ado_service_connection_rg`) to authenticate with Azure and manage resources.
    2. An attacker could exploit misconfigurations in these service connections if they are granted overly broad permissions in Azure Active Directory or are scoped to the wrong Azure subscription or resource group.
    3. For example, if `ado_service_connection_rg` has "Contributor" role at the subscription level instead of resource group level, pipelines using this connection could potentially manage resources outside of the intended resource group.
    4. Similarly, if the service principal associated with the service connection has excessive permissions, an attacker who gains access to the Azure DevOps project or pipeline execution context could leverage these permissions to perform unauthorized actions on Azure resources.
* Impact:
    - Unauthorized access to Azure Machine Learning workspaces and related resources (storage accounts, compute clusters, endpoints, etc.).
    - Data exfiltration or modification from storage accounts.
    - Unauthorized modification or deletion of ML models, endpoints, and deployments.
    - Resource manipulation leading to service disruption or financial impact.
* Vulnerability rank: High
* Currently implemented mitigations: None in the provided code templates. The security relies on the user correctly configuring Azure DevOps service connections.
* Missing mitigations:
    - Documentation and guidance on the principle of least privilege for service connection configuration.
    - Validation or checks within the templates to warn users about overly permissive service connection configurations (though this might be difficult to implement directly within YAML templates).
    - Security scanning or policy enforcement at the Azure DevOps organization or Azure subscription level to detect and remediate overly permissive service connections.
* Preconditions:
    - The user deploys MLOps infrastructure using the provided templates.
    - Azure DevOps service connections (`ado_service_connection_aml_ws`, `ado_service_connection_rg`) are created with overly permissive roles or incorrect scope.
    - An attacker gains access to the Azure DevOps project or pipeline execution context (e.g., through compromised credentials, insider threat, or supply chain attack).
* Source code analysis:
    - Files like `/code/templates/aml-cli-v2/create-deployment.yml`, `/code/templates/python-sdk-v2/create-online-endpoint.yml`, `/code/templates/infra/run-terraform-apply.yml` all use `azureSubscription` input, which refers to Azure DevOps service connection.
    - The `AzureCLI@2` and `TerraformTaskV2@2` tasks use this service connection to authenticate with Azure.
    - Example from `/code/templates/aml-cli-v2/create-deployment.yml`:
      ```yaml
      steps:
        - task: AzureCLI@2
          displayName: Create deployment
          inputs:
            azureSubscription: $(ado_service_connection_rg) #needs to have access at the RG level
            scriptType: bash
            scriptLocation: inlineScript
            inlineScript: |
              # ... Azure CLI commands to create deployment ...
      ```
    - If `ado_service_connection_rg` is misconfigured to have subscription-level "Contributor" role, the Azure CLI commands in `inlineScript` will have excessive permissions.
* Security test case:
    1. **Setup**:
        - Create an Azure DevOps project and organization.
        - Deploy the MLOps templates to this project.
        - Intentionally misconfigure the `ado_service_connection_rg` service connection by granting it "Contributor" role at the subscription level instead of resource group level.
        - Create a pipeline using `/code/templates/aml-cli-v2/create-deployment.yml`.
    2. **Execution**:
        - Run the pipeline. Observe that the deployment is created successfully (as expected).
        - Now, manually try to use the same service connection (or the underlying service principal) to perform an action outside the intended resource group, for example, delete a resource group in a different subscription or resource group.
        - If the service connection is indeed overly permissive, the unauthorized action will succeed.
    3. **Expected Result**:
        - The test should demonstrate that with a misconfigured service connection, it is possible to perform actions on Azure resources beyond the intended scope, proving the vulnerability.