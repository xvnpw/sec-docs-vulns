### 1. Vulnerability Name: Insecure Azure Service Principal Credentials Management

* Description:
    1. The MLOps v2 template guides users to set up Azure infrastructure and ML pipelines using Azure DevOps or GitHub Actions.
    2. These pipelines require Azure Service Principal credentials to authenticate and authorize actions against Azure resources.
    3. The provided project files, particularly the pipeline definitions (e.g., `/code/infrastructure/bicep/pipelines/bicep-ado-deploy-infra.yml`, `/code/infrastructure/terraform/github-actions/tf-gha-deploy-infra.yml`, `/code/cv/aml-cli-v2/mlops/github-actions/deploy-model-training-pipeline.yml`, etc.), rely on templates from the `Azure/mlops-templates` repository (e.g., `uses: Azure/mlops-templates/.github/workflows/read-yaml.yml@main`, `template: templates/infra/create-resource-group.yml@mlops-templates`, etc.).
    4. If the `mlops-templates` repository contains templates that encourage or allow insecure credential management practices (e.g., hardcoding credentials in pipeline definitions, storing credentials in source code, logging credentials), users following this template may inadvertently expose their Azure Service Principal credentials.
    5. An attacker gaining access to these exposed credentials could then impersonate the Service Principal and gain unauthorized access to the Azure resources deployed by the MLOps system.

* Impact:
    - **High/Critical:** Unauthorized access to Azure resources including the Azure Machine Learning workspace, storage accounts, key vaults, container registry, and potentially other deployed services.
    - Data exfiltration: An attacker could access and download sensitive data stored in Azure Storage or used by ML models.
    - Resource manipulation: An attacker could modify or delete Azure resources, disrupt ML pipelines, inject malicious code into ML models or deployments, or use compute resources for cryptocurrency mining or other malicious activities.
    - Lateral movement: Compromised credentials could potentially be used to access other Azure subscriptions or resources if the Service Principal has overly broad permissions.

* Vulnerability Rank: Critical

* Currently Implemented Mitigations:
    - The project files utilize Azure DevOps service connections and GitHub Actions secrets (e.g., `secrets.AZURE_CREDENTIALS`, `$(ado_service_connection_rg)`). This indicates an attempt to use secure credential storage mechanisms provided by these platforms.
    - The `SECURITY.md` file encourages reporting security vulnerabilities through private channels (MSRC), not public GitHub issues.

* Missing Mitigations:
    - **Secure Credential Management Guidance:** The project lacks explicit documentation and guidance on secure credential management practices for Azure Service Principals. This should include:
        - **Principle of Least Privilege:** Guidance on creating Service Principals with only the necessary permissions (e.g., using custom roles in Azure RBAC).
        - **Secure Storage:** Strong recommendations against hardcoding credentials and clear instructions on using secure secret storage mechanisms provided by Azure DevOps/GitHub Actions (Service Connections, Secrets).
        - **Credential Rotation:** Best practices for regular rotation of Service Principal secrets.
        - **Auditing and Monitoring:** Guidance on enabling auditing and monitoring of Service Principal usage to detect suspicious activities.
    - **Secure Templates in `mlops-templates`:** The `mlops-templates` repository needs to be reviewed and hardened to ensure that templates do not introduce or encourage insecure credential management practices. Templates should:
        - **Force parameterization of credentials:** Templates should always use variables or parameters for credentials, forcing users to provide them through secure channels (Service Connections, Secrets).
        - **Avoid logging credentials:** Templates should be carefully reviewed to ensure no credentials or secrets are logged in pipeline outputs or logs.
        - **Provide secure examples:** Examples within templates and documentation should always demonstrate secure credential handling.
    - **Automated Security Checks:** Implement automated security checks (e.g., static analysis, secret scanning) in the project and in the `mlops-templates` repository to detect potential credential exposure risks.

* Preconditions:
    - Users implementing the MLOps v2 template follow insecure practices for managing Azure Service Principal credentials, either due to lack of guidance or by ignoring secure practices.
    - Vulnerable templates exist in the `Azure/mlops-templates` repository that facilitate or allow insecure credential management.
    - An attacker gains access to the insecurely managed credentials. This could happen through various means, including:
        - Access to source code repositories where credentials are hardcoded or stored insecurely.
        - Access to pipeline logs or outputs where credentials are exposed.
        - Compromise of developer machines or CI/CD systems where credentials are stored or used.

* Source Code Analysis:
    - The provided code does not directly hardcode credentials.
    - The pipeline definitions (e.g., `/code/infrastructure/bicep/pipelines/bicep-ado-deploy-infra.yml`, `/code/infrastructure/terraform/github-actions/tf-gha-deploy-infra.yml`) use variables like `ado_service_connection_rg` and `secrets.AZURE_CREDENTIALS` which suggests the intention to use secure credential management.
    - **However, the vulnerability is likely introduced by the reusable templates from `Azure/mlops-templates` repository, which are invoked by these pipeline definitions.** Without access to the `mlops-templates` repository, a direct source code analysis to pinpoint the insecure template code is not possible.
    - **Example Scenario (Hypothetical Vulnerable Template in `mlops-templates`):**
        - Assume a template in `mlops-templates` named `templates/infra/create-aml-workspace.yml` contains a task that directly embeds a Service Principal secret value retrieved from a parameter into an Azure CLI command, instead of using a secure way to pass the credential.
        - A pipeline like `/code/infrastructure/bicep/pipelines/bicep-ado-deploy-infra.yml` might then pass the Service Principal secret as a parameter to this template, inadvertently making it less secure if the template itself handles it insecurely.

* Security Test Case:
    1. **Setup:**
        - Create an Azure DevOps pipeline or GitHub Actions workflow based on the provided project files, specifically one that deploys infrastructure (e.g., `/code/infrastructure/terraform/github-actions/tf-gha-deploy-infra.yml`).
        - Configure the pipeline to use an Azure Service Principal for authentication.
        - **Hypothetical Vulnerability Injection (Simulate a vulnerable template):** Modify a template in `mlops-templates` (if possible, or create a local mock template for testing) to intentionally log the Service Principal secret value to the pipeline logs during deployment. For example, in a bash script within a template, add `echo "Service Principal Secret: $service_principal_secret"` where `$service_principal_secret` is a parameter intended to hold the secret.
    2. **Execution:**
        - Run the pipeline to deploy the Azure infrastructure.
    3. **Verification:**
        - **Check Pipeline Logs:** Examine the logs of the pipeline execution.
        - **Vulnerability Confirmation:** If the Service Principal secret value is visible in the pipeline logs (as introduced by the hypothetical vulnerable template modification), then the vulnerability is confirmed. This demonstrates that insecure templates can lead to credential exposure through pipeline logs.
    4. **Expected Result (Vulnerable Case):** The Service Principal secret will be found in plain text within the pipeline execution logs, proving the vulnerability.
    5. **Expected Result (Mitigated Case - if mitigations were in place):** The Service Principal secret should *not* be found in plain text in the pipeline logs. Secure credential handling would ensure that secrets are only passed securely and not exposed in logs or outputs.

This test case, while hypothetical due to the lack of access to `mlops-templates`, illustrates how to identify credential exposure vulnerabilities if insecure templates are present or if users are guided to implement insecure practices. To fully validate and fix this, the `mlops-templates` repository should be audited and hardened, and clear secure credential management guidance must be provided to users of this MLOps template.