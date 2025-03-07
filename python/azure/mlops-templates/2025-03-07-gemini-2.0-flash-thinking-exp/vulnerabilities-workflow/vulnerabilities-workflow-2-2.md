- Vulnerability Name: Exposure of Client Secret in Terraform Configurations
  - Description: The Terraform templates `/code/templates/infra/run-terraform-apply.yml` and `/code/templates/infra/run-terraform-plan.yml` use an Azure DevOps variable `CLIENT_SECRET` to pass the client secret to Terraform. This variable is passed as a command-line argument to Terraform: `-var "client_secret=$(CLIENT_SECRET)"`. If the Azure DevOps pipeline configuration or logs are not properly secured, or if the `CLIENT_SECRET` variable is not handled as a secret within Azure DevOps, it could be exposed to unauthorized users. An attacker with access to the pipeline definition or logs could potentially retrieve the client secret.
  - Impact: If the client secret is compromised, an attacker could use it to authenticate as the service principal associated with the Azure service connection `ado_service_connection_rg`. This could allow the attacker to manage Azure resources within the subscription, potentially leading to data breaches, resource manipulation, or denial of service.
  - Vulnerability Rank: High
  - Currently Implemented Mitigations: None in the provided code. Azure DevOps itself provides mechanisms to mark variables as secret, which prevents them from being displayed in logs, but this is a configuration outside of the provided code.
  - Missing Mitigations: The templates should avoid directly passing secrets as command-line arguments. Instead, Terraform should be configured to retrieve the client secret from a more secure source, such as Azure Key Vault or Azure DevOps secret store in a more secure way (not as `-var` in command line).  Ideally, Managed Identity should be used to avoid secrets management.
  - Preconditions:
    - An Azure DevOps service connection `ado_service_connection_rg` is configured using a service principal that requires a client secret.
    - The Azure DevOps pipeline is configured to use the Terraform templates and the `CLIENT_SECRET` variable is populated with the service principal's client secret.
    - An attacker gains access to the Azure DevOps pipeline definition or pipeline execution logs.
  - Source Code Analysis:
    - File: `/code/templates/infra/run-terraform-apply.yml`
      ```yaml
      steps:
        - task: TerraformTaskV2@2
          displayName: 'Terraform apply'
          inputs:
            provider: 'azurerm'
            command: 'apply'
            workingDirectory: '$(System.DefaultWorkingDirectory)/$(terraform_workingdir)'
            commandOptions: '-var "location=$(location)" -var "prefix=$(namespace)" -var "postfix=$(postfix)" -var "environment=$(environment)" -var "enable_aml_computecluster=$(enable_aml_computecluster)" -var "enable_monitoring=$(enable_monitoring)" -var "client_secret=$(CLIENT_SECRET)"'
            environmentServiceNameAzureRM: '$(ado_service_connection_rg)'
      ```
    - File: `/code/templates/infra/run-terraform-plan.yml`
      ```yaml
      steps:
        - task: TerraformTaskV2@2
          displayName: 'Terraform plan'
          inputs:
            provider: 'azurerm'
            command: 'plan'
            workingDirectory: '$(System.DefaultWorkingDirectory)/$(terraform_workingdir)'
            commandOptions: '-var "location=$(location)" -var "prefix=$(namespace)" -var "postfix=$(postfix)" -var "environment=$(environment)" -var "enable_aml_computecluster=$(enable_aml_computecluster)" -var "enable_monitoring=$(enable_monitoring)" -var "client_secret=$(CLIENT_SECRET)"'
            environmentServiceNameAzureRM: '$(ado_service_connection_rg)'
      ```
      In both files, the `commandOptions` input for the `TerraformTaskV2@2` task includes `-var "client_secret=$(CLIENT_SECRET)"`. This directly passes the value of the `CLIENT_SECRET` Azure DevOps variable to Terraform as a variable named `client_secret`.
  - Security Test Case:
    1. Set up an Azure DevOps project and pipeline.
    2. Configure an Azure service connection `ado_service_connection_rg` using a service principal with a client secret.
    3. Define a pipeline variable named `CLIENT_SECRET` and set its value to the client secret of the service principal. Mark the variable as *not* secret for testing purposes to ensure it is visible in logs (in real scenario it would be secret, but still passed as command line arg).
    4. Create a pipeline stage that uses the `/code/templates/infra/run-terraform-apply.yml` or `/code/templates/infra/run-terraform-plan.yml` template.
    5. Run the pipeline.
    6. Examine the pipeline execution logs for the Terraform task.
    7. Verify that the client secret is visible in the logs as part of the Terraform command line arguments, e.g., `-var "client_secret=YOUR_CLIENT_SECRET"`.