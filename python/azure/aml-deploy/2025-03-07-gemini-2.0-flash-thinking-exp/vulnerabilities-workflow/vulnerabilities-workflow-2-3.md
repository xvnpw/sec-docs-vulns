- Vulnerability Name: Exposure of Azure Credentials through GitHub Secrets
- Description:
    - An attacker who gains unauthorized access to a GitHub repository's secrets can retrieve the `AZURE_CREDENTIALS` secret.
    - This secret contains sensitive Azure service principal credentials, including `clientId`, `clientSecret`, `subscriptionId`, and `tenantId`.
    - With these credentials, the attacker can authenticate to the victim's Azure subscription and resource group.
    - Once authenticated, the attacker can leverage the "Contributor" role associated with the service principal to interact with Azure resources, specifically the Azure Machine Learning workspace.
    - The attacker can then deploy malicious machine learning models to the victim's Azure Machine Learning workspace using the compromised credentials and the `aml-deploy` action or directly via Azure SDK/CLI.
- Impact:
    - **Unauthorized Access to Data:** Malicious models deployed by the attacker could be designed to exfiltrate sensitive data processed by the Azure Machine Learning workspace or access other data within the Azure environment.
    - **Service Disruption:** Attackers can replace legitimate models with malicious or malfunctioning ones, disrupting critical services that rely on these models. This can lead to incorrect predictions, system failures, and reputational damage.
    - **Resource Manipulation:** The attacker might be able to manipulate other Azure resources within the resource group, potentially leading to further security breaches, denial of service, or unexpected financial costs for the victim.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - **Secret Masking:** The `mask_parameter` function in `code/utils.py` is used in `code/main.py` to mask the `azure_credentials` (tenantId, clientId, clientSecret, subscriptionId) in the GitHub Action logs. This prevents accidental exposure of the secret in logs.
    - **Documentation on Secret Management:** The `README.md` file provides instructions on how to create and store `AZURE_CREDENTIALS` as a GitHub secret, guiding users towards secure secret management practices within GitHub Actions.
- Missing Mitigations:
    - **Secret Rotation Policy:** The project lacks guidance or mechanisms for regular rotation of the `AZURE_CREDENTIALS` secret. Implementing a secret rotation policy would reduce the window of opportunity if the secret is compromised.
    - **Principle of Least Privilege for Service Principal:** The documentation recommends granting the "Contributor" role to the service principal at the resource group scope. This might be overly permissive. The principle of least privilege should be applied by recommending a custom role with only the necessary permissions for deploying models within the specific Azure Machine Learning workspace, limiting the potential impact of credential compromise.
    - **GitHub Secret Scanning Awareness:** The documentation does not mention or encourage users to utilize GitHub's secret scanning feature or similar tools to proactively detect accidental commits or exposure of the `AZURE_CREDENTIALS` secret.
- Preconditions:
    - The victim organization uses the `aml-deploy` GitHub Action in their CI/CD workflows to automate model deployment to Azure Machine Learning.
    - The victim has correctly configured the `AZURE_CREDENTIALS` secret in their GitHub repository as per the action's documentation.
    - An attacker gains unauthorized access to the GitHub repository's secrets. This could be due to various reasons, including but not limited to: compromised developer accounts, vulnerabilities in GitHub's platform, or insider threats.
- Source Code Analysis:
    1. **`code/main.py` - Secret Loading and Masking:**
        - Line 39: `azure_credentials = os.environ.get("INPUT_AZURE_CREDENTIALS", default="{}")` - The action retrieves the Azure credentials from the `INPUT_AZURE_CREDENTIALS` environment variable, which is expected to be set by GitHub Actions from the repository's secrets.
        - Line 58-61: `mask_parameter(parameter=azure_credentials.get("tenantId", ""))`, `mask_parameter(parameter=azure_credentials.get("clientId", ""))`, `mask_parameter(parameter=azure_credentials.get("clientSecret", ""))`, `mask_parameter(parameter=azure_credentials.get("subscriptionId", ""))` -  The code utilizes the `mask_parameter` function from `utils.py` to mask the sensitive parts of the `azure_credentials` in the logs. This is a positive security measure to prevent accidental logging of the secret.
    2. **`code/utils.py` - Masking Implementation:**
        - Line 17-18: `def mask_parameter(parameter):` and `print(f"::add-mask::{parameter}")` - The `mask_parameter` function uses the GitHub Actions command `::add-mask::` to instruct the Actions runner to mask the provided `parameter` in the logs. This mitigation is in place to reduce the risk of secret leakage through logs.
    3. **`action.yml` - Input Definition:**
        - Inputs section: `azure_credentials` input is defined with `required: true` and description guiding users to store the output of `az ad sp create-for-rbac` as a secret named `AZURE_CREDENTIALS`. This highlights the reliance on GitHub secrets for secure credential injection.

- Security Test Case:
    1. **Setup:**
        - Create a private GitHub repository to simulate a victim's repository.
        - Set up an Azure Machine Learning workspace (can be a trial or sandbox workspace for testing).
        - Create an Azure service principal with "Contributor" role at the resource group level of the AML workspace.
        - In the GitHub repository, configure `AZURE_CREDENTIALS` as a repository secret, pasting the JSON output from `az ad sp create-for-rbac ...`.
        - Create a simple GitHub Actions workflow (e.g., `.github/workflows/test-secret-exposure.yml`) that uses the `aml-deploy` action. The workflow should be triggered manually.
        - Add an additional step in the workflow definition after the `aml-deploy` action step. This step will attempt to explicitly print the `AZURE_CREDENTIALS` secret to the logs to verify if it's accessible within the workflow context (for demonstration purposes only, not recommended in production). A safer alternative for verification is to attempt an authenticated Azure operation.
    2. **Execution:**
        - Manually trigger the `Test Secret Exposure` workflow in the GitHub repository.
    3. **Verification:**
        - **Check Workflow Logs:** Examine the logs of the "Attempt Secret Access" step. While the `secrets.AZURE_CREDENTIALS` value might be masked by GitHub Actions in the logs UI, the step itself executes within the workflow environment and has access to the secret. The "Verify Azure Authentication" step will confirm if the credentials can be used to successfully authenticate with Azure.
        - **Simulate Attacker Access:** Imagine an attacker who has gained read access to the repository's workflows and logs (e.g., through compromised CI/CD pipeline or monitoring tools). They could potentially reconstruct or infer the secret value or directly use the workflow environment to perform actions using the compromised credentials.
    4. **Expected Result:**
        - The "Verify Azure Authentication" step should succeed, demonstrating that the `AZURE_CREDENTIALS` secret, when configured for the `aml-deploy` action, is indeed accessible within the workflow run environment. This confirms that if an attacker compromises the GitHub repository's secrets, they can retrieve and misuse these Azure credentials to perform actions in the victim's Azure subscription, including deploying malicious models as described in the vulnerability description.