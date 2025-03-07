- **Vulnerability Name:** Insecure storage of Azure credentials in GitHub Secrets
- **Description:**
    1. The Azure Machine Learning Workspace GitHub Action requires users to store sensitive Azure credentials (clientId, clientSecret, tenantId, subscriptionId) as a GitHub secret named `AZURE_CREDENTIALS`.
    2. These credentials, obtained using `az ad sp create-for-rbac`, grant broad contributor access to the specified Azure subscription and resource group.
    3. If an attacker gains access to the GitHub repository's secrets (e.g., through compromised developer accounts, repository misconfigurations, or GitHub platform vulnerabilities), they can retrieve the `AZURE_CREDENTIALS` secret.
    4. With these stolen credentials, the attacker can authenticate to Azure and gain unauthorized contributor-level access to the Azure Machine Learning workspace and potentially other resources within the specified subscription and resource group.
- **Impact:**
    - **High:** Unauthorized access to the Azure Machine Learning workspace.
    - Potential data breach or manipulation of machine learning models, datasets, and experiments within the workspace.
    - Resource hijacking and unauthorized usage of Azure resources within the subscription.
    - Lateral movement to other Azure services if the service principal has broader permissions.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - **Input Validation:** The action validates the structure of the `AZURE_CREDENTIALS` JSON input against a schema (`azure_credentials_schema` in `/code/code/schemas.py`) to ensure it contains the required fields (clientId, clientSecret, subscriptionId, tenantId). This helps to detect basic configuration errors but does not prevent secret compromise.
    - **Secret Masking:** The action uses `utils.mask_parameter` function in `/code/code/utils.py` to mask the `tenantId`, `clientId`, `clientSecret`, and `subscriptionId` in the GitHub Actions logs. This prevents the secrets from being directly displayed in the logs if masking is effective.
- **Missing Mitigations:**
    - **Secret Rotation:** The action does not provide any mechanism or guidance for rotating the `AZURE_CREDENTIALS` secret regularly. Stale credentials increase the window of opportunity for attackers if secrets are compromised.
    - **Principle of Least Privilege:** The action encourages the use of contributor role for the service principal, which grants broad permissions.  The action lacks guidance or features to configure more granular, least privilege access for the service principal, limiting the potential impact of credential compromise.
    - **Alternative Authentication Methods:** The action relies solely on service principal credentials stored as GitHub secrets. It does not offer or recommend alternative, potentially more secure authentication methods like workload identity or managed identities, which could reduce the risk of secret exposure.
    - **Secret Scanning and Leakage Detection:** The action itself does not include any mechanisms to detect if the `AZURE_CREDENTIALS` secret has been accidentally leaked (e.g., committed to code, exposed in logs before masking).
- **Preconditions:**
    1. The user must configure the GitHub Action in their workflow and store Azure service principal credentials as a GitHub secret named `AZURE_CREDENTIALS`.
    2. An attacker must gain access to the GitHub repository's secrets.
- **Source Code Analysis:**
    - **`/code/action.yml`**: Defines `azure_credentials` as a required input, explicitly instructing users to store sensitive credentials as a GitHub secret.
    - **`/code/main.py`**:
        ```python
        azure_credentials = os.environ.get("INPUT_AZURE_CREDENTIALS", default="{}")
        try:
            azure_credentials = json.loads(azure_credentials)
        except JSONDecodeError:
            # ... error message ...
            raise AMLConfigurationException(...)

        validate_json(
            data=azure_credentials,
            schema=azure_credentials_schema,
            input_name="AZURE_CREDENTIALS"
        )

        mask_parameter(parameter=azure_credentials.get("tenantId", ""))
        mask_parameter(parameter=azure_credentials.get("clientId", ""))
        mask_parameter(parameter=azure_credentials.get("clientSecret", ""))
        mask_parameter(parameter=azure_credentials.get("subscriptionId", ""))

        sp_auth = ServicePrincipalAuthentication(
            tenant_id=azure_credentials.get("tenantId", ""),
            service_principal_id=azure_credentials.get("clientId", ""),
            service_principal_password=azure_credentials.get("clientSecret", ""),
            cloud=cloud
        )
        ```
        - The code retrieves `AZURE_CREDENTIALS` from the environment variables, which is how GitHub Actions secrets are passed to actions.
        - It parses the secret as JSON and validates it.
        - It attempts to mask the secret components using `mask_parameter` *after* retrieving and parsing it.
        - It uses the unmasked secret components to create `ServicePrincipalAuthentication`.
    - **`/code/utils.py`**:
        ```python
        def mask_parameter(parameter):
            print(f"::add-mask::{parameter}")
        ```
        - The `mask_parameter` function uses the GitHub Actions command `::add-mask::` to mask the provided parameter in logs. This relies on GitHub Actions' log processing to be effective.

- **Security Test Case:**
    1. **Setup:**
        - Create a public GitHub repository.
        - Create an Azure Machine Learning workspace and a service principal with contributor access to the resource group containing the workspace, as described in the action's README.
        - Add the JSON output of `az ad sp create-for-rbac` as a GitHub secret named `AZURE_CREDENTIALS` in the repository settings.
        - Create a GitHub workflow in the repository that uses the `Azure/aml-workspace@v1` action, providing the `AZURE_CREDENTIALS` secret as input.
        - Add a step after the `aml-workspace` action that attempts to echo the `AZURE_CREDENTIALS` secret or parts of it (e.g., `echo ${{ secrets.AZURE_CREDENTIALS }}`).  *(Note: GitHub Actions prevents secrets from being directly echoed in logs, this step is for demonstration of access within the workflow context)*.
    2. **Execution:**
        - Run the GitHub workflow (e.g., by pushing a commit to the repository).
    3. **Verification:**
        - Observe the workflow logs.
        - While the direct echo of `secrets.AZURE_CREDENTIALS` will be masked by GitHub Actions, the action itself successfully uses the `AZURE_CREDENTIALS` to authenticate to Azure and configure the workspace. This confirms that the secret is accessible within the workflow environment where the action runs.
        - To simulate secret retrieval by an attacker who has gained access to repository secrets (outside of the workflow log masking), one could potentially use the GitHub API (if permissions allow) or other means to access the stored secrets if repository security is compromised.  *(Note: Directly demonstrating secret retrieval from GitHub secrets store is typically not possible for external testers due to security controls, but the test case demonstrates the action's reliance on and access to the secret within the workflow context, highlighting the inherent risk if secrets are compromised at the repository level)*.
    4. **Conclusion:**
        - The test case demonstrates that the action relies on and successfully uses the `AZURE_CREDENTIALS` GitHub secret to authenticate to Azure. If an attacker compromises the GitHub repository secrets, they could potentially gain access to these credentials and thus unauthorized access to the Azure Machine Learning workspace. This confirms the vulnerability related to insecure storage and potential compromise of Azure credentials through GitHub Secrets.