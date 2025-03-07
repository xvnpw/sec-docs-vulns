### Vulnerability List

- Vulnerability Name: Overly Permissive Service Principal Roles
  - Description:
    1. A user forks the repository to build custom Dev Box images.
    2. Following the documentation, the user creates an Azure Service Principal to allow GitHub Actions workflow to interact with Azure.
    3. The documentation suggests granting either "Contributor" role on the entire subscription OR "Owner" on a specific resource group and "Contributor" on the Azure Compute Gallery.
    4. A user, misunderstanding the principle of least privilege or due to convenience, grants the "Owner" role at the subscription level to the Service Principal, instead of the least privileged option.
    5. An attacker gains unauthorized access to the forked repository. This could be through various means such as compromising a maintainer's GitHub account, exploiting a vulnerability in the GitHub Actions workflow, or social engineering.
    6. Once the attacker has repository access, they can potentially access the `AZURE_CREDENTIALS` secret, either directly (if repository secrets are misconfigured or accessible in forks, which is unlikely but worth considering) or indirectly by modifying the workflow to exfiltrate the secret (e.g., printing it to logs, sending it to an external endpoint).
    7. With the leaked `AZURE_CREDENTIALS` and the overly permissive "Owner" role, the attacker can now authenticate as the Service Principal and perform any action within the Azure subscription.
  - Impact:
    - Complete control over the Azure subscription granted to the Service Principal.
    - Ability to create, modify, and delete any Azure resources within the subscription.
    - Potential for data exfiltration from Azure services (e.g., Storage Accounts, Databases).
    - Possibility of denial-of-service by deleting critical resources.
    - Lateral movement to other Azure resources or subscriptions if the compromised subscription has further access.
  - Vulnerability Rank: High
  - Currently Implemented Mitigations:
    - Documentation in `/code/README.md` mentions the **minimum required roles**: "Contributor" on the subscription OR "Owner" on a specific resource group and "Contributor" on the [Azure Compute Gallery][az-gallery] (and its resource group). This serves as a documentation-based guidance to users.
  - Missing Mitigations:
    - **Least Privilege Enforcement Guidance:**  The documentation should strongly emphasize the principle of least privilege and explicitly recommend granting the least permissive roles necessary. Provide clear steps and examples for creating a custom role with the minimal required permissions instead of suggesting broad built-in roles like "Contributor" or "Owner" on the subscription.
    - **Role Validation Automation:** Implement automated checks within the GitHub Actions workflow to validate the effective roles assigned to the Service Principal. The workflow could query Azure to determine the roles assigned to the Service Principal and issue a warning or fail the workflow if overly permissive roles like "Owner" at the subscription level are detected.
    - **Secret Scanning Implementation:** Integrate secret scanning tools within the repository to proactively detect accidental commits of sensitive information, including potential credentials.
    - **Enhanced Documentation Prominence:**  Make the security considerations and least privilege recommendations more prominent in the README.md, possibly by adding a dedicated "Security Considerations" section at the beginning of the document.
  - Preconditions:
    - User forks the repository.
    - User creates an Azure Service Principal.
    - User grants overly permissive Azure roles (e.g., Owner role on the entire subscription) to the Service Principal.
    - User configures the `AZURE_CREDENTIALS` repository secret in their forked repository with the Service Principal credentials.
    - Attacker gains unauthorized access to the forked repository.
  - Source Code Analysis:
    - `/code/README.md`: The file provides instructions on setting up the Service Principal and assigning roles.
    ```markdown
    **IMPORTANT: Once you create a new Service Principal you must [assign it the following roles in RBAC][assign-rbac]:**:

    - **Contributor** on the subscription used to provision resources, **OR**
    - **Owner** on a specific (existing) resource group (see [Resource Group Usage](#resource-group-usage) below) and **Contributor** on the [Azure Compute Gallery][az-gallery] (and its resource group)
    ```
    - The documentation, while mentioning roles, does not explicitly warn against granting overly broad permissions like "Owner" on the subscription and doesn't guide towards creating a least privilege custom role.
    - No code within the provided project files (YAML configurations or Python scripts) actively checks or enforces the principle of least privilege for the Service Principal. The scripts are designed to function with valid Azure credentials, assuming the user has configured them correctly.
  - Security Test Case:
    1. **Setup:**
        - Fork the repository.
        - Create an Azure Service Principal.
        - **Grant the "Owner" role** to the Service Principal at the subscription level in Azure.
        - Configure the `AZURE_CREDENTIALS` repository secret in your forked repository with the Service Principal's credentials (clientId, clientSecret, tenantId, subscriptionId).
        - Modify any file in the `/images` or `/scripts` directory to trigger the GitHub Actions workflow defined in `.github/workflows/build_images.yml`. This will execute the image build process using the configured Service Principal.
    2. **Simulate Repository Compromise and Secret Exfiltration:**
        - Assume an attacker gains access to your forked repository.
        - **Modify the GitHub Actions workflow** `.github/workflows/build_images.yml` to exfiltrate the `AZURE_CREDENTIALS` secret. Add a step to print the secret to the workflow logs for demonstration purposes:
        ```yaml
        steps:
          - name: Checkout code
            uses: actions/checkout@v3
          - name: Display AZURE_CREDENTIALS Secret
            run: echo "AZURE_CREDENTIALS: ${{ secrets.AZURE_CREDENTIALS }}"
          - name: Build Images # (Original workflow step name)
            uses: ./.github/actions/build-images
            with:
              client_id: ${{ secrets.AZURE_CREDENTIALS.clientId }}
              client_secret: ${{ secrets.AZURE_CREDENTIALS.clientSecret }}
              subscription_id: ${{ secrets.AZURE_CREDENTIALS.subscriptionId }}
              tenant_id: ${{ secrets.AZURE_CREDENTIALS.tenantId }}
              repository: ${{ github.server_url }}/${{ github.repository }}
              revision: ${{ github.sha }}
              token: ${{ secrets.GITHUB_TOKEN }}
        ```
        - Commit and push the modified workflow file to your forked repository. This will trigger the workflow execution.
    3. **Retrieve Leaked Credentials:**
        - Go to the "Actions" tab in your forked repository on GitHub.
        - Find the latest workflow run triggered by your commit.
        - Examine the logs for the "Display AZURE_CREDENTIALS Secret" step. The `AZURE_CREDENTIALS` secret will be printed in the logs (obfuscated by GitHub Actions, but still retrievable by someone with repository access if not properly handled in a real exfiltration scenario). In a real attack, the secret could be sent to an attacker-controlled server instead of being printed to logs.
    4. **Demonstrate Impact - Unauthorized Azure Access:**
        - Using the leaked credentials (clientId, clientSecret, tenantId), use the Azure CLI to log in as the Service Principal:
        ```bash
        az login --service-principal -u <clientId> -p <clientSecret> --tenant <tenantId>
        ```
        - After successful login, execute Azure CLI commands to demonstrate the "Owner" level access. For example, list resource groups in the subscription:
        ```bash
        az group list
        ```
        - Or, attempt to create a new resource group:
        ```bash
        az group create -n attacker-created-rg -l eastus
        ```
        - If these commands are successful, it confirms that an attacker with the leaked `AZURE_CREDENTIALS` and the "Owner" role can perform administrative actions on the Azure subscription, demonstrating the high impact of the vulnerability.