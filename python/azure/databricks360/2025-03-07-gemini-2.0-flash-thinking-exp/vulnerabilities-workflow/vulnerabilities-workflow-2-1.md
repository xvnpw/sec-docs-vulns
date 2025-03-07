### Vulnerability List

* Vulnerability Name: Overly Permissive Resource Group Permissions for DevOps Service Principal
* Description:
    * Step 1: User deploys the Azure Databricks infrastructure using the provided Infrastructure-as-Code scripts, specifically `iac-adb-360/helpers/rg-create.sh`.
    * Step 2: The `rg-create.sh` script automatically assigns the 'User Access Administrator' role to the `devops-sc` service principal at the resource group scope, in addition to the 'Contributor' role.
    * Step 3: This grants the `devops-sc` service principal excessive privileges, far beyond what is necessary for deploying and managing infrastructure resources. The 'User Access Administrator' role allows managing user access and permissions within the resource group.
    * Step 4: If an attacker compromises the `devops-sc` service principal (e.g., through compromised CI/CD pipelines or leaked credentials), they inherit these overly permissive privileges.
    * Step 5: The attacker can then leverage 'User Access Administrator' role to manage access control within the resource group, potentially escalating privileges, modifying permissions for other users or service principals, and gaining unauthorized access to resources and data within the Azure subscription.
* Impact:
    * Successful exploitation of this vulnerability allows an attacker to gain 'User Access Administrator' privileges at the resource group level.
    * This enables the attacker to manage user access, permissions, and potentially escalate privileges further within the Azure subscription.
    * The attacker could compromise the confidentiality, integrity, and availability of resources within the resource group and potentially the entire subscription.
* Vulnerability Rank: Medium
* Currently Implemented Mitigations:
    * None. The provided scripts directly implement this overly permissive role assignment.
* Missing Mitigations:
    * **Principle of Least Privilege:**  The scripts should be modified to adhere to the principle of least privilege. The 'devops-sc' service principal should only be granted the 'Contributor' role at the resource group level, which is sufficient for IaC deployments. The 'User Access Administrator' role should be removed from the script.
    * **Documentation Warning:** The documentation should be updated to explicitly warn users about the dangers of overly permissive IAM roles and recommend reviewing and customizing the assigned roles based on their specific security requirements.
* Preconditions:
    * User deploys the Azure Databricks infrastructure using the unmodified `rg-create.sh` script.
    * The `devops-sc` service principal is created and used as intended by the IaC scripts.
* Source Code Analysis:
    * File: `/code/iac-adb-360/helpers/rg-create.sh`
    * Lines:
    ```bash
    az role assignment create --role 'Contributor' --assignee $serviceprincipaloid --scope "/subscriptions/$subscriptionid/resourceGroups/$rgDev"
    az role assignment create --role 'User Access Administrator' --assignee $serviceprincipaloid --scope "/subscriptions/$subscriptionid/resourceGroups/$rgDev"
    ```
    * Visualization:
    ```mermaid
    graph LR
        A[rg-create.sh script execution] --> B{Assign 'Contributor' Role to devops-sc};
        B --> C{Assign 'User Access Administrator' Role to devops-sc};
        C --> D[Overly permissive IAM roles for devops-sc];
        D --> E[Potential Privilege Escalation if devops-sc is compromised];
    ```
    * The script explicitly assigns both 'Contributor' and 'User Access Administrator' roles to the `devops-sc` service principal during resource group creation. This is a direct configuration issue within the script that leads to the vulnerability.
* Security Test Case:
    * Step 1: Set up the prerequisites as described in the `iac-adb-360/README.md` for a standard installation, including creating the `devops-sc` service principal.
    * Step 2: Execute the `iac-adb-360/helpers/rg-create.sh` script to create the resource groups and assign initial permissions.
    * Step 3: Log in to the Azure portal with an account that has permissions to view IAM roles in the newly created resource group (e.g., the subscription owner or a user with 'Resource Group Reader' role).
    * Step 4: Navigate to the resource group created by the script (e.g., `rg-wus2-adb360<date>-dev`).
    * Step 5: Go to 'Access control (IAM)' and then 'Role assignments'.
    * Step 6: Search for the `devops-sc` service principal.
    * Step 7: Verify that the `devops-sc` service principal has both 'Contributor' and 'User Access Administrator' roles assigned at the resource group scope.
    * Step 8: To simulate an attacker who has compromised the `devops-sc` service principal credentials, try to perform an action that requires 'User Access Administrator' permissions, such as:
        * Using Azure CLI or PowerShell, logged in as the `devops-sc` service principal, attempt to create a new role assignment for another user or service principal within the resource group, granting them elevated privileges (e.g., 'Owner' or 'Contributor').
        * Example Azure CLI command (replace placeholders with actual values):
        ```bash
        az role assignment create --role 'Contributor' --assignee <object_id_of_another_user_or_sp> --scope "/subscriptions/<subscription_id>/resourceGroups/<resource_group_name>" --principal-type ServicePrincipal
        ```
    * Step 9: If the attacker is able to successfully create the role assignment using the `devops-sc` service principal, it confirms that the 'User Access Administrator' role provides excessive privileges and the vulnerability is valid.


* Vulnerability Name: Potential Open Workspace Access in Standard Deployment
* Description:
    * Step 1: User follows the documentation for a "Standard Installation (no SCC)" as described in `/code/iac-adb-360/README.md`.
    * Step 2: The standard installation, by design, may result in a Databricks workspace that is accessible via public IP addresses, depending on the specific configurations and Azure Databricks deployment model chosen by the user (Classic vs. NPIP/SCC, though the text mentions standard is less safe than SCC/NPIP).
    * Step 3: If the user does not implement additional network security measures (e.g., Network Security Groups - NSGs, Azure Firewall, Private Link, IP access lists within Databricks), the workspace's public endpoints could be exposed to the internet.
    * Step 4: An attacker from the public internet could attempt to access the Databricks workspace through these public endpoints.
    * Step 5: If the workspace's access controls are not sufficiently hardened (e.g., weak passwords, lack of multi-factor authentication, overly permissive workspace access policies), an attacker might be able to gain unauthorized access to the Databricks environment.
* Impact:
    * Successful exploitation could lead to unauthorized access to the Databricks workspace, including data stored within the workspace, compute resources, notebooks, jobs, and potentially connected data sources.
    * This could result in data breaches, data manipulation, denial of service, or other malicious activities within the Databricks environment.
* Vulnerability Rank: Medium (context-dependent, severity increases with weak internal access controls)
* Currently Implemented Mitigations:
    * The documentation in `/code/iac-adb-360/README.md` provides an alternative "SCC (Secure Cluster Connectivity) Installation" method, which aims to mitigate public exposure by deploying without public IP addresses.
* Missing Mitigations:
    * **Stronger Emphasis on SCC:** The documentation should strongly recommend SCC installation as the default and preferred method, especially for production environments, due to the inherent security advantages of private network connectivity.
    * **Security Hardening Guidance for Standard Deployment:** If users choose standard deployment, the documentation should provide explicit, step-by-step guidance on network security hardening, including:
        * Implementing Network Security Groups (NSGs) to restrict inbound and outbound traffic to the workspace.
        * Configuring IP access lists within the Databricks workspace to limit access to specific trusted IP ranges.
        * Enforcing strong authentication policies, including multi-factor authentication (MFA) for all users.
        * Regularly reviewing and hardening workspace access control policies.
    * **Automated Security Configuration:** The IaC scripts for standard deployment could be enhanced to automatically implement basic network security configurations (e.g., create and apply restrictive NSG rules) as a baseline, while still recommending SCC for optimal security.
* Preconditions:
    * User chooses to deploy the Databricks workspace using the "Standard Installation (no SCC)" method.
    * User does not implement sufficient network security controls to restrict access to the publicly accessible Databricks workspace.
    * Workspace internal access controls are not sufficiently strong.
* Source Code Analysis:
    * File: `/code/iac-adb-360/README.md`
    * The vulnerability is not directly caused by a specific code section but arises from the architectural choice of offering a standard deployment option that *can* be publicly accessible if not secured and the documentation's presentation of SCC as an *alternative* rather than a strong recommendation.
    * Visualization:
    ```mermaid
    graph LR
        A[Standard Installation (no SCC) Documentation] --> B{Potential Public Workspace Exposure};
        B --> C[User does not harden network security];
        C --> D[Public Internet Access to Databricks Workspace];
        D --> E[Potential Unauthorized Access to Databricks Environment];
    ```
    * The documentation provides instructions for both standard and SCC installations, but the standard installation path can lead to a less secure deployment if users are not aware of or do not implement necessary network security hardening measures.
* Security Test Case:
    * Step 1: Deploy a Databricks workspace using the IaC scripts and following the "Standard Installation (no SCC)" instructions in `/code/iac-adb-360/README.md`.
    * Step 2: Identify the public endpoint or public IP address associated with the deployed Databricks workspace (if applicable in standard deployment - this may depend on classic vs. NPIP). This might involve checking the Azure portal for network interfaces associated with the Databricks workspace resources.
    * Step 3: From a machine outside of the Azure VNet where the Databricks workspace is deployed (i.e., from the public internet), attempt to access the Databricks workspace URL.
    * Step 4: If the workspace is accessible from the public internet, proceed to attempt unauthorized access. Try to log in using default credentials (if any are configured - which should not be the case in a properly configured environment, but testing default configurations is relevant) or attempt to exploit any known vulnerabilities in publicly exposed Databricks workspace interfaces (though less likely to be directly present in this IaC project, the exposure increases risk).
    * Step 5: A more direct test (if feasible and ethical within your testing context) would be to attempt to bypass authentication if possible or exploit weak default configurations to gain unauthorized access to the workspace environment.
    * Step 6: If unauthorized access to the Databricks workspace is achieved from the public internet due to lack of network security hardening, the vulnerability is confirmed. This test case primarily validates the *exposure* risk associated with the standard deployment and lack of user-implemented network security, rather than a direct code vulnerability in the IaC itself.