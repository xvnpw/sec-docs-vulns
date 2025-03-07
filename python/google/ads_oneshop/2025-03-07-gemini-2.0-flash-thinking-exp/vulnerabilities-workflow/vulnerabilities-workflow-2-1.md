### Vulnerability List

- Vulnerability Name: Insecure Looker Studio Dashboard Sharing Configuration
  - Description: After deploying Looker Studio dashboards using Ads OneShop, users are responsible for configuring sharing settings within Looker Studio. If users misconfigure these settings, sensitive Google Ads and Merchant Center data visualized in the dashboards could be unintentionally exposed to unauthorized individuals. This could happen if users grant public access (e.g., "Anyone with the link can view") or share with incorrect Google accounts, failing to restrict access to authorized personnel.
  - Impact: Exposure of sensitive Google Ads and Merchant Center data, including but not limited to performance metrics, product data, and potentially competitive insights, to unauthorized individuals. This data breach could lead to competitive disadvantage for merchants, privacy violations if personal data is exposed, and potential misuse of merchant data by malicious actors.
  - Vulnerability Rank: Medium
  - Currently Implemented Mitigations: None. The Ads OneShop project automates the deployment of dashboards but does not include any mechanisms to enforce or guide secure sharing settings within Looker Studio post-deployment. The project relies on the user to manually configure these settings correctly.
  - Missing Mitigations:
    - Security Guidance Documentation: Missing explicit security guidance within the project's documentation (e.g., in `README.md` or `walkthrough.md`) detailing the risks of improper Looker Studio sharing configurations and providing step-by-step instructions on how to securely configure sharing settings to prevent unauthorized access. This documentation should emphasize the principle of least privilege and recommend sharing dashboards only with explicitly authorized Google accounts.
    - Secure Default Configuration (Potentially): Explore the feasibility of programmatically setting more secure default sharing configurations for the Looker Studio templates during deployment, if Looker Studio API and project goals allow. For example, setting the default sharing to "Specific people" and providing instructions on how to manage the list of authorized users. However, this mitigation might be limited by Looker Studio API capabilities and could impact the intended collaborative use-cases for the dashboards.
  - Preconditions:
    - User successfully deploys the Ads OneShop project and the associated Looker Studio dashboards.
    - User, after deployment, accesses the Looker Studio dashboard and manually modifies the default sharing settings.
    - User unintentionally configures insecure sharing settings, such as granting "Anyone with the link can view" access or sharing with unintended Google accounts.
  - Source Code Analysis:
    - The provided project files, including shell scripts (`deploy_job.sh`, `run_job.sh`, `schedule_job.sh`), Python scripts (`src/acit/*.py`, `extensions/merchant_excellence/model/*.py`), and configuration files (`env.sh`, `appsecrets.yaml`), are primarily focused on automating the data pipeline and dashboard deployment.
    - Review of these files reveals no code or configurations that directly interact with or manage Looker Studio dashboard sharing settings. The deployment process concludes with the creation of the dashboards from templates, after which the responsibility for securing access is entirely delegated to the user through Looker Studio's native sharing interface.
    - For example, `deploy_job.sh` script automates the deployment of a Cloud Run job for data processing but does not extend to configuring Looker Studio permissions. Similarly, Python scripts handle data extraction and transformation but are not designed to manage Looker Studio settings.
    - Visualization:
      ```mermaid
      graph LR
      A[Ads OneShop Deployment Scripts] --> B(Google Cloud Infrastructure);
      B --> C{Data Processing Pipeline};
      C --> D[BigQuery Dataset];
      A --> E[Looker Studio Templates];
      E --> F(Looker Studio Dashboards);
      F --> G{User Configures Sharing in Looker Studio};
      G -- Misconfiguration --> H[Unintentional Data Exposure];
      G -- Secure Configuration --> I[Authorized Access Only];
      style G fill:#f9f,stroke:#333,stroke-width:2px
      style F fill:#ccf,stroke:#333,stroke-width:2px
      style H fill:#fcc,stroke:#333,stroke-width:2px
      style I fill:#cfc,stroke:#333,stroke-width:2px
      ```
      The diagram illustrates that the project's scope ends before the crucial step of securing dashboard sharing, which is left to the user. Misconfiguration at step G leads to vulnerability H.

  - Security Test Case:
    1. **Deployment:** Execute the Ads OneShop deployment process as documented in `walkthrough.md` and `README.md`. This will deploy the data pipeline and create Looker Studio dashboards from the provided templates.
    2. **Access Looker Studio:** After successful deployment, navigate to Looker Studio and locate the deployed dashboards (ACIT and/or MEX4P dashboards).
    3. **Misconfigure Sharing Settings:** Open the sharing settings for one of the dashboards. Change the access level from the default (likely "Specific people" or "Private") to "Anyone with the link can view". Save these changes.
    4. **Verify Unauthorized Access:** Open a new private browsing window or use a different Google account that was not intended to have access to the dashboard. In this new session, use the "Get shareable link" obtained from the misconfigured dashboard and attempt to access it.
    5. **Observe Data Exposure:** Verify that, in the unauthorized session, you can successfully access and view the dashboard and its sensitive Google Ads and Merchant Center data. This confirms the vulnerability as unauthorized access is granted due to misconfigured sharing settings.
    6. **Remediation (Expected):** To remediate this in a real-world scenario, revert the sharing settings in Looker Studio to a secure configuration, granting access only to explicitly authorized Google accounts and providing clear documentation to prevent future misconfigurations.