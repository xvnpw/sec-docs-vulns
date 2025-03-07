- Vulnerability Name: Insecure Looker Studio Dashboard Sharing Configuration
- Description:
    1. The Ads OneShop project deploys Looker Studio dashboards that visualize sensitive Google Ads and Merchant Center data.
    2. The setup instructions in `README.md` and `walkthrough.md` guide users to create copies of pre-built dashboard templates.
    3. These instructions mention updating data sources to use the user's BigQuery dataset but do not explicitly warn users about the importance of configuring secure sharing settings for the Looker Studio dashboards.
    4. If a user misconfigures the sharing settings in Looker Studio, granting public access or sharing with unintended parties, sensitive business performance data from Google Ads and Merchant Center can be exposed. This includes product data insights and Google Ads performance metrics.
    5. An external threat actor, if provided with a publicly accessible link or through unintended sharing, can gain unauthorized access to the Looker Studio dashboard and view the sensitive data.
- Impact:
    - Unauthorized access to sensitive Google Ads and Merchant Center data.
    - Exposure of business performance insights, including product data, advertising metrics, and potentially competitive information.
    - Reputational damage and loss of business advantage due to data leakage.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None in the project code itself. The project relies on Google Cloud and Looker Studio's security features.
- Missing Mitigations:
    - Explicit warnings and best practice documentation within `README.md` and `walkthrough.md` about secure Looker Studio dashboard sharing configurations.
    - Potentially, a script or automated check to verify Looker Studio dashboard sharing settings during or after deployment (though this might be complex to implement).
- Preconditions:
    - User successfully deploys Ads OneShop and Looker Studio dashboards.
    - User misconfigures sharing settings of the Looker Studio dashboards, making them accessible to unintended parties.
    - Threat actor obtains access to the misconfigured dashboard link.
- Source Code Analysis:
    - The code in the repository focuses on data extraction, processing, and loading into BigQuery. There is no code within the Ads OneShop repository that directly manages or enforces sharing settings on Looker Studio dashboards.
    - The vulnerability arises from the deployment process and user configuration of Google Cloud services, specifically Looker Studio, rather than a flaw in the provided code.
    - `README.md` and `walkthrough.md` guide users on deploying the dashboards and updating data sources, but lack security hardening guidance for Looker Studio sharing.
- Security Test Case:
    1. Deploy Ads OneShop core pipeline and ACIT/MEX4P dashboards following the instructions in `README.md` and `walkthrough.md`.
    2. Access the deployed Looker Studio dashboard templates (ACIT and MEX4P) using the provided links in `README.md`.
    3. Create a copy of one of the dashboard templates in your Looker Studio account as instructed.
    4. Update the data sources of the copied dashboard to point to your deployed BigQuery dataset.
    5. Misconfigure the sharing settings of the copied dashboard by selecting "Anyone with the link can view" or by explicitly sharing with an external email address.
    6. As an external threat actor (using a different Google account or incognito mode):
        - If "Anyone with the link can view" was selected, access the dashboard using the publicly shareable link obtained from Looker Studio.
        - If explicitly shared, access the dashboard using the external email account it was shared with.
    7. Verify that the threat actor can successfully view the dashboard and access the sensitive Google Ads and Merchant Center data visualized in the reports without authorization to the Ads OneShop project or Google Ads/Merchant Center accounts.