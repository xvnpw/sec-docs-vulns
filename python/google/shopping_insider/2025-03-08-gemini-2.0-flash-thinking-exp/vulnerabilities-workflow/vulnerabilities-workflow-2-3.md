### Vulnerability List for Shopping Insider Project

* Vulnerability Name: Insecurely Shared Looker Studio Dashboards
* Description:
    1. A user installs Shopping Insider and sets up Looker Studio dashboards using the provided templates.
    2. The user shares the Looker Studio dashboard with "Anyone with the link" to facilitate internal access within their organization, or for external collaboration.
    3. An attacker, who is not authorized to access the data, obtains the shared link to the Looker Studio dashboard through unintentional sharing, insider threat, or by exploiting misconfigurations in the sharing settings.
    4. The attacker opens the Looker Studio dashboard using the obtained link.
    5. Looker Studio grants the attacker viewer access to the dashboard, as it is configured for "Anyone with the link".
    6. The attacker is able to view sensitive business data from Google Merchant Center and Google Ads, including product performance metrics, advertising costs, and potentially competitive market insights, through the pre-built visualizations and reports in the dashboard.
* Impact:
    - Unauthorized access to sensitive business data, including Google Merchant Center and Google Ads performance data.
    - Potential exposure of competitive insights, impacting business strategy and decision-making.
    - Reputational damage and loss of customer trust due to data breach.
    - Financial loss due to compromised business intelligence and potential misuse of exposed data.
* Vulnerability Rank: High
* Currently Implemented Mitigations:
    - None. The project provides no specific guidance or built-in mechanisms to restrict access to Looker Studio dashboards beyond the default sharing options available in Looker Studio itself. The README.md mentions joining a Google Group to gain viewer access to some resources, but this group is for templates and spreadsheets and not directly related to securing user-generated dashboards.
* Missing Mitigations:
    - **Principle of Least Privilege Guidance:** Documentation should strongly recommend against using "Anyone with the link" sharing for sensitive dashboards. It should emphasize the importance of using more restrictive sharing options within Looker Studio, such as sharing with specific Google accounts or Google Groups.
    - **Access Control Recommendations:** Provide clear instructions and best practices for securing Looker Studio dashboards, including:
        - Sharing dashboards only with authorized users or groups within the organization.
        - Utilizing Looker Studio's user and group management features for access control.
        - Regularly reviewing and auditing dashboard sharing settings.
        - Educating users about the risks of over-sharing and best practices for data security.
    - **Data Source Access Control:** While not directly within the project's code, the documentation should advise users to review and restrict access to the underlying BigQuery datasets that feed the Looker Studio dashboards. This includes utilizing BigQuery's IAM roles and dataset access controls to ensure only authorized users can query the data directly, even if dashboard security is bypassed.
* Preconditions:
    - The user must have successfully installed Shopping Insider and created Looker Studio dashboards from the provided templates.
    - The user must have shared the Looker Studio dashboard using the "Anyone with the link" sharing option, or a similarly permissive setting that allows unauthorized access.
    - The attacker must obtain the shared link to the dashboard.
* Source Code Analysis:
    - The provided project files do not directly manage or enforce access control on Looker Studio dashboards. The project focuses on data extraction, transformation, and providing dashboard templates.
    - The vulnerability arises from the user's configuration and sharing practices within Looker Studio, which is outside the scope of the provided code.
    - However, the project's documentation (README.md) guides users to use Looker Studio templates and provides links to these templates. This implicitly encourages users to create and potentially share dashboards based on these templates.
    - The `setup.sh` script and Python code (`cloud_env_setup.py`, `cloud_data_transfer.py`, `cloud_bigquery.py`) correctly set up data transfers and BigQuery views, but do not include any features to control access to Looker Studio or the dashboards created by users.
    - The `config.yaml` and `config_parser.py` files are for configuration settings and do not relate to access control vulnerabilities.
    - The `auth.py` and `plugins/cloud_utils/cloud_auth.py` files handle authentication for Google Cloud services during setup, but not for Looker Studio dashboard access.

* Security Test Case:
    1. **Setup Shopping Insider:** Install Shopping Insider using either Option 1 or Option 2 as described in the README.md, ensuring the installation is successful and Looker Studio dashboard templates are available.
    2. **Create a Dashboard:** Create a Looker Studio dashboard from the "Shopping Insider Dashboard Template" or "Merchant Market Insights Dashboard Template". Connect the dashboard to the BigQuery data sources created by the Shopping Insider installation.
    3. **Enable "Anyone with the link" sharing:** In Looker Studio, open the newly created dashboard. Click the "Share" button in the top right corner. In the sharing dialog, under "Get link", change the access setting to "Anyone with the link" and select "Viewer" access. Copy the generated shareable link.
    4. **Access Dashboard from an Unauthorized Account:** Open a new browser session or use a private browsing window where you are not logged in with an authorized Google account (or log in with a completely separate Google account that should not have access).
    5. **Paste the Shared Link:** Paste the copied shareable link into the browser's address bar and press Enter.
    6. **Verify Unauthorized Access:** Observe that the Looker Studio dashboard loads successfully and displays the Shopping Insider data. You are able to view the dashboard and interact with the reports and visualizations without being explicitly granted access beyond having the link. This confirms that "Anyone with the link" sharing exposes the sensitive data to anyone who obtains the link.

This test case demonstrates that if a user shares the Looker Studio dashboard with "Anyone with the link", an external attacker who obtains this link can successfully access and view the sensitive data, confirming the vulnerability.