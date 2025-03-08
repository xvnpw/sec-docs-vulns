### Vulnerabilities List for Shopping Insider Project

This document outlines identified vulnerabilities within the Shopping Insider project. Each vulnerability is described in detail, including its potential impact, severity, existing and missing mitigations, preconditions for exploitation, source code analysis, and a security test case to validate the vulnerability.

#### 1. Unintentional Public Exposure of Sensitive Business Data via Looker Studio Dashboards

- **Vulnerability Name:** Unintentional Public Exposure of Sensitive Business Data via Looker Studio Dashboards

- **Description:**
    1. The Shopping Insider project extracts data from Google Merchant Center and Google Ads, processes it in BigQuery, and visualizes it in Looker Studio dashboards.
    2. Users create and share Looker Studio dashboards to gain insights from this data.
    3. Looker Studio offers public sharing options ("Public on the web" or "Anyone with the link"). If users select these options, even unintentionally, dashboards containing sensitive business data become publicly accessible.
    4. External threat actors, including competitors or malicious individuals, can access these publicly shared Looker Studio dashboards.
    5. Once accessed, threat actors can view and potentially misuse sensitive business performance data, leading to competitive disadvantage, reputational damage, or other harms.

- **Impact:**
    - Confidentiality breach: Sensitive business performance data from Google Merchant Center and Google Ads becomes accessible to unauthorized individuals.
    - Reputational damage: Unintentional data exposure can damage the retailer's reputation and erode customer trust.
    - Competitive disadvantage: Competitors gaining access to business performance data can use it to their advantage.
    - Financial loss: Exposure of sensitive financial or strategic data could lead to direct or indirect financial losses.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    No specific code-level mitigations are implemented within the Shopping Insider project itself to prevent misconfiguration of Looker Studio sharing settings. The project relies on Looker Studio's default sharing settings, which require users to explicitly choose sharing options.

- **Missing Mitigations:**
    - Security Hardening Documentation: Comprehensive documentation is missing, explicitly warning users about the risks of unintentional public data exposure through Looker Studio dashboard sharing. This documentation should be prominently placed in the README file and installation guides, emphasizing best practices for secure sharing. The documentation should include:
        - Clear warnings about the risks associated with "Public on the web" and "Anyone with the link" sharing options in Looker Studio.
        - Recommendations to use restricted sharing options within Looker Studio, such as sharing only with "Specific people or groups" who are authorized to view the data.
        - Best practices for managing Looker Studio user permissions and data access controls.
        - Guidance on regularly auditing and reviewing Looker Studio sharing settings.

- **Preconditions:**
    - The Shopping Insider project must be successfully installed, and Looker Studio dashboards must be created using the project's data sources.
    - A user with edit access to a Looker Studio dashboard must misconfigure the dashboard's sharing settings, selecting a public option like "Public on the web" or "Anyone with the link can view".
    - A threat actor must discover the publicly accessible dashboard, potentially through unintended sharing or leakage of an "Anyone with the link" URL.

- **Source Code Analysis:**
    - The project's source code (shell scripts, Python scripts, SQL files, configuration files) focuses on automating data pipelines and infrastructure within Google Cloud Platform (GCP).
    - The code sets up data extraction, BigQuery datasets and tables, and data transfers from Google Merchant Center and Google Ads.
    - Critically, there is **no source code within the project that directly manages or controls Looker Studio dashboard sharing settings.** Looker Studio sharing configurations are managed within the Looker Studio interface by the user, independently of the project's code.
    - The project indirectly contributes to the risk by creating the data infrastructure used for potentially sensitive Looker Studio dashboards. Lack of user awareness about secure sharing practices in Looker Studio can lead to unintentional data exposure.
    - Configuration files and scripts within the project do not include any settings related to Looker Studio sharing.
    - Authentication and authorization within the project code are for Google Cloud services access during setup and not for Looker Studio dashboard access control.
    - **Conclusion:** The vulnerability is a configuration vulnerability arising from user misconfiguration of Looker Studio sharing settings, not a flaw in the project's code. The missing mitigation is focused on documentation and user guidance.

- **Security Test Case:**
    1. **Project Installation:** Install the Shopping Insider project in a Google Cloud Project.
    2. **Looker Studio Dashboard Creation:** Create a Looker Studio dashboard using the "Shopping Insider Dashboard Template" and connect it to the BigQuery views created by the project.
    3. **Dashboard Sharing Misconfiguration:** Open the dashboard in edit mode and click "Share". Change general access to "Anyone with the link" (Viewer).
    4. **External, Unauthenticated Access Attempt ("Anyone with the link" scenario):**
        - Copy the shareable link.
        - Open a private browsing window (or different browser, logged out of Google account).
        - Paste the link and verify you can access and view the dashboard and data without login.
    5. **External, Unauthenticated Access Attempt ("Public on the web" scenario):** (Optional, similar to step 4 but with "Public on the web" setting).
    6. **Expected Outcome:** Successful unauthenticated access to sensitive business data in the Looker Studio dashboard, confirming the vulnerability.
    7. **Remediation Test (Documentation Mitigation):** Implement documentation mitigations (security warnings in README.md). Re-run steps 1-3, but share dashboard securely ("Specific people or groups"). Verify external unauthenticated access is now prevented.

#### 2. OAuth Scope Abuse via Phished Installation Script/Sheet

- **Vulnerability Name:** OAuth Scope Abuse via Phished Installation Script/Sheet

- **Description:**
    1. Attackers create a fake website mimicking the official Shopping Insider project and host modified installation methods (Cyborg Google Sheet or `setup.sh` script).
    2. Phishing techniques lure retailers to this fake channel.
    3. Retailers, believing they are using legitimate installation, use the attacker's modified script/sheet.
    4. The modified script/sheet prompts for OAuth permissions, potentially requesting excessive scopes or misusing legitimate ones.
    5. Upon OAuth authorization, the attacker gains access to the retailer's Google Cloud project and potentially sensitive data.

- **Impact:**
    - **Critical Data Breach:** Unauthorized access to retailer's Google Merchant Center and Google Ads data.
    - **Financial Loss:** Potential for unauthorized ad spending, manipulation of product listings, or data exfiltration.
    - **Reputational Damage:** Loss of customer trust and business reputation.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    None in the project code. The project disclaimer about not being an officially supported Google product serves as a weak warning but does not prevent the vulnerability.

- **Missing Mitigations:**
    - **Code Signing/Integrity Checks:** Implement mechanisms to verify the authenticity of the `setup.sh` script and Cyborg Google Sheet template (checksums, digital signatures, official distribution channels).
    - **Principle of Least Privilege for OAuth Scopes:** Ensure OAuth scopes are strictly limited to minimum required permissions. Regularly review and minimize requested scopes.
    - **Clear Security Warnings in Documentation:** Prominently display warnings in the README.md and installation guides about the risks of unofficial versions and the need to verify the source of installation tools.

- **Preconditions:**
    - Attackers must create a convincing phishing campaign leading to a malicious installation.
    - Retailers must have Google Cloud Project, Google Merchant Center, and Google Ads accounts and be willing to use provided installation methods.
    - Retailers must be tricked into authorizing OAuth permissions for the attacker's malicious script/sheet.

- **Source Code Analysis:**
    - The vulnerability is architectural, arising from the installation process relying on user execution of scripts and OAuth authorization, making it susceptible to phishing.
    - `README.md`: Outlines installation options (Cyborg Sheet, Shell Script), making them targets for attackers.
    - `setup.sh`: Primary installation entry point, a modified version could exfiltrate OAuth tokens or perform malicious actions.
    - `cloud_env_setup.py` and `auth.py`: Handle API enabling, data transfers, and OAuth authorization. Compromised versions could grant attacker access or steal credentials.
    - **OAuth Flow (Implicit):** Reliance on OAuth for authorization creates inherent risk if users authorize malicious clients.

- **Security Test Case:**
    1. **Set up a Phishing Environment:** Create a fake website mimicking the project and host a modified `setup.sh` script that exfiltrates OAuth tokens or creates backdoors.
    2. **Phishing Attack:** Send a phishing email to a target retailer, urging them to install "Shopping Insider" and link to the fake website.
    3. **Retailer Interaction (Simulated):** Assume the retailer downloads and executes the malicious `setup.sh`, providing project details and completing OAuth authorization.
    4. **Verify Exploit:** Check if the attacker received the OAuth token or gained unauthorized access to the retailer's Google Cloud project and data using the phished token or backdoors. Attempt to access BigQuery datasets or run queries.