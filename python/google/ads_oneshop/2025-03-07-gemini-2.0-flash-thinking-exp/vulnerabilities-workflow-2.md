## Combined Vulnerability List

This document outlines identified vulnerabilities, combining information from provided lists and removing duplicates. Each vulnerability is described in detail, including its potential impact, rank, mitigations, and steps to reproduce and verify.

### Insecure Looker Studio Dashboard Sharing Configuration

- **Description:**
    After deploying Looker Studio dashboards using Ads OneShop, users are responsible for configuring sharing settings within Looker Studio. Misconfiguration of these settings can unintentionally expose sensitive Google Ads and Merchant Center data visualized in the dashboards to unauthorized individuals. This can occur if users grant public access (e.g., "Anyone with the link can view") or share with incorrect Google accounts, failing to restrict access to authorized personnel. The setup instructions in `README.md` and `walkthrough.md` guide users to create copies of pre-built dashboard templates and update data sources, but do not explicitly warn users about the critical importance of secure sharing configurations in Looker Studio.

- **Impact:**
    Exposure of sensitive Google Ads and Merchant Center data to unauthorized individuals. This includes business performance insights, product data, advertising metrics, and potentially competitive information. A data breach could lead to competitive disadvantage for merchants, privacy violations if personal data is exposed, potential misuse of merchant data by malicious actors, and reputational damage and loss of business advantage due to data leakage.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    None. The Ads OneShop project automates dashboard deployment but does not include mechanisms to enforce or guide secure sharing settings within Looker Studio post-deployment. The project relies entirely on the user to manually configure these settings correctly using Google Cloud and Looker Studio's native security features.

- **Missing Mitigations:**
    - **Security Guidance Documentation:** Explicit security guidance is missing within the project's documentation (e.g., in `README.md` or `walkthrough.md`). This documentation should detail the risks of improper Looker Studio sharing configurations and provide step-by-step instructions on how to securely configure sharing settings to prevent unauthorized access. It should emphasize the principle of least privilege and recommend sharing dashboards only with explicitly authorized Google accounts.
    - **Secure Default Configuration (Potentially):** Explore the feasibility of programmatically setting more secure default sharing configurations for the Looker Studio templates during deployment, if Looker Studio API and project goals allow. For example, setting the default sharing to "Specific people" and providing instructions on how to manage the list of authorized users. However, this mitigation might be limited by Looker Studio API capabilities and could impact the intended collaborative use-cases for the dashboards.

- **Preconditions:**
    - User successfully deploys the Ads OneShop project and the associated Looker Studio dashboards.
    - User, after deployment, accesses the Looker Studio dashboard and manually modifies the default sharing settings.
    - User unintentionally configures insecure sharing settings, such as granting "Anyone with the link can view" access or sharing with unintended Google accounts.
    - Threat actor obtains access to the misconfigured dashboard link.

- **Source Code Analysis:**
    - The provided project files, including shell scripts (`deploy_job.sh`, `run_job.sh`, `schedule_job.sh`), Python scripts (`src/acit/*.py`, `extensions/merchant_excellence/model/*.py`), and configuration files (`env.sh`, `appsecrets.yaml`), are focused on automating the data pipeline and dashboard deployment.
    - Review of these files reveals no code or configurations that directly interact with or manage Looker Studio dashboard sharing settings. The deployment process concludes with the creation of the dashboards from templates, after which the responsibility for securing access is entirely delegated to the user through Looker Studio's native sharing interface.
    - The `README.md` and `walkthrough.md` documentation guide users on deploying the dashboards and updating data sources, but lack security hardening guidance for Looker Studio sharing configurations.
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

- **Security Test Case:**
    1. **Deployment:** Execute the Ads OneShop deployment process as documented in `walkthrough.md` and `README.md`. This will deploy the data pipeline and create Looker Studio dashboards from the provided templates.
    2. **Access Looker Studio:** After successful deployment, navigate to Looker Studio and locate the deployed dashboards (ACIT and/or MEX4P dashboards).
    3. **Misconfigure Sharing Settings:** Open the sharing settings for one of the dashboards. Change the access level from the default to "Anyone with the link can view". Save these changes.
    4. **Verify Unauthorized Access:** Open a new private browsing window or use a different Google account that was not intended to have access to the dashboard. In this new session, use the "Get shareable link" obtained from the misconfigured dashboard and attempt to access it.
    5. **Observe Data Exposure:** Verify that, in the unauthorized session, you can successfully access and view the dashboard and its sensitive Google Ads and Merchant Center data. This confirms the vulnerability as unauthorized access is granted due to misconfigured sharing settings.


### Lack of Integrity Check for Looker Studio Templates

- **Description:**
    The project relies on users copying Looker Studio templates from provided links. An attacker could create a malicious Looker Studio template designed to exfiltrate data and trick a user into using it. If a user, believing it to be a safe template, copies and connects their Google BigQuery dataset to the data sources within the malicious template, it could execute hidden scripts or configurations to exfiltrate sensitive data from the user's BigQuery dataset to an attacker-controlled location. This exfiltration could leverage Looker Studio features like calculated fields or custom queries to send data to external services.

- **Impact:**
    - Confidentiality breach: Sensitive data from the user's Google BigQuery dataset, such as Google Ads and Google Merchant Center performance data, product information, and potentially customer data, can be exfiltrated and exposed to the attacker.
    - Reputational damage: Users who fall victim to this attack may lose trust in the project and the organization providing it.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    None. There is no system in place to verify the integrity or authenticity of Looker Studio templates provided to users. The project relies on users copying templates from external links without any security checks.

- **Missing Mitigations:**
    - Implement a system to verify the integrity and authenticity of Looker Studio templates provided to users. This could involve:
        - Hosting templates centrally and providing them directly to users, rather than relying on users to copy templates from potentially untrusted sources.
        - Implementing a template signing or verification process to ensure that templates are from a trusted source and haven't been tampered with.
        - Providing clear warnings and security guidelines to users about the risks of using templates from untrusted sources.

- **Preconditions:**
    - The attacker needs to create a malicious Looker Studio template.
    - The attacker needs to successfully trick a user into using this malicious template instead of a legitimate one, possibly through social engineering.
    - The user must have a Google BigQuery dataset connected to their Google Ads and Google Merchant Center accounts.
    - The user must follow the project's instructions to connect their BigQuery dataset to the Looker Studio template.

- **Source Code Analysis:**
    - The provided project files are primarily focused on the backend data pipeline and do not include the Looker Studio templates themselves or any mechanisms to validate them.
    - The vulnerability lies in the project's design and distribution model for Looker Studio templates, which relies on users copying templates from external links without any integrity checks.
    - The `README.md` and `walkthrough.md` files simply provide links to templates hosted on Looker Studio, without any security considerations for template integrity.

- **Security Test Case:**
    1. **Setup Malicious Template:** Create a Looker Studio template that attempts to exfiltrate data when a BigQuery data source is connected. This can be done using a hidden chart with a calculated field that constructs a URL containing data from the BigQuery dataset and sends it to an attacker-controlled server using the `IMAGE` function or similar techniques.
    2. **Host Malicious Template:** Host the malicious template in Looker Studio and obtain its template URL.
    3. **Impersonate Legitimate Project (Social Engineering):** Create a fake website or communication mimicking the official Ads OneShop project and promote the malicious template URL as the official template. Use social engineering to convince a test user to use this malicious template.
    4. **User Copies and Connects Data:** As a test user, follow the attacker's instructions to access the malicious template, make a copy, and connect its data sources to a test BigQuery dataset with sample Google Ads and Merchant Center data.
    5. **Verify Data Exfiltration:** Monitor the attacker-controlled server for incoming requests containing data from the test user's BigQuery dataset. Analyze server logs to confirm successful data exfiltration.

### Benchmark CSV Injection

- **Description:**
    The project utilizes publicly available `benchmark_details.csv` and `benchmark_values.csv` files in the GitHub repository for benchmark data in the Merchant Excellence for Partners (MEX4P) dashboards. An attacker can modify these CSV files in the public repository to inject malicious or fabricated benchmark data. When a legitimate user downloads these compromised CSV files and manually uploads them to their BigQuery dataset as part of the MEX4P setup, the Ads OneShop pipeline processes this data. Consequently, the MEX4P dashboards and reports are generated using the attacker-injected benchmark data, leading to data corruption and misleading insights.

- **Impact:**
    - Corruption of data integrity within the Merchant Excellence for Partners (MEX4P) dashboards and reports.
    - Users relying on these dashboards will be presented with flawed and potentially misleading business insights due to the injected false benchmark data.
    - Incorrect assessments of Google Merchant Center performance and adoption of inappropriate optimization strategies by merchants.
    - Undermining of the credibility and trustworthiness of the Ads OneShop project and its MEX4P solution.
    - Potential negative impact on AI/ML models relying on benchmark data for training or inference, leading to flawed recommendations and predictions within the Merchant Excellence solution.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    None. The project relies on users manually downloading and uploading benchmark CSV files without any validation or sanitization. There are no checks in the provided scripts or documentation to ensure the integrity of the uploaded benchmark data.

- **Missing Mitigations:**
    - Implement input validation and sanitization for the benchmark CSV files before ingestion into BigQuery. This should include:
        - File format validation: Verify that the uploaded files are valid CSV files.
        - Schema validation: Ensure CSV files contain expected columns with correct headers and data types.
        - Data type validation: Validate the data type of each column.
        - Data sanitization: Sanitize data to escape special characters.
        - Consider automating benchmark data updates from a trusted source instead of manual uploads from potentially compromised files.

- **Preconditions:**
    - Public accessibility of `benchmark_details.csv` and `benchmark_values.csv` files in the GitHub repository, making them modifiable.
    - Users must manually download and upload these CSV files to their BigQuery datasets as part of the MEX4P setup.
    - Merchant Excellence for Partners (MEX4P) feature must be enabled.

- **Source Code Analysis:**
    - The provided project files do not contain any code for processing or validating the `benchmark_details.csv` and `benchmark_values.csv` files before they are used in the MEX4P dashboards.
    - The files are focused on the automated data pipeline for Google Ads and Merchant Center data and the Merchant Excellence model, but lack logic for handling benchmark CSV file uploads or performing validation.
    - The `README.md` and `walkthrough.md` documentation instruct users to manually download and upload these CSV files to BigQuery, a process outside of the automated pipeline and lacking security checks.

- **Security Test Case:**
    1. **Setup:** Ensure a deployed Ads OneShop instance with MEX4P enabled and access to the associated BigQuery dataset.
    2. **Download Benchmark Files:** Download `benchmark_values.csv` from the project's GitHub repository.
    3. **Modify Benchmark File:** Open `benchmark_values.csv` and inject malicious data by modifying or adding rows with fabricated benchmark values.
    4. **Save Modified File:** Save the changes to the `benchmark_values.csv` file.
    5. **Upload to BigQuery:** Manually upload the *modified* `benchmark_values.csv` file (and `benchmark_details.csv` if needed) to your BigQuery dataset, overwriting or creating the `MEX_benchmark_values` (and `MEX_benchmark_details`) tables as per instructions.
    6. **Run Data Pipeline (if necessary):** Trigger the Ads OneShop data pipeline if dashboards are not automatically updated.
    7. **Access MEX4P Dashboard:** Open the MEX4P dashboard in Looker Studio.
    8. **Verify Data Injection:** Navigate to reports within the MEX4P dashboard displaying benchmark data, particularly the metric you modified.
    9. **Observe Impact:** Check if the injected malicious data is reflected in the dashboard. Verify if the modified metric displays the injected value. If the dashboard reflects the manipulated benchmark data, the CSV injection vulnerability is demonstrated.