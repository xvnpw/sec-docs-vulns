- vulnerability name: Lack of Integrity Check for Looker Studio Templates
- description: |
    1. An attacker creates a malicious Looker Studio template that is designed to exfiltrate data.
    2. The attacker hosts this malicious template and tricks a user into using it, possibly by impersonating the legitimate project or through other social engineering tactics.
    3. The user, believing it to be a safe template, makes a copy of the malicious template in Looker Studio.
    4. The user connects their Google BigQuery dataset to the data sources within the copied malicious template, as instructed in the project's documentation for legitimate templates.
    5. The malicious template, upon data source connection, executes hidden scripts or configurations that exfiltrate sensitive data from the user's BigQuery dataset to an attacker-controlled location. This exfiltration could happen through various Looker Studio features, potentially leveraging calculated fields, custom queries, or data connectors to send data to external services.
- impact: |
    - Confidentiality breach: Sensitive data from the user's Google BigQuery dataset, such as Google Ads and Google Merchant Center performance data, product information, and potentially customer data, can be exfiltrated and exposed to the attacker.
    - Reputational damage: Users who fall victim to this attack may lose trust in the project and the organization providing it.
- vulnerability rank: High
- currently implemented mitigations: None
- missing mitigations: |
    - Implement a system to verify the integrity and authenticity of Looker Studio templates provided to users. This could involve:
        - Hosting templates centrally and providing them directly to users, rather than relying on users to copy templates from potentially untrusted sources.
        - Implementing a template signing or verification process to ensure that templates are from a trusted source and haven't been tampered with.
        - Providing clear warnings and security guidelines to users about the risks of using templates from untrusted sources.
- preconditions: |
    - The attacker needs to create a malicious Looker Studio template.
    - The attacker needs to successfully trick a user into using this malicious template instead of a legitimate one.
    - The user must have a Google BigQuery dataset connected to their Google Ads and Google Merchant Center accounts.
    - The user must follow the project's instructions to connect their BigQuery dataset to the Looker Studio template.
- source code analysis: |
    - The provided project files are primarily focused on the backend data pipeline (Python scripts, Dockerfiles, deployment scripts) and do not directly include the Looker Studio templates themselves.
    - Therefore, a direct source code analysis of the provided files will not reveal the malicious template or the exfiltration mechanism.
    - The vulnerability lies in the project's design and distribution model for Looker Studio templates, which relies on users copying templates from external links without any integrity checks.
    - The code does not implement any mechanism to validate the source or content of the Looker Studio templates. The `README.md` and `walkthrough.md` files simply provide links to templates hosted on Looker Studio, without any security considerations for template integrity.
- security test case: |
    1. **Setup Malicious Template:**
        - Create a Looker Studio template that, when a BigQuery data source is connected, attempts to exfiltrate data. This could be achieved using a hidden chart or table that uses a calculated field to construct a URL containing data from the BigQuery dataset and sends it to an attacker-controlled server using `IMAGE` function or similar techniques within Looker Studio.
    2. **Host Malicious Template:**
        - Host the malicious template in Looker Studio and obtain its template URL.
    3. **Impersonate Legitimate Project (Social Engineering):**
        - Create a fake website or communication that mimics the official Ads OneShop project.
        - On this fake platform, promote the malicious Looker Studio template URL as the official template for ACIT or MEX4P dashboard.
        - Use social engineering tactics to convince a test user to use this malicious template. This could involve:
            - Sending a phishing email to the test user with the malicious template link.
            - Creating a misleading tutorial video showcasing the "easy setup" using the malicious template.
            - Posting in online forums frequented by Google Ads/Merchant Center users, recommending the "improved" template (malicious one).
    4. **User Copies and Connects Data:**
        - As a test user, follow the attacker's instructions and the project's general setup guide to:
            - Access the malicious Looker Studio template using the provided link.
            - Make a copy of the template.
            - Connect the template's data sources to a test BigQuery dataset containing sample Google Ads and Google Merchant Center data.
    5. **Verify Data Exfiltration:**
        - Monitor the attacker-controlled server for incoming requests containing data from the test user's BigQuery dataset.
        - Analyze server logs to confirm successful data exfiltration, verifying that sensitive information from the connected BigQuery dataset was indeed sent to the attacker.

    **Expected result:** The test should demonstrate that by using a malicious template and tricking a user, sensitive data can be exfiltrated from the user's BigQuery dataset without any warnings or integrity checks from the Ads OneShop project itself. This proves the vulnerability of relying on untrusted Looker Studio templates.