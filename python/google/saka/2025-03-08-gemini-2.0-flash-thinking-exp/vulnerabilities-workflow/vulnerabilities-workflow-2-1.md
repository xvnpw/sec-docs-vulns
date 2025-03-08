### Vulnerability List:

- Vulnerability Name: Potential Exposure of SA360 SFTP Password and Google Ads API Credentials due to Misconfiguration
- Description:
    1. An attacker identifies a publicly accessible GitHub repository containing the SAKA project code.
    2. The attacker reviews the `README.md` and `environment_variables.sh` files, understanding the intended configuration process.
    3. The attacker hypothesizes that a victim might misconfigure the setup by directly embedding sensitive credentials (SA360 SFTP password, Google Ads API credentials) as environment variables in the Cloud Function or by exposing the `environment_variables.sh` file with actual credentials.
    4. The attacker searches for publicly accessible GCP Cloud Functions or Cloud Source Repositories related to SAKA.
    5. If the attacker finds a publicly accessible Cloud Function instance and is able to view its environment variables (depending on GCP project's IAM configuration, this might be possible if permissions are overly permissive, although less likely for external attacker), the attacker checks for environment variables that might contain the SA360 SFTP password or Google Ads API credentials.
    6. Alternatively, if the attacker finds a publicly accessible Cloud Source Repository that is misconfigured and contains the `environment_variables.sh` file with filled-in credentials, the attacker can directly access these credentials.
    7. If the attacker successfully obtains the SA360 SFTP password and/or Google Ads API credentials, they can use these credentials to gain unauthorized access. For SA360 SFTP password, they can access the victim's SA360 SFTP server. For Google Ads API credentials, they can access and potentially control the victim's Google Ads account.
- Impact:
    - High. If SA360 SFTP credentials are exposed, an attacker could gain unauthorized access to the victim's Search Ads 360 account via SFTP. This could allow the attacker to manipulate bulksheets, potentially leading to unauthorized changes in campaigns, keywords, ads, or data exfiltration.
    - High. If Google Ads API credentials are exposed, an attacker could gain unauthorized access to the victim's Google Ads account via the Google Ads API. This could allow the attacker to manipulate campaigns, keywords, ads, budgets, and access sensitive advertising data, potentially leading to financial loss, data breaches, and reputational damage for the victim.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - The `install_to_gcp.sh` script is designed to store sensitive credentials (Google Ads API credentials and SA360 SFTP password) in Google Cloud Secret Manager. This is a secure way to manage secrets and prevents them from being directly embedded in environment variables or code.
    - The `cicd/deploy_saka_cf_to_gcp.yaml` Cloud Build configuration deploys the Cloud Function without directly passing sensitive credentials as environment variables. It relies on the Cloud Function code to retrieve credentials from Secret Manager at runtime.
- Missing Mitigations:
    - There is no explicit check in the installation script or Cloud Function code to verify that Secret Manager is correctly configured and being used.
    - There is no explicit warning in the `README.md` or `environment_variables.sh` file about the critical security risk of exposing credentials directly in environment variables or committing `environment_variables.sh` to public repositories.
    - There is no automated check to prevent committing `environment_variables.sh` file with filled-in credentials to the source repository (e.g., a pre-commit hook).
- Preconditions:
    - The victim must misconfigure the SAKA setup process. This could involve:
        - Modifying the `install_to_gcp.sh` or deployment process to directly pass SA360 SFTP password and/or Google Ads API credentials as environment variables to the Cloud Function.
        - Committing the `environment_variables.sh` file with actual credentials to a publicly accessible source code repository.
    - The attacker must be able to access the misconfigured environment (e.g., publicly accessible Cloud Function environment variables due to IAM misconfiguration or a publicly accessible source code repository containing the exposed credentials).
- Source Code Analysis:
    - `install_to_gcp.sh`: This script correctly uses `gcloud secrets create` to store `google_ads_api_credentials` and `sa360_sftp_password` in Secret Manager. This part of the script is secure.
    - `cicd/deploy_saka_cf_to_gcp.yaml`: This Cloud Build configuration correctly deploys the Cloud Function and sets environment variables using `${_...}` substitutions, which are intended for non-sensitive configuration parameters. It does not directly embed sensitive credentials.
    - `cloud_functions/main.py`: The `_retrieve_secret` function is used to fetch `google_ads_api_credentials` and `sa360_sftp_password` from Secret Manager. This is the secure and intended way to access credentials.
    - **Vulnerability Point**: The vulnerability is not in the code itself, but in the *potential for misconfiguration* during setup. If a user deviates from the intended secure setup (using Secret Manager as shown in `install_to_gcp.sh` and `main.py`) and instead exposes credentials, the system becomes vulnerable. This deviation is not prevented or explicitly warned against by the provided code or documentation beyond the intended secure flow.
- Security Test Case:
    1. **Setup Misconfigured Environment (Simulate Victim Error):**
        a.  Modify the `cicd/deploy_saka_cf_to_gcp.yaml` file to directly pass the SA360 SFTP password and Google Ads API credentials as environment variables to the Cloud Function. For example, add lines under `args:` like: `--set-env-vars,SA360_SFTP_PASSWORD=YOUR_SFTP_PASSWORD,GADS_DEVELOPER_TOKEN=YOUR_DEV_TOKEN,...`
        b.  Deploy the Cloud Function using this modified Cloud Build configuration.
    2. **Attempt to Access Exposed Credentials (Simulate Attacker Action):**
        a.  In the GCP Console, navigate to the deployed Cloud Function.
        b.  Go to the "Environment variables" section of the Cloud Function configuration.
        c.  Observe if the SA360 SFTP password and Google Ads API credentials are now visible as environment variables in the Cloud Function configuration.
        d.  If the credentials are visible, this confirms the misconfiguration vulnerability. An attacker with sufficient GCP permissions (or if environment variables are inadvertently made public, which is less likely for external attacker but possible with internal misconfiguration) could access these exposed credentials.
    3. **Alternative Test Case (Exposed `environment_variables.sh`):**
        a.  Fill in the `environment_variables.sh` file with *dummy* sensitive credentials (do not use real credentials for testing).
        b.  Accidentally (or intentionally for testing) commit and push this `environment_variables.sh` file to a *public* GitHub repository (or a test repository that simulates public exposure).
        c.  As an attacker, browse the public repository and locate the `environment_variables.sh` file.
        d.  Observe if the dummy credentials are visible in the publicly accessible `environment_variables.sh` file. If yes, this demonstrates the risk of user error leading to credential exposure if this file is not properly secured and accidentally made public.