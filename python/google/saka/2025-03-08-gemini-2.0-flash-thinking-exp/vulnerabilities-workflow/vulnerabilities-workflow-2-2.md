- Vulnerability Name: Credential Compromise via Social Engineering
- Description:
    1. The SAKA setup process requires users to manually configure the `environment_variables.sh` file with sensitive credentials for Google Ads API and SA360 SFTP.
    2. An attacker can use social engineering techniques to trick a victim into downloading a modified version of the SAKA repository or providing manipulated credentials.
    3. This could involve sending phishing emails, creating fake repositories, or compromising the victim's development environment.
    4. If the victim uses the attacker's manipulated `environment_variables.sh` file during the installation process by running `install_to_gcp.sh`, the attacker's credentials will be stored in the Google Cloud Secret Manager.
    5. Subsequently, the SAKA Cloud Function, when triggered, will use these attacker-controlled credentials to access the victim's Google Ads and SA360 accounts.
    6. This grants the attacker unauthorized access to the victim's advertising data and the ability to manipulate ad campaigns.
- Impact:
    - Unauthorized access to victim's Google Ads and SA360 accounts.
    - Potential data exfiltration of advertising performance data.
    - Manipulation of ad campaigns, leading to financial losses or reputational damage for the victim.
    - Misuse of advertising budget.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None in the code itself.
    - The README.md provides a disclaimer stating the solution is experimental and without warranty, and users assume all risks. This is not a technical mitigation but a legal disclaimer.
- Missing Mitigations:
    - Input validation in `install_to_gcp.sh` to check the format and validity of provided credentials before storing them in Secret Manager. While full validation might be complex, basic checks could help.
    - Security warnings in the README.md and during the installation process, explicitly highlighting the risk of social engineering and the importance of using strong, unique credentials and obtaining the software from trusted sources.
    - Consider alternative, more secure credential management methods that reduce the reliance on manual user input of sensitive information in plain text files, although this might increase complexity of setup.
- Preconditions:
    - The victim must intend to install and use the SAKA solution.
    - The attacker must successfully socially engineer the victim into using malicious credentials during the setup process. This requires tricking the user before they run the `install_to_gcp.sh` script.
- Source Code Analysis:
    - `/code/environment_variables.sh`: This file is intended to be edited by the user and stores sensitive information like `GADS_CLIENT_ID`, `GADS_DEVELOPER_TOKEN`, `GADS_REFRESH_TOKEN`, `GADS_CLIENT_SECRET`, `SA360_SFTP_USERNAME`, and `SA360_SFTP_PASSWORD` in plain text.
    - `/code/install_to_gcp.sh`: This script sources the `environment_variables.sh` file, reading the credentials.
    - ```bash
      source ./environment_variables.sh
      ...
      GOOGLE_ADS_API_CREDENTIALS=$"{"$'\n'"  \"developer_token\": \"$GADS_DEVELOPER_TOKEN\","$'\n'"  \"refresh_token\": \"$GADS_REFRESH_TOKEN\","$'\n'"  \"client_id\": \"$GADS_CLIENT_ID\","$'\n'"  \"client_secret\": \"$GADS_CLIENT_SECRET\","$'\n'"  \"login_customer_id\": \"$GADS_MANAGER_ACCOUNT_CUSTOMER_ID\","$'\n'"  \"use_proto_plus\": \"True\""$'\n'"}"
      echo "$GOOGLE_ADS_API_CREDENTIALS" | gcloud secrets create google_ads_api_credentials ...
      echo "$SA360_SFTP_PASSWORD" | gcloud secrets create sa360_sftp_password ...
      ```
        The script takes the values directly from the sourced `environment_variables.sh` and uses them to create secrets in Google Cloud Secret Manager.
    - `/code/cloud_functions/main.py`: The Cloud Function retrieves these secrets from Secret Manager.
    - ```python
      google_ads_api_credentials = _retrieve_secret(
          settings[constants.GCP_PROJECT_ID], constants.GOOGLE_ADS_API_CREDENTIALS)
      ...
      sa_360_sftp_password = _retrieve_secret(settings[constants.GCP_PROJECT_ID],
                                              constants.SA360_SFTP_PASSWORD)
      ```
        The `_retrieve_secret` function fetches the secrets which were populated from `environment_variables.sh`.
    - If a malicious actor can manipulate the content of `environment_variables.sh` before the user runs `install_to_gcp.sh`, the attacker's provided credentials will be used by the Cloud Function.

- Security Test Case:
    1. **Setup Attacker Environment:**
        - Create a GCP project under the attacker's control.
        - Create attacker-controlled Google Ads API credentials (Developer Token, Client ID, Client Secret, Refresh Token) and SA360 SFTP credentials (Hostname, Port, Username, Password).
    2. **Prepare Malicious `environment_variables.sh`:**
        - Download or clone the original SAKA repository.
        - Modify the `/code/environment_variables.sh` file, replacing the placeholder values with the attacker's controlled Google Ads API and SA360 SFTP credentials.
        - For example, set `GADS_DEVELOPER_TOKEN` to the attacker's token, `SA360_SFTP_PASSWORD` to the attacker's password etc.
    3. **Social Engineering Attack:**
        - Trick the victim into downloading and using the modified SAKA repository or specifically the modified `environment_variables.sh` file. This could be done through phishing, offering "easier setup instructions" with a link to the malicious repository, or other social engineering techniques.
    4. **Victim Installation:**
        - The victim, believing they are installing the legitimate SAKA solution, follows the setup guide and uses the attacker-provided `environment_variables.sh` file.
        - The victim runs `bash install_to_gcp.sh` in their GCP project. This script will store the attacker's credentials in the victim's GCP Secret Manager.
        - The victim completes the installation by pushing the code to Cloud Source Repositories, triggering Cloud Build and deploying the Cloud Function.
    5. **Trigger Cloud Function (Attacker Access):**
        - Once the Cloud Function is deployed and triggered (either by schedule or manually), it will retrieve the credentials from Secret Manager.
        - Because these secrets were populated using the attacker's malicious `environment_variables.sh`, the Cloud Function will now use the attacker's credentials to attempt to connect to Google Ads API and SA360 SFTP.
        - **Verification:** The attacker can monitor their controlled Google Ads API and SA360 SFTP accounts for connection attempts originating from the victim's Cloud Function. If successful, the attacker has effectively gained access to the victim's advertising accounts through the compromised credentials.