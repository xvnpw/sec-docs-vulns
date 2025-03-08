## Combined Vulnerability List

### Vulnerability: Potential Exposure of SA360 SFTP Password and Google Ads API Credentials due to Misconfiguration

- **Description:**
    1. An attacker identifies a publicly accessible GitHub repository containing the SAKA project code.
    2. The attacker reviews the `README.md` and `environment_variables.sh` files, understanding the intended configuration process.
    3. The attacker hypothesizes that a victim might misconfigure the setup by directly embedding sensitive credentials (SA360 SFTP password, Google Ads API credentials) as environment variables in the Cloud Function or by exposing the `environment_variables.sh` file with actual credentials.
    4. The attacker searches for publicly accessible GCP Cloud Functions or Cloud Source Repositories related to SAKA.
    5. If the attacker finds a publicly accessible Cloud Function instance and is able to view its environment variables (depending on GCP project's IAM configuration), the attacker checks for environment variables that might contain the SA360 SFTP password or Google Ads API credentials.
    6. Alternatively, if the attacker finds a publicly accessible Cloud Source Repository that is misconfigured and contains the `environment_variables.sh` file with filled-in credentials, the attacker can directly access these credentials.
    7. If the attacker successfully obtains the SA360 SFTP password and/or Google Ads API credentials, they can use these credentials to gain unauthorized access. For SA360 SFTP password, they can access the victim's SA360 SFTP server. For Google Ads API credentials, they can access and potentially control the victim's Google Ads account.

- **Impact:**
    - High. If SA360 SFTP credentials are exposed, an attacker could gain unauthorized access to the victim's Search Ads 360 account via SFTP. This could allow the attacker to manipulate bulksheets, potentially leading to unauthorized changes in campaigns, keywords, ads, or data exfiltration.
    - High. If Google Ads API credentials are exposed, an attacker could gain unauthorized access to the victim's Google Ads account via the Google Ads API. This could allow the attacker to manipulate campaigns, keywords, ads, budgets, and access sensitive advertising data, potentially leading to financial loss, data breaches, and reputational damage for the victim.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - The `install_to_gcp.sh` script is designed to store sensitive credentials (Google Ads API credentials and SA360 SFTP password) in Google Cloud Secret Manager. This is a secure way to manage secrets and prevents them from being directly embedded in environment variables or code.
    - The `cicd/deploy_saka_cf_to_gcp.yaml` Cloud Build configuration deploys the Cloud Function without directly passing sensitive credentials as environment variables. It relies on the Cloud Function code to retrieve credentials from Secret Manager at runtime.

- **Missing Mitigations:**
    - There is no explicit check in the installation script or Cloud Function code to verify that Secret Manager is correctly configured and being used.
    - There is no explicit warning in the `README.md` or `environment_variables.sh` file about the critical security risk of exposing credentials directly in environment variables or committing `environment_variables.sh` to public repositories.
    - There is no automated check to prevent committing `environment_variables.sh` file with filled-in credentials to the source repository (e.g., a pre-commit hook).

- **Preconditions:**
    - The victim must misconfigure the SAKA setup process. This could involve:
        - Modifying the `install_to_gcp.sh` or deployment process to directly pass SA360 SFTP password and/or Google Ads API credentials as environment variables to the Cloud Function.
        - Committing the `environment_variables.sh` file with actual credentials to a publicly accessible source code repository.
    - The attacker must be able to access the misconfigured environment (e.g., publicly accessible Cloud Function environment variables due to IAM misconfiguration or a publicly accessible source code repository containing the exposed credentials).

- **Source Code Analysis:**
    - `install_to_gcp.sh`: This script correctly uses `gcloud secrets create` to store `google_ads_api_credentials` and `sa360_sftp_password` in Secret Manager. This part of the script is secure.
    - `cicd/deploy_saka_cf_to_gcp.yaml`: This Cloud Build configuration correctly deploys the Cloud Function and sets environment variables using `${_...}` substitutions, which are intended for non-sensitive configuration parameters. It does not directly embed sensitive credentials.
    - `cloud_functions/main.py`: The `_retrieve_secret` function is used to fetch `google_ads_api_credentials` and `sa360_sftp_password` from Secret Manager. This is the secure and intended way to access credentials.
    - **Vulnerability Point**: The vulnerability is not in the code itself, but in the *potential for misconfiguration* during setup. If a user deviates from the intended secure setup (using Secret Manager as shown in `install_to_gcp.sh` and `main.py`) and instead exposes credentials, the system becomes vulnerable. This deviation is not prevented or explicitly warned against by the provided code or documentation beyond the intended secure flow.

- **Security Test Case:**
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

### Vulnerability: Credential Compromise via Social Engineering

- **Description:**
    1. The SAKA setup process requires users to manually configure the `environment_variables.sh` file with sensitive credentials for Google Ads API and SA360 SFTP.
    2. An attacker can use social engineering techniques to trick a victim into downloading a modified version of the SAKA repository or providing manipulated credentials.
    3. This could involve sending phishing emails, creating fake repositories, or compromising the victim's development environment.
    4. If the victim uses the attacker's manipulated `environment_variables.sh` file during the installation process by running `install_to_gcp.sh`, the attacker's credentials will be stored in the Google Cloud Secret Manager.
    5. Subsequently, the SAKA Cloud Function, when triggered, will use these attacker-controlled credentials to access the victim's Google Ads and SA360 accounts.
    6. This grants the attacker unauthorized access to the victim's advertising data and the ability to manipulate ad campaigns.

- **Impact:**
    - Unauthorized access to victim's Google Ads and SA360 accounts.
    - Potential data exfiltration of advertising performance data.
    - Manipulation of ad campaigns, leading to financial losses or reputational damage for the victim.
    - Misuse of advertising budget.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - None in the code itself.
    - The README.md provides a disclaimer stating the solution is experimental and without warranty, and users assume all risks. This is not a technical mitigation but a legal disclaimer.

- **Missing Mitigations:**
    - Input validation in `install_to_gcp.sh` to check the format and validity of provided credentials before storing them in Secret Manager. While full validation might be complex, basic checks could help.
    - Security warnings in the README.md and during the installation process, explicitly highlighting the risk of social engineering and the importance of using strong, unique credentials and obtaining the software from trusted sources.
    - Consider alternative, more secure credential management methods that reduce the reliance on manual user input of sensitive information in plain text files, although this might increase complexity of setup.

- **Preconditions:**
    - The victim must intend to install and use the SAKA solution.
    - The attacker must successfully socially engineer the victim into using malicious credentials during the setup process. This requires tricking the user before they run the `install_to_gcp.sh` script.

- **Source Code Analysis:**
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

- **Security Test Case:**
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

### Vulnerability: Insecure Storage of Google Ads and SA360 Credentials in `environment_variables.sh`

- **Description:**
    1. The project requires users to configure sensitive credentials, including Google Ads API credentials (Developer Token, Client ID, Client Secret, Refresh Token) and SA360 SFTP password, by modifying the `environment_variables.sh` file.
    2. This file is located in the root directory of the project and is intended to be edited directly by the user to input their specific configuration values.
    3. If a user mistakenly commits this `environment_variables.sh` file, containing plaintext credentials, to a version control system (like Git), especially a public repository, or if the file is left accessible on a publicly accessible server, these credentials can be easily exposed to unauthorized individuals.
    4. An attacker who gains access to this exposed `environment_variables.sh` file can retrieve the plaintext credentials.
    5. With the Google Ads API credentials, the attacker can then impersonate the legitimate user and gain unauthorized access to their Google Ads account via the Google Ads API.
    6. With the SA360 SFTP password, the attacker might gain access to the SA360 SFTP server, although the hostname, port and username are not stored in this file, limiting the immediate impact without additional information.

- **Impact:**
    - **High Impact:** Exposure of Google Ads API credentials allows unauthorized access to the victim's Google Ads account.
    - **Data Breach:** Attackers can access and exfiltrate sensitive advertising data from the Google Ads account, including campaign performance data, search terms, and potentially customer-related information.
    - **Account Takeover:** Attackers can manipulate advertising campaigns, budgets, and settings within the Google Ads account, leading to financial losses, reputational damage, and disruption of advertising activities.
    - **Financial Loss:** Unauthorized ad spending and manipulation of campaigns can result in direct financial losses for the victim.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - The `install_to_gcp.sh` script includes the command `git add --all -- ':!environment_variables.sh'` which explicitly excludes `environment_variables.sh` from being added to the Git repository when using the installation script. This is intended to prevent accidental committing of the file.
    - The `.gitignore` mechanism is implicitly used by the installation script's command, but there is no explicit `.gitignore` file in the repository to enforce this exclusion if users manually manage the git repository.

- **Missing Mitigations:**
    - **Explicit Warning in README and `environment_variables.sh`:** Add a clear and prominent warning in both the `README.md` setup guide and at the beginning of the `environment_variables.sh` file itself, explicitly stating the sensitive nature of the credentials stored in this file and the severe security risks of committing it to version control or exposing it publicly.
    - **Guidance on Secure Handling:** Provide explicit instructions in the `README.md` on secure handling of `environment_variables.sh`, emphasizing that it should *never* be committed to version control and should be protected with appropriate file system permissions.
    - **Enforce `.gitignore`:** Include a `.gitignore` file in the repository that explicitly ignores `environment_variables.sh` to provide an additional layer of protection against accidental commits, regardless of whether the installation script is used.
    - **Alternative Configuration Methods:** Explore and implement more secure and robust methods for handling sensitive configuration, such as:
        - **Environment Variables:**  Instruct users to set environment variables directly in their Cloud Shell or local environment instead of using a file. This reduces the risk of accidental file exposure. The install script could be modified to read directly from environment variables or guide users to set them.
        - **Secure Configuration Management:** Investigate using dedicated secure configuration management tools or GCP services like Secret Manager for initial configuration input, rather than relying on a shell script.
        - **Input via Script Arguments:** Modify the install script to accept sensitive credentials as command-line arguments instead of reading from a file. This would require users to input the secrets directly during installation, reducing the risk of storing them in a persistent file.

- **Preconditions:**
    1. The user must download or clone the SAKA repository and follow the setup guide.
    2. The user must edit the `environment_variables.sh` file to configure their Google Ads and SA360 credentials.
    3. The user must then, either intentionally or unintentionally, make the `environment_variables.sh` file accessible to an attacker. This could happen by:
        - Accidentally committing and pushing `environment_variables.sh` to a public or accessible Git repository.
        - Leaving the `environment_variables.sh` file on a publicly accessible server or storage location with insecure permissions.
        - Sharing the file directly with unauthorized individuals.

- **Source Code Analysis:**
    - **`/code/environment_variables.sh`**: This file defines shell variables for all configurations, including:
        ```bash
        GADS_CLIENT_ID=""
        GADS_DEVELOPER_TOKEN=""
        GADS_REFRESH_TOKEN=""
        GADS_CLIENT_SECRET=""
        SA360_SFTP_PASSWORD=""
        ```
        These variables are intended to be set by the user. The file itself contains no security warnings.
    - **`/code/install_to_gcp.sh`**:
        ```bash
        source ./environment_variables.sh
        ...
        GOOGLE_ADS_API_CREDENTIALS=$"{"$'\n'"  \"developer_token\": \"$GADS_DEVELOPER_TOKEN\","$'\n'"  \"refresh_token\": \"$GADS_REFRESH_TOKEN\","$'\n'"  \"client_id\": \"$GADS_CLIENT_ID\","$'\n'"  \"client_secret\": \"$GADS_CLIENT_SECRET\","$'\n'"  \"login_customer_id\": \"$GADS_MANAGER_ACCOUNT_CUSTOMER_ID\","$'\n'"  \"use_proto_plus\": \"True\""$'\n'"}"
        echo "$GOOGLE_ADS_API_CREDENTIALS" | gcloud secrets create google_ads_api_credentials ...
        echo "$SA360_SFTP_PASSWORD" | gcloud secrets create sa360_sftp_password ...
        ...
        git add --all -- ':!environment_variables.sh'
        ```
        The script sources `environment_variables.sh`, reads the credential variables, and then stores them in Secret Manager. Crucially, it attempts to prevent `environment_variables.sh` from being added to git using `git add --all -- ':!environment_variables.sh'`. This indicates an awareness of the sensitivity, but the mitigation is limited to the install script and doesn't prevent manual commits.
    - **`/code/README.md`**: The README guides users to edit `environment_variables.sh` in the "Configuration" step:
        ```markdown
        ### 3. Configuration
        -   In GCP Cloud Shell or your local terminal, navigate to the root directory of
            the SAKA repository and edit the environment_variables.sh file. Supply
            values for the variables, noting the ones that are optional. Explanations of
            each environment variable are shown next to the respective variable.
        ```
        It does not explicitly warn about the security risks of exposing this file, relying only on the implicit exclusion in the install script and not including the file in the subsequent git push instructions.

- **Security Test Case:**
    1. **Setup:** Follow the "Setup Guide" in `README.md` up to step 3 "Configuration".
    2. **Configure Credentials:** Edit `environment_variables.sh` and fill in placeholder values for `GADS_CLIENT_ID`, `GADS_DEVELOPER_TOKEN`, `GADS_REFRESH_TOKEN`, `GADS_CLIENT_SECRET`, and `SA360_SFTP_PASSWORD`. Use *dummy* or *test* credentials for this test; do *not* use real production credentials.
    3. **Initialize Git Repository:** In the root directory of the SAKA project, initialize a Git repository: `git init`.
    4. **Stage `environment_variables.sh`:** Add the `environment_variables.sh` file to the staging area: `git add environment_variables.sh`. This simulates a user mistakenly adding the credentials file.
    5. **Commit Changes:** Commit the staged file: `git commit -m "Accidentally added credentials file"`.
    6. **Create Remote Repository (Simulated Public Exposure):** Create a *private* Git repository on a platform like GitHub, GitLab, or Bitbucket for testing purposes.  Get the repository URL.  *Do not use a public repository for security testing with credentials*.
    7. **Push to Remote:** Add the remote repository and push the local branch:
        ```bash
        git remote add origin <YOUR_PRIVATE_REPO_URL>
        git push -u origin main
        ```
    8. **Verify Exposure in Remote Repository:** Access the *private* remote repository through the web interface or Git client. Browse to the `environment_variables.sh` file in the repository.
    9. **Observe Exposed Credentials:** Confirm that the `environment_variables.sh` file is present in the repository and that the *dummy* credentials you entered in step 2 are visible in plaintext within the file.
    10. **Simulate Attacker Access (Manual Verification):**  As an attacker, if you were to gain access to this repository (e.g., through compromised credentials, misconfigured repository permissions, or if it were mistakenly made public), you could easily find and read the `environment_variables.sh` file and extract the Google Ads API credentials and SA360 SFTP password.
    11. **Cleanup:** Delete the *private* test repository and ensure you have not committed any real credentials.