### Vulnerability List:

- Vulnerability Name: Insecure Storage of Google Ads and SA360 Credentials in `environment_variables.sh`

- Description:
    1. The project requires users to configure sensitive credentials, including Google Ads API credentials (Developer Token, Client ID, Client Secret, Refresh Token) and SA360 SFTP password, by modifying the `environment_variables.sh` file.
    2. This file is located in the root directory of the project and is intended to be edited directly by the user to input their specific configuration values.
    3. If a user mistakenly commits this `environment_variables.sh` file, containing plaintext credentials, to a version control system (like Git), especially a public repository, or if the file is left accessible on a publicly accessible server, these credentials can be easily exposed to unauthorized individuals.
    4. An attacker who gains access to this exposed `environment_variables.sh` file can retrieve the plaintext credentials.
    5. With the Google Ads API credentials, the attacker can then impersonate the legitimate user and gain unauthorized access to their Google Ads account via the Google Ads API.
    6. With the SA360 SFTP password, the attacker might gain access to the SA360 SFTP server, although the hostname, port and username are not stored in this file, limiting the immediate impact without additional information.

- Impact:
    - **High Impact:** Exposure of Google Ads API credentials allows unauthorized access to the victim's Google Ads account.
    - **Data Breach:** Attackers can access and exfiltrate sensitive advertising data from the Google Ads account, including campaign performance data, search terms, and potentially customer-related information.
    - **Account Takeover:** Attackers can manipulate advertising campaigns, budgets, and settings within the Google Ads account, leading to financial losses, reputational damage, and disruption of advertising activities.
    - **Financial Loss:** Unauthorized ad spending and manipulation of campaigns can result in direct financial losses for the victim.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - The `install_to_gcp.sh` script includes the command `git add --all -- ':!environment_variables.sh'` which explicitly excludes `environment_variables.sh` from being added to the Git repository when using the installation script. This is intended to prevent accidental committing of the file.
    - The `.gitignore` mechanism is implicitly used by the installation script's command, but there is no explicit `.gitignore` file in the repository to enforce this exclusion if users manually manage the git repository.

- Missing Mitigations:
    - **Explicit Warning in README and `environment_variables.sh`:** Add a clear and prominent warning in both the `README.md` setup guide and at the beginning of the `environment_variables.sh` file itself, explicitly stating the sensitive nature of the credentials stored in this file and the severe security risks of committing it to version control or exposing it publicly.
    - **Guidance on Secure Handling:** Provide explicit instructions in the `README.md` on secure handling of `environment_variables.sh`, emphasizing that it should *never* be committed to version control and should be protected with appropriate file system permissions.
    - **Enforce `.gitignore`:** Include a `.gitignore` file in the repository that explicitly ignores `environment_variables.sh` to provide an additional layer of protection against accidental commits, regardless of whether the installation script is used.
    - **Alternative Configuration Methods:** Explore and implement more secure and robust methods for handling sensitive configuration, such as:
        - **Environment Variables:**  Instruct users to set environment variables directly in their Cloud Shell or local environment instead of using a file. This reduces the risk of accidental file exposure. The install script could be modified to read directly from environment variables or guide users to set them.
        - **Secure Configuration Management:** Investigate using dedicated secure configuration management tools or GCP services like Secret Manager for initial configuration input, rather than relying on a shell script.
        - **Input via Script Arguments:** Modify the install script to accept sensitive credentials as command-line arguments instead of reading from a file. This would require users to input the secrets directly during installation, reducing the risk of storing them in a persistent file.

- Preconditions:
    1. The user must download or clone the SAKA repository and follow the setup guide.
    2. The user must edit the `environment_variables.sh` file to configure their Google Ads and SA360 credentials.
    3. The user must then, either intentionally or unintentionally, make the `environment_variables.sh` file accessible to an attacker. This could happen by:
        - Accidentally committing and pushing `environment_variables.sh` to a public or accessible Git repository.
        - Leaving the `environment_variables.sh` file on a publicly accessible server or storage location with insecure permissions.
        - Sharing the file directly with unauthorized individuals.

- Source Code Analysis:
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

- Security Test Case:
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

This test case demonstrates how easily the credentials can be exposed if `environment_variables.sh` is mistakenly committed, validating the vulnerability.