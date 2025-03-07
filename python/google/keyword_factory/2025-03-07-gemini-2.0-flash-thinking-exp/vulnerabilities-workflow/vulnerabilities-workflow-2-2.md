- Vulnerability Name: OAuth2 Credential Phishing and Stored Credentials Vulnerability
- Description:
    1. Attacker sets up a fake website that looks identical to the legitimate Keyword Factory application.
    2. Attacker distributes the link to the fake website to Google Ads users, possibly via phishing emails or ads.
    3. Unsuspecting users click the link and are presented with the fake Keyword Factory application.
    4. Users, believing it is the legitimate tool, enter their Google Ads API and Google Sheets API OAuth2 credentials (Client ID, Client Secret, Refresh Token, Developer Token, MCC ID) into the "Authentication" tab of the fake application and click "Save".
    5. The fake application captures these credentials.
    6. If the fake application is a true mimic, it might even store these credentials in a `config.yaml` file, similar to the real application's behavior, potentially on attacker-controlled storage.
    7. Alternatively, the attacker could directly exploit the legitimate application if they gain access to the storage where `config.yaml` is saved (e.g., GCS bucket if permissions are misconfigured or Cloud Run instance if compromised).
    8. With the stolen OAuth2 credentials from either the phishing site or compromised config file, the attacker can now access the victim's Google Ads and Google Sheets accounts using the Google Ads API and Google Sheets API.
- Impact:
    - Critical: Full unauthorized access to victim's Google Ads and Google Sheets accounts. Attackers can modify campaigns, access sensitive data, incur ad spending, and manipulate data in Google Sheets.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - Disclaimer in README.md: "This is not an officially supported Google product." - This warns users but is not a technical mitigation.
- Missing Mitigations:
    - No protection against phishing: The application itself does not have any built-in mechanism to verify its authenticity to the user or prevent being mimicked by a fake site.
    - Storing credentials in config.yaml: Storing sensitive OAuth2 credentials in a configuration file, even in a GCS bucket, increases the risk if the bucket is compromised or permissions are weak. More secure credential management practices should be implemented.
- Preconditions:
    - Users must be tricked into using the fake application or the attacker gains access to the storage where `config.yaml` is stored in a legitimate deployment.
    - Users must have Google Ads and Google Sheets accounts and OAuth2 credentials for these APIs.
- Source Code Analysis:
    - /code/app.py:
        - `authenticate(config_params)` function in `app.py` takes client\_id, client\_secret, refresh\_token, developer\_token, login\_customer\_id from user input.
        - It calls `st.session_state.config.client_id = config_params['client_id']` and similar lines to set these parameters in the `Config` object.
        - It calls `st.session_state.config.save_to_file()` which, as seen in `/code/utils/config.py`, saves these credentials to `config.yaml`.
    - /code/utils/config.py:
        - `Config.save_to_file()` function writes the credential attributes (client\_id, client\_secret, refresh\_token, developer\_token, login\_customer\_id, spreadsheet\_url) into `config.yaml` file using `yaml.dump()`.
        - `Config._config_file_path_set()` determines the file path for `config.yaml`. It tries to use GCS path `gs://{project_id}-keyword_factory/config.yaml` if running in GCP environment, otherwise defaults to local `config.yaml`.
- Security Test Case:
    1. Setup Fake Website: Create a simple HTML page that visually mimics the "Authentication" tab of the Keyword Factory application UI from `app.py`. Include the same input fields (Client ID, Client Secret, Refresh Token, Developer Token, MCC ID) and a "Save" button.
    2. Deploy Fake Website: Host this fake website on a publicly accessible domain (e.g., using a free hosting service or a temporary domain). Make the URL look somewhat similar to a plausible (but fake) application URL.
    3. Phishing Attack: Send a phishing email or message to a target Google Ads user. The email should:
        - Contain a plausible scenario where the user might need to use a keyword tool.
        - Include a link to the fake website created in step 2, disguised as a link to the real Keyword Factory.
    4. Victim Interaction: Wait for the victim to click the link and visit the fake website.
    5. Credential Capture: If the victim enters their real Google Ads API and Google Sheets API OAuth2 credentials into the fields on the fake website and clicks the "Save" button, the fake website should log or send these credentials to the attacker (this part depends on the attacker's implementation of the fake website). A simple implementation would be to just log the POST request data.
    6. Verification of Access: Using the captured credentials, attempt to authenticate with the Google Ads API and Google Sheets API. Successfully accessing the APIs using the phished credentials proves the vulnerability. For example, use the Google Ads API client library to make a simple API call (like listing campaigns) using the phished credentials. If successful, unauthorized access is confirmed.