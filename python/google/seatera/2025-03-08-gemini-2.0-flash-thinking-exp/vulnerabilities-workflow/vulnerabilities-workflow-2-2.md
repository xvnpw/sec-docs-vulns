- Vulnerability name: Inherent Phishing Susceptibility due to Credential Input Requirement
- Description:
    1. An attacker sets up a malicious instance of SeaTera, mimicking the legitimate application.
    2. The attacker distributes phishing emails or links to advertisers, enticing them to use the malicious SeaTera instance.
    3. Unsuspecting advertisers, believing they are interacting with the legitimate tool, enter their Google Ads API credentials (Client ID, Client Secret, Refresh Token, Developer Token, MCC ID) into the malicious SeaTera instance through the "Authentication" tab in the UI.
    4. The malicious SeaTera instance captures these credentials.
    5. The attacker now has unauthorized access to the advertiser's Google Ads accounts and Google Sheets, using the stolen credentials.
- Impact:
    - Complete compromise of the victim's Google Ads account and potentially associated Google Sheets data.
    - Attackers can manipulate ad campaigns, access sensitive advertising data, incur unauthorized ad spend, and potentially exfiltrate or modify data in connected Google Sheets.
    - Reputational damage to the victim's business and financial loss.
- Vulnerability rank: High
- Currently implemented mitigations:
    - Disclaimer in README.md: "This is not an officially supported Google product." This provides a weak warning but doesn't actively prevent phishing.
    - OAuth 2.0 flow with refresh token: While OAuth 2.0 is used, the application design still necessitates users entering and storing sensitive credentials, making it vulnerable to phishing regardless of the OAuth implementation itself.
- Missing mitigations:
    - Explicit and prominent warnings within the application UI about the phishing risks associated with entering credentials, especially on unofficial instances.
    - Guidance and best practices for users to verify the legitimacy of the SeaTera instance they are using (e.g., checking the URL, official deployment channels).
    - Consider alternative authentication methods that reduce the need for users to directly input and manage long-lived credentials, if feasible for the application's functionality. However, given the current project scope and API requirements, this might be a significant architectural change.
- Preconditions:
    - An attacker needs to deploy a malicious instance of SeaTera.
    - Attackers need to successfully phish advertisers into using the malicious instance and entering their credentials.
    - Advertisers must have Google Ads API credentials and OAuth2 credentials, and be willing to input them into the SeaTera application.
- Source code analysis:
    1. **frontend.py:** The `frontend.py` file contains the UI elements for credential input in the "Authentication" tab.
    ```python
    with st.expander("**Authentication**", expanded=not st.session_state.valid_config):
        if not st.session_state.valid_config:
            client_id = st.text_input("Client ID", value=value_placeholder(config.client_id))
            client_secret = st.text_input("Client Secret", value=value_placeholder(config.client_secret))
            refresh_token = st.text_input("Refresh Token", value=value_placeholder(config.refresh_token))
            developer_token = st.text_input("Developer Token", value=value_placeholder(config.developer_token))
            mcc_id = st.text_input("MCC ID", value=value_placeholder(config.login_customer_id))
            login_btn = st.button("Save", type='primary',on_click=authenticate, args=[{...}])
    ```
    This code block shows that the application directly prompts users for all necessary Google Ads API and OAuth2 credentials through text input fields in the UI.
    2. **frontend.py:** The `authenticate` function in `frontend.py` handles saving these credentials.
    ```python
    def authenticate(config_params):
        st.session_state.config.client_id = config_params['client_id']
        st.session_state.config.client_secret = config_params['client_secret']
        st.session_state.config.refresh_token = config_params['refresh_token']
        st.session_state.config.developer_token = config_params['developer_token']
        st.session_state.config.login_customer_id = config_params['login_customer_id']

        st.session_state.config.check_valid_config()
        st.session_state.valid_config = True
        st.session_state.config.save_to_file()
    ```
    The `authenticate` function takes the credential parameters and saves them to the `Config` object and then persists them to the `config.yaml` file using `st.session_state.config.save_to_file()`.
    3. **utils/config.py:** The `Config.save_to_file()` function in `utils/config.py` saves the credentials to the `config.yaml` file in Google Cloud Storage.
    ```python
    def save_to_file(self):
        try:
            config = deepcopy(self.to_dict())
            blob = self.bucket.blob(CONFIG_FILE_NAME)
            with blob.open('w') as f:
                yaml.dump(config, f)
            print(f"Configurations updated in {self.file_path}")
        except Exception as e:
            print(f"Could not write configurations to {self.file_path} file")
            print(e)
    ```
    This function demonstrates how the user-provided credentials, entered in the frontend, are ultimately stored. This mechanism, while functional, makes the application inherently susceptible to phishing attacks because users are required to input and the application stores these sensitive credentials.

- Security test case:
    1. Deploy a malicious instance of SeaTera on a publicly accessible platform (e.g., using the "Run on Google Cloud" button but under attacker's GCP project).
    2. Create a phishing email that mimics a legitimate communication about SeaTera, enticing advertisers to use the tool. The email should contain a link to the attacker's malicious SeaTera instance URL.
    3. Send the phishing email to target advertisers.
    4. If a target advertiser clicks the link and accesses the malicious SeaTera instance, instruct them (within the test scenario) to enter valid, but *test* Google Ads API credentials into the "Authentication" tab and click "Save".
    5. After the advertiser enters the credentials, the attacker (as the operator of the malicious instance) should be able to access the `config.yaml` file in their GCP storage bucket associated with the malicious SeaTera instance.
    6. Verify that the `config.yaml` file contains the *test* credentials that the advertiser entered.
    7. Using these stolen *test* credentials, attempt to access the advertiser's *test* Google Ads account via the Google Ads API or Google Sheets API to confirm successful credential theft and unauthorized access.

This test case demonstrates how an attacker can leverage the application's design, which requires users to input credentials, to successfully phish and steal those credentials from unsuspecting users.