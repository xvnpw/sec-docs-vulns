- Vulnerability Name: Insecure Storage of OAuth 2.0 Client Secrets in Configuration File
- Description:
    - The Rubik application requires users to manually create OAuth 2.0 Desktop Client credentials (Client ID and Client Secret) and store them in a YAML configuration file (`rubik.yaml`).
    - The `generate_token.py` script, used to generate access and refresh tokens, explicitly instructs users to input their Client ID and Client Secret.
    - The `README.md` also guides users to obtain these credentials and configure `rubik.yaml`.
    - The `rubik.yaml` file, as shown in the example, is intended to store `client_id` and `client_secret` in plain text.
    - This practice of storing client secrets in a configuration file, especially a version-controlled one or one that might be inadvertently shared, exposes the secret to unauthorized access.
    - An attacker who gains access to the `rubik.yaml` file can extract the Client ID and Client Secret.
- Impact:
    - If an attacker obtains the Client ID and Client Secret, they can impersonate the legitimate application.
    - Using these credentials, an attacker can generate their own access and refresh tokens using `generate_token.py` or similar OAuth 2.0 flows.
    - With valid tokens, the attacker can then access and manipulate the victim's Google Merchant Center account via the Content API, potentially leading to unauthorized changes to product listings, data exfiltration, or other malicious activities within the Merchant Center account.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The application explicitly requires and guides users to store Client ID and Client Secret in `rubik.yaml`.
- Missing Mitigations:
    - **Secure Storage for Client Secret:** The application should not require storing the Client Secret in a plain text configuration file. More secure methods include:
        - Environment variables:  Instruct users to set `CLIENT_ID` and `CLIENT_SECRET` as environment variables instead of storing them in `rubik.yaml`.
        - Secret management services: For more complex deployments, recommend using dedicated secret management services provided by cloud providers or third-party tools.
        - Prompt for Secret at Runtime:  The application could prompt the user to enter the Client Secret each time it runs, instead of storing it persistently. This is less convenient but more secure for desktop applications.
    - **Warning in Documentation:** The documentation (`README.md`) should explicitly warn users about the security risks of storing Client Secrets in `rubik.yaml` and strongly recommend using environment variables or other secure methods.
- Preconditions:
    - The user must have downloaded the Rubik project and followed the setup instructions in `README.md`.
    - The user must have created OAuth 2.0 Desktop Client credentials in Google Cloud Console.
    - The user must have configured `rubik.yaml` with their Client ID and Client Secret.
    - An attacker must gain access to the `rubik.yaml` file. This could happen if the user:
        - Commits `rubik.yaml` to a public repository.
        - Stores `rubik.yaml` in an insecure location accessible to the attacker.
        - Is socially engineered into sharing their `rubik.yaml` file.
- Source Code Analysis:
    - **`generate_token.py`**:
        - The script takes `--client_id` and `--client_secret` as command-line arguments, clearly showing the expectation that these sensitive values are available.
        - It uses `ClientConfigBuilder` to construct OAuth client configuration using the provided `client_id` and `client_secret`.
        - This configuration is then used by `InstalledAppFlow` to initiate the OAuth 2.0 flow.
        - The script's purpose is to generate access and refresh tokens *using* the Client ID and Client Secret, reinforcing their necessity and exposure.
    - **`main.py`**:
        - `main.py` reads the configuration from `rubik.yaml` using `read_from_yaml(config_file)`.
        - The configuration dictionary `rubik_options` obtained from `rubik.yaml` is directly passed to `MerchantCenterUpdaterDoFn`.
        - `MerchantCenterUpdaterDoFn`'s constructor takes `client_id` and `client_secret` directly from `rubik_options`.
    - **`merchant/merchant_center_uploader.py`**:
        - `MerchantCenterUpdaterDoFn` stores `client_id` and `client_secret` as instance attributes.
        - In `_get_merchant_center_service()`, `Credentials` are created using `self.client_id` and `self.client_secret`.
    - **`config/read.py`**:
        - `read_from_yaml(file_name="rubik.yaml")` reads the YAML file and returns the configuration as a dictionary.
    - **`rubik.yaml`**:
        - The example `rubik.yaml` file explicitly shows placeholders for `<client_id>` and `<client_secret>`, indicating direct storage in this file.

    ```
    rubik.yaml example:
    client_id: <client_id>
    client_secret: <client_secret>
    access_token: <access_token>
    refresh_token: <refresh_token>
    ...
    ```

- Security Test Case:
    1. **Setup:**
        - Set up the Rubik application as described in the `README.md`, including creating OAuth 2.0 Desktop Client credentials and configuring `rubik.yaml` with a *test* Merchant Center account's Client ID and Client Secret.
        - Ensure the application runs successfully and can update offers in the test Merchant Center account.
    2. **Attacker Scenario:**
        - Assume the attacker gains access to the `rubik.yaml` file. This could be simulated by simply copying the file.
        - Extract the `client_id` and `client_secret` values from the `rubik.yaml` file.
    3. **Token Generation (Attacker):**
        - On the attacker's machine, run `generate_token.py` script, providing the stolen `client_id` and `client_secret` as command-line arguments:
          ```shell
          python3 generate_token.py --client_id <stolen_client_id> --client_secret <stolen_client_secret>
          ```
        - Follow the OAuth flow as prompted by `generate_token.py`, logging in with an attacker-controlled Google account.
        - The script will output an `access_token` and `refresh_token`.
    4. **Unauthorized Access (Attacker):**
        - Modify a *copy* of the victim's `rubik.yaml` file, replacing the original `access_token` and `refresh_token` with the tokens generated in the previous step (using the stolen Client ID and Secret). Keep the original `client_id` and `client_secret` in the file, or replace them with the stolen ones - it doesn't matter as tokens are already generated.
        - Run `main.py` with the modified `rubik.yaml` against the *victim's test* Merchant Center account (the same account used in step 1).
    5. **Verification:**
        - Observe that the Rubik application, running with the attacker-generated tokens (but based on the victim's Client ID and Secret), successfully authenticates and interacts with the victim's Merchant Center account.
        - This demonstrates that an attacker, possessing the Client ID and Client Secret, can gain unauthorized access to the Merchant Center account.

This test case proves that storing Client ID and Client Secret in `rubik.yaml` leads to a high-severity vulnerability, as it allows for unauthorized access to the Merchant Center account if the configuration file is compromised.