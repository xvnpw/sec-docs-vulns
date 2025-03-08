- Vulnerability Name: Service Account Credential Exposure
- Description:
    1. The `requests-iap` library is designed to authenticate requests to Google Cloud IAP protected resources using a Google service account.
    2. The library requires users to provide service account credentials in the form of a JSON file (typically named `google-serviceaccount-creds.json`).
    3. This file contains sensitive information, including the private key of the service account.
    4. If an attacker gains unauthorized access to this `google-serviceaccount-creds.json` file, they can use it to impersonate the service account.
    5. By using the compromised service account credentials with the `requests-iap` library or directly with Google Cloud APIs, the attacker can generate valid OIDC tokens.
    6. These tokens can then be used to bypass IAP authentication and access protected resources as if they were the legitimate service account.
- Impact:
    - Complete bypass of Identity-Aware Proxy (IAP) authentication.
    - Unauthorized access to applications and data protected by IAP.
    - Potential data breaches, unauthorized actions within the Google Cloud project, and resource manipulation, depending on the permissions granted to the compromised service account.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None. The library itself does not implement any mitigations for the risk of service account credential exposure. It relies on the user to securely manage the `google-serviceaccount-creds.json` file.
- Missing Mitigations:
    - **Secure Credential Storage Documentation:**  The documentation should strongly emphasize the critical importance of securing the `google-serviceaccount-creds.json` file. It should provide best practices for secure storage, such as:
        - Storing the file in a secure location with restricted access permissions.
        - Avoiding storing the file directly in code repositories.
        - Using environment variables or secure secret management systems to provide the credentials instead of directly referencing a file path.
        - Rotating service account keys regularly.
    - **Warning in README and Code:** Add a prominent warning in the README and potentially in the code itself (e.g., as a comment in `iapauth.py` or during `IAPAuth` class initialization) about the security risks of exposing service account credentials and the user's responsibility to protect them.
- Preconditions:
    1. An attacker must gain unauthorized access to the `google-serviceaccount-creds.json` file used by an application leveraging the `requests-iap` library. This could happen through various means, such as:
        - Compromising the server or system where the file is stored.
        - Exploiting vulnerabilities in the application or infrastructure to gain file system access.
        - Social engineering or insider threats.
        - Accidental exposure (e.g., committing the file to a public code repository).
    2. The application must be configured to use the `requests-iap` library for authentication to Google Cloud IAP protected resources.
- Source Code Analysis:
    1. **`iapauth.py` - `IAPAuth.__init__`**:
        ```python
        class IAPAuth(requests.auth.AuthBase):
            # ...
            def __init__(
                self,
                client_id,
                service_account_secret_dict, # <-- Service account credentials passed here
                jwt_soft_expiration=1800,
                oauth_token_uri="https://www.googleapis.com/oauth2/v4/token",
                jwt_bearer_token_grant_type="urn:ietf:params:oauth:grant-type:jwt-bearer",
            ):
                self.client_id = client_id
                self.service_account_secret_dict = service_account_secret_dict # <-- Stored as object attribute
                # ...
        ```
        - The `IAPAuth` class constructor takes `service_account_secret_dict` as an argument. This dictionary is expected to be loaded from the `google-serviceaccount-creds.json` file, as shown in the `README.md` example.
        - The code directly stores this dictionary as an attribute `self.service_account_secret_dict`.

    2. **`iapauth.py` - `IAPAuth.get_jwt_assertion`**:
        ```python
        def get_jwt_assertion(self):
            message = {
                "kid": self.service_account_secret_dict["private_key_id"], # <-- Private key ID from credentials
                "iss": self.service_account_secret_dict["client_email"], # <-- Client email from credentials
                "sub": self.service_account_secret_dict["client_email"], # <-- Client email from credentials
                "aud": self.oauth_token_uri,
                "iat": int(time.time()),
                "exp": int(time.time()) + 60 * 60,
                "target_audience": self.client_id,
            }

            return jwt.encode(
                message,
                load_pem_private_key(
                    jwt.utils.force_bytes(self.service_account_secret_dict["private_key"]), # <-- Private key from credentials
                    password=None,
                    backend=default_backend(),
                ),
                algorithm="RS256",
            )
        ```
        - The `get_jwt_assertion` method retrieves sensitive information directly from `self.service_account_secret_dict`: `private_key_id`, `client_email`, and crucially, the `private_key`.
        - It uses the `private_key` to sign the JWT assertion.
        - If an attacker has access to `service_account_secret_dict`, they can call this method (or replicate its functionality) to generate valid JWT assertions.

    3. **`iapauth.py` - `IAPAuth.get_google_open_id_connect_token`**:
        ```python
        def get_google_open_id_connect_token(self):
            r = requests.post(
                self.oauth_token_uri,
                timeout=4,
                data={
                    "assertion": self.get_jwt_assertion(), # <-- JWT assertion generated using credentials
                    "grant_type": self.jwt_bearer_token_grant_type,
                },
            )
            r.raise_for_status()
            log.debug("Successfully requested id_token from Google API.")
            return r.json()["id_token"] # <-- OIDC token returned
        ```
        - This method uses the `get_jwt_assertion` method to create a JWT and exchanges it with Google's OAuth2 API to obtain an OIDC token.
        - An attacker with access to the `service_account_secret_dict` can use this entire flow (or replicate it) to obtain valid OIDC tokens that bypass IAP.

    **Visualization:**

    ```
    [Attacker with access to google-serviceaccount-creds.json] --> (Uses requests-iap library or replicates its logic) --> [Generate JWT Assertion (get_jwt_assertion)] --> [Exchange JWT for OIDC Token (get_google_open_id_connect_token)] --> [Valid OIDC Token] --> [Access IAP Protected Resource]
    ```

- Security Test Case:
    1. **Pre-requisites:**
        - Attacker obtains a valid `google-serviceaccount-creds.json` file. This step is outside the scope of testing the library itself but represents the precondition for the vulnerability. For testing purposes, you can simulate this by copying a legitimate service account credentials file to a known location accessible to the test script.
        - Have a test instance of an application protected by Google Cloud IAP. Note down the IAP client ID for this application. Let's say the protected resource URL is `https://service.behind.iap.example.com` and the client ID is `test-client-id`.
    2. **Attacker Action:**
        - Write a Python script that replicates the token generation process of the `requests-iap` library using the compromised `google-serviceaccount-creds.json` file.
        - This script should:
            - Load the `google-serviceaccount-creds.json` file into a dictionary.
            - Instantiate the `IAPAuth` class, passing the client ID of the target IAP-protected application and the loaded credentials dictionary.
            - Call the `get_google_open_id_connect_token()` method of the `IAPAuth` instance to obtain an OIDC token.
        - Use the obtained OIDC token to make a request to the IAP-protected resource (`https://service.behind.iap.example.com`) by setting the `Authorization: Bearer <TOKEN>` header.
    3. **Verification:**
        - The request to `https://service.behind.iap.example.com` should be successful (return a 200 OK status code) and return the content of the protected resource.
        - This demonstrates that an attacker with access to the `google-serviceaccount-creds.json` file can successfully bypass IAP authentication and access protected resources.

    **Python Test Script (Conceptual):**

    ```python
    import requests
    import json
    from requests_iap.iapauth import IAPAuth

    # Path to the compromised service account credentials file (attacker's access)
    credentials_file = "google-serviceaccount-creds.json" # Attacker has obtained this file

    # IAP Client ID of the target application
    client_id = "test-client-id" # Attacker knows the client ID

    with open(credentials_file, "r") as f:
        service_account_secret_dict = json.load(f)

    iap_auth = IAPAuth(client_id=client_id, service_account_secret_dict=service_account_secret_dict)
    oidc_token = iap_auth.get_google_open_id_connect_token()

    headers = {"Authorization": f"Bearer {oidc_token}"}
    target_url = "https://service.behind.iap.example.com" # Target IAP protected resource

    response = requests.get(target_url, headers=headers)

    if response.status_code == 200:
        print("[SUCCESS] Successfully accessed IAP protected resource using compromised credentials.")
        print("Response Content:", response.text)
    else:
        print(f"[FAILURE] Failed to access IAP protected resource. Status code: {response.status_code}")
        print("Response Content:", response.text)
    ```
    **Expected Result:** The test script should successfully access the IAP-protected resource, proving the vulnerability.