## Combined Vulnerability List

### Vulnerability: Unverified JWT Token in RelayState for SP-Initiated Login

- **Description:**
    - Step 1: An attacker crafts a malicious JWT token containing a user identifier (e.g., email address).
    - Step 2: The attacker initiates an SP-initiated login request by accessing the `/sso/sp/` endpoint with a `token` parameter. This token is meant to be a valid JWT previously issued by the application.
    - Step 3: The application decodes the JWT token from the `token` parameter in `sp_initiated_login` view and uses it to construct a SAML authentication request, embedding the JWT as `RelayState`.
    - Step 4: The user is redirected to the Identity Provider (IdP) for authentication.
    - Step 5: After successful authentication at the IdP, the IdP redirects the user back to the application's ACS endpoint (`/sso/acs/`) along with the SAML response and the `RelayState` parameter (containing the JWT token).
    - Step 6: The application's ACS view decodes the JWT token from the `RelayState` parameter. **Vulnerability:** The application trusts the user identifier from the JWT in the `RelayState` without proper verification of the JWT's signature in `sp_initiated_login` view before initiating SAML flow. An attacker could forge a JWT with an arbitrary user identifier, and if the application proceeds without verifying the JWT's integrity, it might lead to authentication bypass or user impersonation within the SAML flow.
- **Impact:**
    - High. If exploited, an attacker can potentially impersonate any user in the SP-initiated login flow by forging a JWT token with the target user's identifier. This could lead to unauthorized access to user accounts and application resources.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - None. The code decodes the JWT from `RelayState` in both `sp_initiated_login` and `acs` views using `decode_custom_or_default_jwt`, but there is no explicit signature verification step in `sp_initiated_login` view before using the decoded user identifier to proceed with the SAML authentication flow. While `decode_jwt_token` *does* perform verification, this is not guaranteed to be enabled or correctly configured to be enforced in `sp_initiated_login` flow.
- **Missing Mitigations:**
    - In `sp_initiated_login` view, before creating the SAML client and initiating the authentication request, the application should explicitly verify the signature of the JWT token received via the `token` parameter. This ensures that the JWT is indeed issued by the application and hasn't been tampered with.
- **Preconditions:**
    - The application must be configured to use JWT authentication (`USE_JWT = True`).
    - The attacker must be able to craft or obtain a JWT token (even if forged or from a different context).
- **Source Code Analysis:**
    - File: `django_saml2_auth/views.py`
    - Function: `sp_initiated_login`

    ```python
    @exception_handler
    def sp_initiated_login(request: HttpRequest) -> HttpResponseRedirect:
        """This view is called by the SP to initiate a login to IdP, aka. SP-initiated SAML SSP."""
        if request.method == "GET":
            token = request.GET.get("token") # [POINT OF INTEREST 1] JWT Token from GET Parameter
            if token:
                user_id = decode_custom_or_default_jwt(token) # [POINT OF INTEREST 2] JWT Decoding - Verification happens here, but...
                if not user_id:
                    raise SAMLAuthError("The token is invalid.", ...)
                saml_client = get_saml_client(get_assertion_url(request), acs, user_id) # [POINT OF INTEREST 3] User_id from decoded JWT is used to create SAML Client.
                jwt_token = create_custom_or_default_jwt(user_id)
                _, info = saml_client.prepare_for_authenticate(  # type: ignore
                    sign=False, relay_state=jwt_token) # [POINT OF INTEREST 4] JWT is embedded as RelayState
                redirect_url = dict(info["headers"]).get("Location", "")
                if not redirect_url:
                    return HttpResponseRedirect(...)
                return HttpResponseRedirect(redirect_url)
        else:
            raise SAMLAuthError("Request method is not supported.", ...)
        return HttpResponseRedirect(...)
    ```
    - **Visualization:**

    ```mermaid
    sequenceDiagram
    participant Attacker
    participant SP-Initiated Login View
    participant SAML Client
    participant Identity Provider (IdP)
    participant ACS View

    Attacker->>SP-Initiated Login View: GET /sso/sp/?token=FORGED_JWT_TOKEN
    SP-Initiated Login View->>decode_custom_or_default_jwt: decode(FORGED_JWT_TOKEN)
    decode_custom_or_default_jwt-->>SP-Initiated Login View: user_id (from forged JWT)  //Potentially UNVERIFIED if JWT is forged
    SP-Initiated Login View->>SAML Client: get_saml_client(..., user_id) // User_id used without explicit verification in sp_initiated_login view
    SP-Initiated Login View->>create_custom_or_default_jwt: create_jwt(user_id)
    create_custom_or_default_jwt-->>SP-Initiated Login View: NEW_JWT_TOKEN
    SP-Initiated Login View->>SAML Client: prepare_for_authenticate(relay_state=NEW_JWT_TOKEN)
    SAML Client-->>SP-Initiated Login View: Redirect URL to IdP
    SP-Initiated Login View->>Attacker: 302 Redirect to IdP (RelayState=NEW_JWT_TOKEN)

    Attacker->>IdP: User Authentication
    IdP-->>Attacker: Authentication Success

    Attacker->>ACS View: POST /sso/acs/ (SAMLResponse, RelayState=NEW_JWT_TOKEN)
    ACS View->>decode_saml_response: decode(SAMLResponse)
    decode_saml_response-->>ACS View: AuthnResponse
    ACS View->>decode_custom_or_default_jwt: decode(NEW_JWT_TOKEN) // Decodes RelayState JWT
    decode_custom_or_default_jwt-->>ACS View: redirected_user_id
    ACS View->>extract_user_identity: extract(AuthnResponse)
    extract_user_identity-->>ACS View: user_identity
    ACS View->>get_user_id: get_user_id(user_identity)
    get_user_id-->>ACS View: saml_user_id
    ACS View->>get_or_create_user: get_or_create_user(user_identity)
    get_or_create_user-->>ACS View: target_user
    ACS View->>login: login(target_user)
    ACS View->>Attacker: 302 Redirect to Welcome Page / Next URL
    ```

- **Security Test Case:**
    - Step 1: Setup:
        - Configure the Django SAML2 Auth plugin with `USE_JWT = True` and a JWT secret or key pair.
        - Ensure SP-initiated login is enabled (default).
        - Have a valid user account in the Django application.
    - Step 2: Forge JWT Token:
        - Using any JWT library, forge a JWT token.
        - Set the payload of the JWT to contain the username of the valid user account.
        - Sign this JWT with a *different* secret or key than the application's configured JWT secret/key.
    - Step 3: Initiate SP-Initiated Login with Forged JWT:
        - Construct the SP-initiated login URL by appending the forged JWT as a `token` parameter to the `/sso/sp/` endpoint.
        - Access this URL in a browser or using a tool like `curl`.
    - Step 4: Observe Redirection:
        - You should be redirected to the Identity Provider (IdP) for authentication.
    - Step 5: Complete SAML Authentication:
        - Authenticate at the IdP using *any* valid IdP credentials.
    - Step 6: Check Application Access:
        - After successful IdP authentication, you will be redirected back to the application's ACS endpoint.
        - **Expected Result (Vulnerable):** You will be logged in as the user identified in the *forged JWT token*, regardless of the IdP credentials you used in Step 5.

### Vulnerability: XML Signature Wrapping Vulnerability

- **Description:**
    1. An attacker intercepts a legitimate SAML Response from the Identity Provider (IdP) to the Service Provider (SP) (Django application).
    2. The attacker manipulates the XML structure of the SAML Response by adding a new assertion that they crafted, "wrapping" the original signed assertion.
    3. The attacker preserves the original, valid XML Signature from the legitimate SAML Assertion and positions it to appear as if it is signing the attacker's malicious assertion or the entire modified SAML Response.
    4. The attacker sends the manipulated SAML Response to the Django SAML2 Authentication SP endpoint (`acs` view).
    5. Due to improper XML signature verification on the SP side, the system might only validate the presence of a signature and its basic validity but fail to verify *what* exactly is being signed.
    6. If the vulnerability exists, the Django SAML2 Authentication library could be tricked into accepting the manipulated SAML Response as valid, because it contains a valid signature, even though the signature might not cover the attacker's injected malicious content.
    7. The system processes the attacker's crafted assertion, potentially granting unauthorized access or privileges based on the attacker-controlled content.
- **Impact:**
    - Critical.
        - Authentication bypass: An attacker can gain unauthorized access to the Django application without valid credentials.
        - Privilege escalation: By manipulating the attributes within the SAML assertion, an attacker might be able to elevate their privileges.
        - Data manipulation: A successful wrapping attack could lead to data manipulation or unauthorized actions within the application.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    - `WANT_ASSERTIONS_SIGNED = True` setting: Enforces that assertions within the SAML response are signed.
    - `WANT_RESPONSE_SIGNED = True` setting: Enforces that the entire SAML response is signed.
    - These settings are configurable via `settings.py`.
- **Missing Mitigations:**
    - Robust XML Signature Verification: Verifying that the signature covers the *entire* SAML Assertion element and/or the relevant parts of the SAML Response.
    - Using an XML parser and signature validation library explicitly designed to prevent XML Signature Wrapping attacks.
    - Implementing checks to ensure that the signed elements are the expected ones without unexpected or redundant elements.
- **Preconditions:**
    - `WANT_ASSERTIONS_SIGNED` and `WANT_RESPONSE_SIGNED` are set to `True` (or default `True`).
    - The attacker can intercept SAML responses between the IdP and SP.
    - The Identity Provider is configured to sign SAML Assertions and/or Responses.
- **Source Code Analysis:**
    - File: `django_saml2_auth/saml.py`
    - Function: `decode_saml_response`
    - Relies on `pysaml2.client.Saml2Client.parse_authn_request_response` for signature verification. The vulnerability depends on the robustness of `pysaml2` library against XML Signature Wrapping attacks, which needs further investigation of `pysaml2` source code and security advisories. There is no explicit mitigation code for wrapping attacks in `django-saml2-auth` beyond relying on `pysaml2` and signature requirement settings.

    **Visualization of XML Signature Wrapping Attack:**

    ```
    [IdP] --> SAML Response (Signed Assertion) --> [Attacker] --> Manipulated SAML Response (Wrapped Assertion, Original Signature) --> [SP - Django App]

    [SP - Django App] -- Processes Response --> [Incorrectly Validates Signature] --> [Authentication Bypass]
    ```

- **Security Test Case:**
    1. **Setup:**
        - Set up a Django application using `django-saml2-auth` with `WANT_ASSERTIONS_SIGNED = True` and `WANT_RESPONSE_SIGNED = True`.
        - Configure a SAML Identity Provider to work with the Django application, ensuring it signs SAML Assertions.
        - Use SAML Tracer or Burp Suite to intercept SAML Responses.
    2. **Capture Legitimate SAML Response:**
        - Initiate a SAML login to the Django application.
        - Capture a valid SAML Response from the IdP.
        - Save the SAML Response XML.
    3. **Manipulate SAML Response (XML Wrapping):**
        - Using an XML editor, add a *new, malicious* Assertion element and "wrap" the original, *validly signed* Assertion, preserving the original `<ds:Signature>`.
    4. **Send Manipulated SAML Response:**
        - Base64 encode the manipulated SAML Response XML.
        - Craft a POST request to the Django application's `acs` endpoint with the encoded SAML Response.
    5. **Observe Authentication Outcome:**
        - Send the crafted POST request.
        - **Expected Vulnerable Behavior:** The application incorrectly validates the manipulated SAML Response and grants access.
    6. **Analyze Logs (if vulnerable):**
        - Examine Django application logs and SAML library's debug logs to confirm processing of the manipulated assertion.