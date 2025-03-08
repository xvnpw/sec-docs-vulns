### Vulnerability List:

- Vulnerability Name: Unverified JWT Token in RelayState for SP-Initiated Login
- Description:
    - Step 1: An attacker crafts a malicious JWT token containing a user identifier (e.g., email address).
    - Step 2: The attacker initiates an SP-initiated login request by accessing the `/sso/sp/` endpoint with a `token` parameter. This token is meant to be a valid JWT previously issued by the application.
    - Step 3: The application decodes the JWT token from the `token` parameter in `sp_initiated_login` view and uses it to construct a SAML authentication request, embedding the JWT as `RelayState`.
    - Step 4: The user is redirected to the Identity Provider (IdP) for authentication.
    - Step 5: After successful authentication at the IdP, the IdP redirects the user back to the application's ACS endpoint (`/sso/acs/`) along with the SAML response and the `RelayState` parameter (containing the JWT token).
    - Step 6: The application's ACS view decodes the JWT token from the `RelayState` parameter. **Vulnerability:** The application trusts the user identifier from the JWT in the `RelayState` without proper verification of the JWT's signature. An attacker could forge a JWT with an arbitrary user identifier, and if the application proceeds without verifying the JWT's integrity, it might lead to authentication bypass or user impersonation within the SAML flow.
- Impact:
    - High. If exploited, an attacker can potentially impersonate any user in the SP-initiated login flow by forging a JWT token with the target user's identifier. This could lead to unauthorized access to user accounts and application resources.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The code decodes the JWT from `RelayState` in both `sp_initiated_login` and `acs` views using `decode_custom_or_default_jwt`, but there is no explicit signature verification step before using the decoded user identifier to proceed with the SAML authentication flow in `sp_initiated_login`. While `decode_jwt_token` *does* perform verification, this is not guaranteed to be enabled or correctly configured by users.
    - `decode_jwt_token` in `django_saml2_auth/user.py` does perform JWT verification using configured keys/secrets. However, the vulnerability lies in the potential bypass within the `sp_initiated_login` flow if the JWT is not properly verified *before* initiating the SAML request.
- Missing Mitigations:
    - In `sp_initiated_login` view, before creating the SAML client and initiating the authentication request, the application should verify the signature of the JWT token received via the `token` parameter. This ensures that the JWT is indeed issued by the application and hasn't been tampered with.
- Preconditions:
    - The application must be configured to use JWT authentication (`USE_JWT = True`).
    - The attacker must be able to craft or obtain a JWT token (even if forged or from a different context).
- Source Code Analysis:
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

    - The vulnerability lies in the `sp_initiated_login` view where the `user_id` is extracted from the JWT passed in the initial GET request and used to create the SAML client. While `decode_custom_or_default_jwt` function itself performs verification, the surrounding logic in `sp_initiated_login` does not explicitly ensure the JWT's integrity *before* proceeding to initiate the SAML authentication request. This creates a window for a forged JWT to be processed.

- Security Test Case:
    - Step 1: Setup:
        - Configure the Django SAML2 Auth plugin with `USE_JWT = True` and a JWT secret or key pair.
        - Ensure SP-initiated login is enabled (default).
        - Have a valid user account in the Django application (created via IdP-initiated flow or other means). Let's say the username is `testuser`.
    - Step 2: Forge JWT Token:
        - Using any JWT library (e.g., PyJWT), forge a JWT token.
        - Set the payload of the JWT to contain the username `testuser` (or email, depending on `USERNAME_FIELD`).
        - **Crucially, sign this JWT with a *different* secret or key than the application's configured JWT secret/key. This simulates an attacker forging a token.**
    - Step 3: Initiate SP-Initiated Login with Forged JWT:
        - Construct the SP-initiated login URL by appending the forged JWT as a `token` parameter to the `/sso/sp/` endpoint. For example: `/sso/sp/?token=<FORGED_JWT_TOKEN>`.
        - Access this URL in a browser or using a tool like `curl`.
    - Step 4: Observe Redirection:
        - You should be redirected to the Identity Provider (IdP) for authentication. This indicates the application proceeded with the SAML flow based on the *unverified* user identifier from the forged JWT.
    - Step 5: Complete SAML Authentication:
        - Authenticate at the IdP using *any* valid IdP credentials. The credentials don't necessarily have to correspond to `testuser` in this case, as we are testing if the initial JWT is properly verified.
    - Step 6: Check Application Access:
        - After successful IdP authentication, you will be redirected back to the application's ACS endpoint.
        - **Expected Result (Vulnerable):** If the application is vulnerable, you will be logged in as the user identified in the *forged JWT token* (`testuser`), regardless of the IdP credentials you used in Step 5. This is because the application trusted the `user_id` from the unverified JWT in the initial SP-initiated login request.
        - **Expected Result (Mitigated):** If the application is properly mitigated, the login should fail, or you should be logged in as a user corresponding to the IdP credentials used in Step 5, but *not* necessarily `testuser` if the IdP credentials are different.  Ideally, the application should reject the request at the `sp_initiated_login` stage if the JWT verification fails.

- Vulnerability Name: Potential Open Redirect in Sign-in View
- Description:
    - Step 1: An attacker crafts a malicious URL with a `next` parameter pointing to an external attacker-controlled domain. For example: `/accounts/login/?next=http://attacker.com`.
    - Step 2: A user, intending to log in to the application, clicks on a link or is redirected to the application's sign-in page (`/accounts/login/`) with the crafted `next` parameter.
    - Step 3: The `signin` view in `django_saml2_auth/views.py` retrieves the `next_url` from the request's GET parameters.
    - Step 4: The view checks if the `next_url` is considered "safe" using `is_safe_url` and `ALLOWED_REDIRECT_HOSTS` setting.
    - Step 5: If `is_safe_url` incorrectly validates the malicious URL (due to configuration issues or bypass vulnerabilities in `is_safe_url` itself), the application proceeds.
    - Step 6: The application redirects the user to the IdP for SAML authentication, embedding the potentially attacker-controlled `next_url` as `RelayState`.
    - Step 7: After successful SAML authentication, the application uses the `RelayState` (attacker-controlled URL) to redirect the user.
- Impact:
    - Medium. Successful exploitation can lead to phishing attacks. An attacker can redirect users to a malicious website after they attempt to log in to the legitimate application, potentially stealing credentials or sensitive information on the attacker-controlled site.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations:
    - The `signin` view uses `django.utils.http.is_safe_url` to validate the `next_url` against the `ALLOWED_REDIRECT_HOSTS` setting.
- Missing Mitigations:
    - Review and strengthen the configuration and usage of `is_safe_url`. Ensure `ALLOWED_REDIRECT_HOSTS` is correctly configured and contains only trusted domains. Regularly audit and update this setting.
    - Consider implementing stricter validation on the `next_url` parameter beyond just host-based checks, potentially including path validation or URL scheme restrictions.
- Preconditions:
    - The application's sign-in view (`/accounts/login/`) is exposed and accessible to users.
    - `ALLOWED_REDIRECT_HOSTS` setting is either misconfigured, too permissive, or `is_safe_url` has a bypass vulnerability (less likely in recent Django versions, but worth considering if using older Django).
- Source Code Analysis:
    - File: `django_saml2_auth/views.py`
    - Function: `signin`

    ```python
    @exception_handler
    def signin(request: HttpRequest) -> HttpResponseRedirect:
        """Custom sign-in view for SP-initiated SSO."""
        saml2_auth_settings = settings.SAML2_AUTH

        next_url = request.GET.get("next") or get_default_next_url() # [POINT OF INTEREST 1] next_url from GET parameter
        if not next_url:
            raise SAMLAuthError("The next URL is invalid.", ...)

        try: # URL Parsing - potentially for extracting 'next' from within next_url, seems redundant/unnecessary for open redirect context
            if "next=" in unquote(next_url):
                parsed_next_url = urlparse.parse_qs(urlparse.urlparse(unquote(next_url)).query)
                next_url = dictor(parsed_next_url, "next.0")
        except Exception:
            next_url = request.GET.get("next") or get_default_next_url()

        # Only permit signin requests where the next_url is a safe URL
        allowed_hosts = set(dictor(saml2_auth_settings, "ALLOWED_REDIRECT_HOSTS", [])) # [POINT OF INTEREST 2] Allowed hosts from settings
        url_ok = is_safe_url(next_url, allowed_hosts) # [POINT OF INTEREST 3] is_safe_url validation

        if not url_ok:
            return HttpResponseRedirect(...) # Redirect to denied if not safe

        request.session["login_next_url"] = next_url

        saml_client = get_saml_client(get_assertion_url(request), acs)
        _, info = saml_client.prepare_for_authenticate(relay_state=next_url)  # type: ignore # [POINT OF INTEREST 4] next_url as RelayState

        redirect_url = dict(info["headers"]).get("Location", "")
        return HttpResponseRedirect(redirect_url) # Redirect to IdP
    ```
    - The code uses `is_safe_url` which is Django's built-in function to prevent open redirects. However, misconfiguration of `ALLOWED_REDIRECT_HOSTS` or potential bypasses in `is_safe_url` (though less likely in modern Django) could still lead to an open redirect. The URL parsing block in the `try...except` seems unnecessary and might even introduce inconsistencies, but is unlikely to be the primary vector for an open redirect here. The core risk lies in the `ALLOWED_REDIRECT_HOSTS` configuration and the robustness of `is_safe_url`.

- Security Test Case:
    - Step 1: Setup:
        - Configure the Django SAML2 Auth plugin.
        - Ensure the sign-in view (`/accounts/login/`) is accessible.
        - **Crucially, intentionally misconfigure `ALLOWED_REDIRECT_HOSTS` to be either empty or to not include your application's domain or any expected safe domains. This simulates a misconfiguration scenario.**
    - Step 2: Craft Malicious URL:
        - Create a malicious URL to the sign-in page with a `next` parameter pointing to an attacker-controlled external domain. For example: `/accounts/login/?next=http://attacker.com`.
    - Step 3: Access Malicious URL:
        - Access the crafted malicious URL in a browser or using a tool like `curl`.
    - Step 4: Observe Redirection after SAML Auth:
        - You will be redirected to the IdP for SAML authentication and proceed with login.
        - After successful SAML authentication at the IdP and redirection back to the application's ACS endpoint, **observe the final redirection.**
        - **Expected Result (Vulnerable):** If the application is vulnerable due to misconfiguration, you will be redirected to `http://attacker.com` after successful SAML authentication. This confirms the open redirect vulnerability.
        - **Expected Result (Mitigated):** If the application is properly mitigated (and `is_safe_url` and `ALLOWED_REDIRECT_HOSTS` are working correctly), you should *not* be redirected to `http://attacker.com`. Instead, you should be redirected to the default next URL or the application's welcome page, indicating that the unsafe `next_url` was correctly blocked.