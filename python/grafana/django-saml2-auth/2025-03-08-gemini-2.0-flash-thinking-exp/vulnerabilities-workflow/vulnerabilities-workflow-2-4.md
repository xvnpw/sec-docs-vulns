### Vulnerabilities:

- Vulnerability Name: Open Redirect in SAML Login Process
- Description:
    - An attacker can craft a malicious URL that, when used as the `next` parameter in the `/accounts/login/` or `/admin/login/` endpoints, redirects a user to an external, attacker-controlled website after successful SAML authentication.
    - Step-by-step trigger:
        1. The attacker identifies a Django application using `django-saml2-auth`.
        2. The attacker crafts a URL to the application's login page (e.g., `/accounts/login/` or `/admin/login/`) and appends a `?next=<malicious_url>` parameter, where `<malicious_url>` is the URL of the attacker's website. For example: `https://vulnerable-app.example.com/accounts/login/?next=https://attacker.com`.
        3. The attacker sends this crafted URL to a victim user or includes it in a phishing campaign.
        4. The victim user clicks on the malicious link and is redirected to the application's login page.
        5. The user initiates the SAML login process and successfully authenticates with their Identity Provider (IdP).
        6. After successful SAML authentication, instead of being redirected to the intended page within the application, the user is redirected to the malicious URL specified in the `next` parameter (`https://attacker.com`).

- Impact:
    - **Phishing:** Attackers can use this vulnerability to create realistic phishing attacks. By redirecting users to a fake login page or a page that mimics the application's interface, attackers can steal user credentials or sensitive information.
    - **Malware Distribution:** Users can be redirected to websites that host malware, leading to system compromise.
    - **Credential Harvesting:**  Users might be tricked into entering their credentials on a fake login page controlled by the attacker after being redirected.
    - **Loss of User Trust:**  If users are unexpectedly redirected to external sites after login, it can erode trust in the application.

- Vulnerability Rank: Medium
- Currently Implemented Mitigations:
    - The project uses Django's `is_safe_url` function in the `signin` view (`django_saml2_auth/views.py`) to validate the `next` URL.
    - The `is_safe_url` function checks if the `next_url` is considered "safe" by comparing its host against the `ALLOWED_REDIRECT_HOSTS` setting in `settings.py`.
    - If `is_safe_url` returns `False`, the user is redirected to the `denied` view, preventing the open redirect in that case.
- Missing Mitigations:
    - **Strict `ALLOWED_REDIRECT_HOSTS` Configuration Enforcement:** The library does not enforce or warn if `ALLOWED_REDIRECT_HOSTS` is not configured or is misconfigured (e.g., empty). The security relies on the Django application developer to correctly set this setting.
    - **Content Security Policy (CSP):**  While not directly mitigating open redirects, CSP headers can help reduce the impact of successful redirects to malicious sites by limiting the resources the browser is allowed to load from those sites. This is not implemented in the library itself but should be considered for applications using it.
- Preconditions:
    - The Django application using `django-saml2-auth` must have either:
        - `ALLOWED_REDIRECT_HOSTS` setting not configured in `settings.py`.
        - `ALLOWED_REDIRECT_HOSTS` setting configured with overly permissive or incorrect values that allow redirection to malicious external hosts.
    - The attacker needs to be able to craft a URL with a malicious `next` parameter and convince a user to click on it.

- Source Code Analysis:
    - File: `/code/django_saml2_auth/views.py`
    - Function: `signin`
    ```python
    @exception_handler
    def signin(request: HttpRequest) -> HttpResponseRedirect:
        ...
        saml2_auth_settings = settings.SAML2_AUTH

        next_url = request.GET.get("next") or get_default_next_url() # [1] Extract next_url from GET parameter
        if not next_url:
            raise SAMLAuthError(...)

        try: # [2] Attempt to extract next URL from within a potentially encoded next parameter, this step is redundant and can be removed.
            if "next=" in unquote(next_url):
                parsed_next_url = urlparse.parse_qs(urlparse.urlparse(unquote(next_url)).query)
                next_url = dictor(parsed_next_url, "next.0")
        except Exception:
            next_url = request.GET.get("next") or get_default_next_url()

        # Only permit signin requests where the next_url is a safe URL
        allowed_hosts = set(dictor(saml2_auth_settings, "ALLOWED_REDIRECT_HOSTS", [])) # [3] Get allowed hosts from settings
        url_ok = is_safe_url(next_url, allowed_hosts) # [4] Validate next_url against allowed_hosts

        if not url_ok: # [5] If not safe, redirect to denied page
            return HttpResponseRedirect(get_reverse([denied, "denied", "django_saml2_auth:denied"]))  # type: ignore

        request.session["login_next_url"] = next_url # [6] Store next_url in session
        ...
        redirect_url = dict(info["headers"]).get("Location", "") # [7] Get redirect URL from SAML client prepare authentication
        return HttpResponseRedirect(redirect_url) # [8] Redirect to IdP, then back to ACS, and finally to next_url (if validation passes in step 4)
    ```
    - **Step [1]:** The `next_url` is obtained from the `GET` request parameters.
    - **Step [2]:** There is an attempt to parse and extract the `next` parameter again if it's encoded within the `next_url`. This step is redundant and might introduce unexpected behavior, but doesn't directly contribute to the open redirect vulnerability itself in a significant way beyond potential parsing issues.
    - **Step [3]:** `ALLOWED_REDIRECT_HOSTS` are retrieved from Django settings. If this setting is missing or misconfigured, `allowed_hosts` will be an empty set or contain unintended hosts.
    - **Step [4]:** `is_safe_url` checks if `next_url` is safe based on `allowed_hosts`. If `allowed_hosts` is empty, `is_safe_url` will incorrectly consider external URLs as safe.
    - **Step [5]:** If `url_ok` is `False` (meaning `is_safe_url` deemed the URL unsafe), the user is redirected to the `denied` page. This is the intended security control.
    - **Step [6]:** If `url_ok` is `True` (or if validation is bypassed due to misconfiguration), the `next_url` is stored in the session.
    - **Step [7] & [8]:** The user is redirected to the Identity Provider (IdP) for authentication. After successful SAML authentication and redirection back to the ACS (Assertion Consumer Service) endpoint, the application will eventually redirect the user to the `next_url` stored in the session (if the initial validation passed or was bypassed).

- Security Test Case:
    - Step-by-step test:
        1. **Setup:** Deploy a Django application using `django-saml2-auth` with SAML authentication configured. Ensure that the `ALLOWED_REDIRECT_HOSTS` setting in `settings.py` is either empty or does not include `attacker.com`.
        2. **Craft Malicious URL:** Create a malicious login URL with a `next` parameter pointing to an external attacker-controlled domain: `https://your-deployed-app.example.com/accounts/login/?next=https://attacker.com`.
        3. **Initiate Login:** Open the crafted URL in a browser or use a tool like `curl`.
        4. **SAML Authentication:**  Proceed through the SAML login process. Successfully authenticate with a test user account against your configured Identity Provider.
        5. **Observe Redirection:** After successful SAML authentication, observe the final redirection URL in the browser or in the `curl` response headers.
        6. **Verify Vulnerability:** Confirm that the user is redirected to `https://attacker.com` instead of a page within the Django application. If the redirection is successful to the attacker's domain, the open redirect vulnerability is confirmed.