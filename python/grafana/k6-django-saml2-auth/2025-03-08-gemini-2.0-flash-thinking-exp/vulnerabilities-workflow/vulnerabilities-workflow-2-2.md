- Vulnerability Name: Open Redirect in signin view
- Description:
    - An attacker can craft a malicious URL for the `signin` view by appending a `next` parameter that points to an external, attacker-controlled website.
    - When a user clicks on this crafted URL, they will be redirected to the SAML Identity Provider (IdP) for authentication.
    - After successful SAML authentication, the Django application will redirect the user to the URL specified in the `next` parameter.
    - If the `ALLOWED_REDIRECT_HOSTS` setting is misconfigured or too permissive, the `is_safe_url` check in `signin` view might pass even for malicious external URLs.
    - This allows the attacker to redirect users to a malicious website after they successfully log in via SAML.
    - This can be used for phishing attacks, where the attacker's site mimics a legitimate login page to steal user credentials or session tokens after SAML authentication on the legitimate site.
- Impact:
    - Phishing attacks: Users could be redirected to fake login pages after successful SAML authentication, potentially leading to credential theft if they re-enter their credentials on the attacker's site.
    - Malware distribution: Attackers could redirect users to websites hosting malware, infecting their systems.
    - Session hijacking: In scenarios where session tokens are exposed after redirection, attackers might be able to hijack user sessions.
    - Brand damage: If users are successfully phished or harmed due to redirection from a legitimate service, it can damage the reputation and trust in the service.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - The project uses Django's `is_safe_url` function to validate the `next` parameter against a list of allowed hosts defined in the `ALLOWED_REDIRECT_HOSTS` setting.
    - This check is implemented in the `signin` view before redirecting the user.
- Missing Mitigations:
    - Strict and properly configured `ALLOWED_REDIRECT_HOSTS`: The default configuration or overly broad configurations of `ALLOWED_REDIRECT_HOSTS` can negate the effectiveness of `is_safe_url`. It should be carefully reviewed and restricted to only trusted domains.
    - Content Security Policy (CSP) header: Implementing a CSP header can help mitigate the impact of open redirects by restricting the domains from which the application can load resources, although it doesn't prevent the redirect itself.
    - Robust input validation and sanitization: While `is_safe_url` is used, additional checks could be implemented to further validate the `next` URL, ensuring it's not only on an allowed host but also conforms to expected URL patterns within the application.
    - Consider removing or deprecating the `signin` view`: The documentation mentions that `signin` view will be deprecated in favor of `sp_initiated_login`. Deprecating and removing potentially vulnerable legacy features reduces attack surface.
- Preconditions:
    - The application must have the `signin` view enabled and accessible.
    - The `ALLOWED_REDIRECT_HOSTS` setting must be either misconfigured (too permissive, allowing external hosts) or not configured at all (in which case `is_safe_url` might still be bypassed under certain conditions depending on Django version and configuration).
- Source Code Analysis:
    - File: `/code/django_saml2_auth/views.py`
    - Function: `signin(request: HttpRequest)`
    ```python
    @exception_handler
    def signin(request: HttpRequest) -> HttpResponseRedirect:
        # ...
        saml2_auth_settings = settings.SAML2_AUTH
        next_url = request.GET.get("next") or get_default_next_url()
        if not next_url:
            # ...
            pass

        # ... (URL parsing logic - not directly related to vulnerability, but can complicate analysis)

        # Only permit signin requests where the next_url is a safe URL
        allowed_hosts = set(dictor(saml2_auth_settings, "ALLOWED_REDIRECT_HOSTS", []))
        url_ok = is_safe_url(next_url, allowed_hosts) # [POINT OF VULNERABILITY MITIGATION CHECK]

        if not url_ok:
            return HttpResponseRedirect(
                get_reverse([denied, "denied", "django_saml2_auth:denied"]))  # type: ignore

        request.session["login_next_url"] = next_url
        # ...
        _, info = saml_client.prepare_for_authenticate(relay_state=next_url) # next_url is used as RelayState
        redirect_url = dict(info["headers"]).get("Location", "")
        return HttpResponseRedirect(redirect_url) # Redirect to IdP
    ```
    - The `signin` view retrieves the `next` parameter from the GET request.
    - It uses `is_safe_url(next_url, allowed_hosts)` to check if the `next_url` is considered "safe".
    - `allowed_hosts` is derived from the `ALLOWED_REDIRECT_HOSTS` setting.
    - If `is_safe_url` returns `False`, the user is redirected to the `denied` view.
    - However, if `is_safe_url` returns `True` (due to misconfiguration of `ALLOWED_REDIRECT_HOSTS` or vulnerabilities in `is_safe_url` itself), the user will be redirected to the potentially malicious URL after SAML authentication.
- Security Test Case:
    - Pre-requisites:
        - An instance of the Django application with SAML2 authentication enabled and the `signin` view exposed.
        - `ALLOWED_REDIRECT_HOSTS` setting should be configured to include or mistakenly allow an external domain (e.g., `["https://malicious.example.com"]` or an empty list which might be vulnerable depending on Django version). Alternatively, test without `ALLOWED_REDIRECT_HOSTS` to see default behavior of `is_safe_url`.
    - Steps:
        1. Craft a malicious URL for the `signin` view, including a `next` parameter pointing to an attacker-controlled website (e.g., `https://your-django-app/accounts/login/?next=https://malicious.example.com`).
        2. Open the crafted URL in a web browser.
        3. Observe that you are redirected to the SAML Identity Provider for authentication.
        4. Complete the SAML authentication process successfully.
        5. After successful authentication, verify that you are redirected to `https://malicious.example.com` instead of the intended application page.
    - Expected Result:
        - After successful SAML authentication, the browser should redirect to `https://malicious.example.com`, demonstrating the open redirect vulnerability. If the redirection is blocked and you are redirected to the `denied` page, then the current configuration is preventing the open redirect for this specific malicious URL, but further testing with different configurations and URLs might be needed to ensure complete mitigation.