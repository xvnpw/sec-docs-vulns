- Vulnerability Name: Insecure Session Management due to missing `httponly` flag in session cookie
    - Description:
        1. The `SessionInterface.save_session` function in `/code/securedrop/journalist_app/sessions.py` sets the session cookie.
        2. It does not explicitly set the `httponly` flag when creating or updating the session cookie.
        3. Without the `httponly` flag, JavaScript code running in the user's browser can access the session cookie.
        4. An attacker could potentially exploit a Cross-Site Scripting (XSS) vulnerability to steal the session cookie.
        5. Once the attacker has the session cookie, they can impersonate the journalist and gain unauthorized access to the journalist interface.
    - Impact:
        - High. An attacker can gain unauthorized access to the journalist interface, potentially leading to the compromise of sensitive documents submitted by anonymous sources.
    - Vulnerability Rank: High
    - Currently Implemented Mitigations:
        - None. The code does not explicitly set the `httponly` flag for the session cookie.
    - Missing Mitigations:
        - Implement the `httponly` flag for the session cookie in the `SessionInterface.save_session` function in `/code/securedrop/journalist_app/sessions.py`. This will prevent client-side JavaScript from accessing the session cookie, mitigating the risk of session hijacking via XSS.
    - Preconditions:
        - An attacker needs to find a way to inject and execute JavaScript code within the journalist application's domain (e.g., via a stored XSS vulnerability, which is not analyzed in provided files but is a common web application vulnerability).
    - Source Code Analysis:
        1. Open `/code/securedrop/journalist_app/sessions.py`.
        2. Go to the `SessionInterface.save_session` function.
        3. Examine the `response.set_cookie` call.
        4. Observe that the `httponly` parameter is not set.

        ```python
        # File: /code/securedrop/journalist_app/sessions.py
        class SessionInterface(FlaskSessionInterface):
            # ...
            def save_session(  # type: ignore[override]
                self, app: Flask, session: ServerSideSession, response: Response
            ) -> None:
                # ...
                if not session.is_api and (session.new or session.to_regenerate):
                    response.headers.add("Vary", "Cookie")
                    response.set_cookie(
                        app.session_cookie_name,
                        session.token,
                        httponly=httponly, # httponly is defined above, but it is always None
                        domain=domain,
                        path=path,
                        secure=secure,
                        samesite=samesite,
                    )
        ```
        5. Notice that `httponly` variable is used, but it is never assigned a value, therefore it defaults to `None` which in `response.set_cookie` means `httponly` flag is not set.
    - Security Test Case:
        1. Deploy a SecureDrop instance.
        2. Log in to the journalist interface.
        3. Using browser developer tools (e.g., in Firefox or Chrome), inspect the session cookie for the journalist interface (usually named `session`).
        4. Verify that the `httponly` flag is NOT set for the session cookie. You can typically see this in the "Cookies" section of the developer tools, by inspecting cookie details. If `httponly` is set, you will see `HttpOnly` attribute set to `true`. If `httponly` is not set, you will not see `HttpOnly` attribute set to `true`.
        5. Assume there is an XSS vulnerability in the Journalist Interface (this test case focuses on session hijacking, not finding XSS, so we assume XSS exists).
        6. As an attacker, inject JavaScript code (e.g., via XSS) into a page in the journalist interface that can access document.cookie.
        7. The injected JavaScript code should be able to read the session cookie value. For example, `document.cookie` in JavaScript will return the session cookie string.
        8. As an attacker, exfiltrate the session cookie (e.g., send it to an attacker-controlled server).
        9. Using the stolen session cookie, attempt to access the journalist interface from a different browser or machine, without providing valid login credentials.
        10. If successful, you will be logged in as the journalist, demonstrating session hijacking.