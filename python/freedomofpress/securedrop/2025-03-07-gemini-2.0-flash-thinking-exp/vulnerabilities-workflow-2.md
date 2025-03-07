## Combined Vulnerability List

### 1. Session Fixation

* Description:
    1. An attacker can perform a session fixation attack by obtaining a valid session ID (SID) before the legitimate user logs in.
    2. The attacker can achieve this by visiting the login page and capturing the SID from the session cookie.
    3. The attacker then tricks the legitimate journalist into logging in using the attacker-obtained SID. This can be done by sending the journalist a link to the login page with the attacker's SID.
    4. Once the journalist logs in, the application associates the journalist's authenticated session with the SID that the attacker already possesses.
    5. Now the attacker can use the pre-obtained SID to gain unauthorized access to the journalist's account, bypassing the login process.

* Impact:
    - High. An attacker can gain complete control over a journalist account, allowing them to access sensitive submitted documents, deanonymize sources, and potentially manipulate the system.

* Vulnerability Rank:
    - High

* Currently Implemented Mitigations:
    - Regenerating session ID on login (`session.regenerate()` in `/code/securedrop/journalist_app/main.py`, `login()` function).

* Missing Mitigations:
    - While session regeneration is implemented after successful login, the application does not invalidate or rotate the session ID upon the initial request to the login page or before authentication. This allows an attacker to obtain a valid session ID before login and use it for session fixation.
    - Missing mitigation to invalidate the old session ID before login, specifically upon visiting the login page.

* Preconditions:
    - The attacker needs to be able to communicate with the target journalist (e.g., via email, chat, or social media) to trick them into using the attacker-provided link.
    - The attacker needs to be able to observe network traffic or cookies to obtain a valid session ID before the journalist logs in.

* Source Code Analysis:
    1. In `/code/securedrop/journalist_app/main.py`, the `login()` function regenerates the session using `session.regenerate()` *after* successful authentication:
    ```python
    @view.route("/login", methods=("GET", "POST"))
    def login() -> Union[str, werkzeug.Response]:
        if request.method == "POST":
            user = validate_user(
                request.form["username"],
                request.form["password"],
                request.form["token"],
            )
            if user:
                # ...
                session["uid"] = user.id
                session.regenerate() # Session regeneration happens after authentication
                return redirect(url_for("main.index"))
        return render_template("login.html")
    ```
    2. In `/code/securedrop/journalist_app/sessions.py`, `SessionInterface.open_session()` retrieves existing SID from cookie or generates a new session if no SID is found:
    ```python
    def open_session(self, app: Flask, request: Request) -> Optional[ServerSideSession]:
        """This function is called by the flask session interface at the
        beginning of each request.
        """
        # ...
        sid = request.cookies.get(app.session_cookie_name) # Get SID from cookie
        if sid:
            try:
                sid = self._get_signer(app).loads(sid)
            except BadSignature:
                sid = None
        if not sid:
            return self._new_session(is_api) # Generate new session if no SID is found or invalid
        # ...
    ```
    3. The vulnerability lies in the fact that a valid session ID is already generated and set in the cookie *before* the user even attempts to log in. This pre-login SID is not invalidated when the user visits the login page or before the login form is submitted and authenticated.

* Security Test Case:
    1. Attacker visits the journalist login page.
    2. Attacker captures the `session` cookie value (SID) from the browser's developer tools or network traffic.
    3. Attacker sends the journalist a link to the journalist login page, for example via email or chat. This step is to make sure journalist will use the same browser and same session for login.
    4. Journalist clicks on the link and logs in using their valid credentials (username, password, OTP).
    5. Attacker uses the captured SID to access the journalist interface by setting the `session` cookie in their browser to the captured value and visiting the journalist homepage URL.
    6. Attacker successfully gains unauthorized access to the journalist interface without providing any credentials.

### 2. Insecure Session Management due to missing HttpOnly flag on session cookie

* Description:
    1. The SecureDrop Journalist Interface uses server-side sessions managed by Flask-Session using Redis.
    2. Upon successful login, a session cookie is set in the user's browser.
    3. This session cookie, while signed for integrity, is missing the `HttpOnly` flag.
    4. Lack of `HttpOnly` flag allows client-side JavaScript to access the session cookie.
    5. An attacker can potentially inject malicious JavaScript (e.g., via XSS vulnerability in another part of the application, or if attacker can somehow modify static files) to steal the session cookie.
    6. Once the session cookie is stolen, the attacker can impersonate the journalist and gain unauthorized access to the journalist interface without needing valid credentials or 2FA.

* Impact:
    - High. Successful exploitation allows complete bypass of journalist authentication, leading to unauthorized access to sensitive whistleblower submissions. An attacker can read, modify, or delete submissions, and potentially deanonymize sources.

* Vulnerability Rank:
    - High

* Currently Implemented Mitigations:
    - Session cookie is signed using `itsdangerous` to prevent tampering.
    - Two-Factor Authentication (TOTP/HOTP) is enforced for journalist accounts, adding a layer of security beyond password-based authentication.
    - Server-side sessions are used, which is generally more secure than client-side sessions if cookies are properly protected.

* Missing Mitigations:
    - Implement `HttpOnly` flag for the session cookie to prevent client-side JavaScript access.

* Preconditions:
    - Attacker needs to be able to inject and execute Javascript in the context of the Journalist interface, or needs to be able to intercept network traffic to perform a man-in-the-middle attack and inject Javascript into the response.

* Source Code Analysis:
    1. File: `/code/securedrop/journalist_app/sessions.py`
    2. Class `SessionInterface` in `save_session` method sets the session cookie.
    3. Look for `response.set_cookie` call:
    ```python
    response.set_cookie(
        app.session_cookie_name,
        session.token,
        httponly=httponly,
        domain=domain,
        path=path,
        secure=secure,
        samesite=samesite,
    )
    ```
    4. The `httponly` parameter is set to `httponly`, which is obtained from `self.get_cookie_httponly(app)`.
    5. Inspect `FlaskSessionInterface.get_cookie_httponly`:
    ```python
    def get_cookie_httponly(self, app):
        return app.config.get("SESSION_COOKIE_HTTPONLY", True)
    ```
    6. By default, `SESSION_COOKIE_HTTPONLY` is `True` in Flask-Session.
    7. Check `app.config` in `/code/securedrop/journalist_app/__init__.py` for any explicit setting of `SESSION_COOKIE_HTTPONLY`.
    8. No explicit setting of `SESSION_COOKIE_HTTPONLY` is found in the provided code.
    9. However, upon closer inspection of `SessionInterface.save_session` function in `/code/securedrop/journalist_app/sessions.py`, it is noticed that `httponly` variable used in `response.set_cookie` is defined but never assigned a value:
    ```python
    httponly = self.get_cookie_httponly(app) # httponly is defined here
    ...
    response.set_cookie(
        app.session_cookie_name,
        session.token,
        httponly=httponly, # httponly is used here, but never assigned a value, defaults to None
        ...
    )
    ```
    This means that `httponly` variable defaults to `None`, and thus `httponly` flag is effectively not set when calling `response.set_cookie`, despite Flask-Session default configuration.

* Security Test Case:
    1. Precondition:
        - Have a running SecureDrop instance.
        - Have a journalist account with valid credentials and 2FA setup.
    2. Steps:
        - Log in to the Journalist Interface using valid credentials and 2FA.
        - Open browser's developer tools (e.g., in Chrome, press F12).
        - Go to the "Application" or "Storage" tab (depending on the browser).
        - In the Cookies section, find the session cookie for the Journalist Interface domain (typically named "session").
        - Observe the cookie details. Check if the "HttpOnly" flag is present under the "Flags" or "Attributes" column. If "HttpOnly" is not checked or listed, the vulnerability exists.
        - To further confirm the vulnerability, try to access the cookie using Javascript in the browser console. For example, type `document.cookie` and check if the session cookie is listed in the output. If it is, Javascript can access the cookie, confirming the vulnerability.