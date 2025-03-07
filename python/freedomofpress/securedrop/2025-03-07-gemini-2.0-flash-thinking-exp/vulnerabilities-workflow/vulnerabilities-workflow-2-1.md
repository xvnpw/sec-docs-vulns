## Vulnerability List

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