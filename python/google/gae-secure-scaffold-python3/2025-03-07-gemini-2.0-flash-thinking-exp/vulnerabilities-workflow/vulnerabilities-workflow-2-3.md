- Vulnerability Name: CSRF Protection Bypass via `@csrf.exempt` Misuse

- Description:
    - A developer using the Secure Scaffold might inadvertently disable CSRF protection on sensitive routes by incorrectly applying the `@app.csrf.exempt` decorator.
    - Step-by-step trigger:
        1. A developer creates a Flask application using `securescaffold.create_app(__name__)`.
        2. The developer intends to exempt a specific route, like a CSP report handler, from CSRF protection as documented.
        3. However, due to misunderstanding or error, the developer applies the `@app.csrf.exempt` decorator to a route that handles sensitive actions, such as user profile updates or financial transactions.
        4. An attacker identifies this unprotected route.
        5. The attacker crafts a malicious website or script that submits a forged request to the vulnerable route on behalf of an authenticated user, without the required CSRF token.
        6. If the user visits the attacker's website or script while logged into the vulnerable application, the forged request is executed by the user's browser, leading to an unintended action on the server.

- Impact:
    - If CSRF protection is bypassed on a sensitive route, an attacker can perform unauthorized actions on behalf of a logged-in user.
    - This could include:
        - Modifying user data.
        - Performing financial transactions.
        - Changing account settings.
        - Any other action the vulnerable route is designed to handle.
    - The severity of the impact depends on the functionality of the unprotected route.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - CSRF protection is enabled by default using Flask-SeaSurf when using `securescaffold.create_app(__name__)`.
    - The project provides documentation and examples on how to use CSRF protection and how to exempt routes when necessary, specifically mentioning CSP report handlers as a valid use case for exemption.
    - The `README.md` and example code explicitly mentions CSRF protection and the `@app.csrf.exempt` decorator, guiding developers on its proper usage.

- Missing Mitigations:
    - **No explicit warnings or linters to detect misuse of `@csrf.exempt` on routes that are not intended for CSRF exemption.** The framework relies on the developer's understanding and correct application of the decorator.
    - **Lack of clear guidelines or best practices within the documentation to strongly discourage the use of `@csrf.exempt` on sensitive routes.** While documentation explains how to use it, it does not sufficiently emphasize the security risks of misusing it on actions beyond specific cases like CSP reporting.

- Preconditions:
    - The developer must have incorrectly applied the `@app.csrf.exempt` decorator to a route that handles sensitive user actions.
    - An attacker needs to identify this route and understand its functionality.
    - A victim user must be logged into the vulnerable application and interact with the attacker's malicious content (website or script).

- Source Code Analysis:
    - `src/securescaffold/factory.py`: The `create_app` function initializes Flask-SeaSurf:
      ```python
      import flask_seasurf

      def create_app(*args, **kwargs) -> flask.Flask:
          app = flask.Flask(*args, **kwargs)
          # ...
          app.csrf = flask_seasurf.SeaSurf(app) # CSRF protection is initialized here
          return app
      ```
    - `README.md`: Explains how to exempt routes:
      ```markdown
      ### CSRF protection with Flask-SeaSurf

      The Flask-SeaSurf library provides CSRF protection. An instance of `SeaSurf` is assigned to the Flask application as `app.csrf`. You can use this to decorate a request handler as exempt from CSRF protection:

          # main.py
          import securescaffold

          app = securescaffold.create_app(__name__)

          @app.csrf.exempt
          @app.route("/csp-report", methods=["POST"])
          def csp_report():
            """CSP report handlers accept POST requests with no CSRF token."""
            return ""
      ```
    - **Vulnerability Point**: The `@app.csrf.exempt` decorator, provided by Flask-SeaSurf and exposed by Secure Scaffold, directly disables CSRF checks for the decorated route. If a developer mistakenly uses this on a sensitive endpoint, CSRF protection is completely removed for that endpoint, creating a vulnerability. The framework provides the tool for exemption, but it does not prevent its misuse.

- Security Test Case:
    - Step-by-step test:
        1. **Setup a vulnerable application**:
            - Create a Flask application using `securescaffold.create_app(__name__)`.
            - Define a vulnerable route `/sensitive-action` that handles a sensitive action (e.g., changing email).
            - **Intentionally and incorrectly** apply `@app.csrf.exempt` decorator to this `/sensitive-action` route.
            - Create a form in a template that submits a POST request to `/sensitive-action` with a parameter (e.g., `new_email`).
        2. **Deploy the application to a publicly accessible instance.**
        3. **Attacker crafts a malicious HTML page**:
            - Create an HTML page that contains a form mimicking the form in the vulnerable application but hosted on a different domain.
            - This form also targets the `/sensitive-action` route of the vulnerable application, submitting a forged request with a malicious payload (e.g., attacker's email as `new_email`).
        4. **Victim user action**:
            - The victim user logs into the deployed vulnerable application.
            - The victim user, in a separate browser tab or window, visits the attacker's malicious HTML page.
        5. **Exploit verification**:
            - The attacker's malicious page automatically submits the forged request to the vulnerable application's `/sensitive-action` route in the victim's browser.
            - Because `@app.csrf.exempt` is applied, the CSRF check is bypassed.
            - If the application logic is vulnerable, the sensitive action is performed on behalf of the victim user (e.g., the victim's email is changed to the attacker's email).
        6. **Expected result**: The sensitive action is performed without the user's intended consent, demonstrating a successful CSRF attack due to the misuse of `@app.csrf.exempt`.

This test case confirms that if a developer misuses `@app.csrf.exempt`, CSRF protection is bypassed, and the application becomes vulnerable to CSRF attacks.