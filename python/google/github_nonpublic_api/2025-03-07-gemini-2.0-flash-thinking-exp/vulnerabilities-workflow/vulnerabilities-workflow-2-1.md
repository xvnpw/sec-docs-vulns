### Vulnerability List

#### 1. Sensitive Information Logging in Form Data
- Description:
    - The `_get_and_submit_form` function logs form data at the DEBUG level using `logging.debug("Form data: %s", str(data))`.
    - Form data, especially during login or form submissions, can contain sensitive information such as passwords, authentication tokens, and personal details.
    - If debug logging is enabled in a production environment or if these logs are accessible to unauthorized users, this sensitive information can be exposed.
    - Step-by-step trigger:
        1. An application using this library enables debug logging for the `github_nonpublic_api` module.
        2. The application uses the `Api` class to perform actions that involve form submissions, such as logging in (`create_login_session`) or creating an organization (`create_organization`).
        3. The `_get_and_submit_form` function is called during these operations, and it logs the form data at the debug level.
        4. If an attacker gains access to these debug logs, they can read the sensitive information contained within the logged form data.
- Impact:
    - Information Leakage.
    - Exposure of sensitive credentials (like usernames and passwords used for GitHub API access) or other confidential data transmitted in forms.
    - Unauthorized access to GitHub accounts or resources if leaked credentials are used maliciously.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations:
    - None. The code currently logs form data in debug level without any redaction or sanitization.
- Missing Mitigations:
    - **Redact sensitive information:** Modify the logging in `_get_and_submit_form` to redact or mask sensitive fields in the form data before logging. For example, fields like 'password', 'authenticity_token', or similar should be filtered out or replaced with placeholder values in the logs.
    - **Conditional logging:** Implement conditional logging based on the sensitivity of the data being logged. Avoid logging form data at all unless absolutely necessary for debugging, and even then, only log non-sensitive parts.
    - **Secure logging practices:**  Advise users of the library to follow secure logging practices, such as:
        - Restricting access to log files to authorized personnel only.
        - Using secure log storage and transmission mechanisms.
        - Regularly reviewing and rotating logs.
        - Disabling debug logging in production environments.
- Preconditions:
    - Debug logging must be enabled for the `github_nonpublic_api` library.
    - An attacker needs to gain access to the log files where debug messages are written.
- Source Code Analysis:
    1. Open the file `/code/github_nonpublic_api/api.py`.
    2. Locate the function `_get_and_submit_form`.
    3. Examine the line: `logging.debug("Form data: %s", str(data))` within this function.
    4. Observe that the entire `data` dictionary, which contains form input values, is logged as a string using `logging.debug`.
    5. Notice that this logging occurs unconditionally whenever `_get_and_submit_form` is called and debug logging is enabled.
    6. Consider the context where `_get_and_submit_form` is used, for instance in `create_login_session`. The form data here includes 'login' (username) and 'password'.
    7. Conclude that if debug logs are enabled, sensitive credentials will be logged in plaintext.
- Security Test Case:
    1. **Setup:**
        - Install the library in a test environment.
        - Configure the Python logging system to capture DEBUG level logs from the `github_nonpublic_api` module and direct them to a file or console.  For example, using basicConfig in the test script:
          ```python
          import logging
          logging.basicConfig(level=logging.DEBUG)
          ```
    2. **Execution:**
        - Write a test script that imports the `Api` class and attempts to create a login session with a dummy username and password.
          ```python
          from github_nonpublic_api import api
          import requests
          import logging

          logging.basicConfig(level=logging.DEBUG) # Enable debug logging

          try:
              gh_api = api.Api(username='testuser', password='testpassword', tfa_callback=lambda: '123456', session=requests.Session())
          except Exception as e:
              # Login might fail, but we are interested in logs before failure
              pass
          ```
        - Run the test script.
    3. **Verification:**
        - Inspect the log output (file or console depending on logging configuration).
        - Search for log entries containing "Form data:".
        - Within the "Form data:" log entry, verify that the submitted form data is present and includes the plaintext username ('testuser') and password ('testpassword').
        - Confirm that sensitive information provided to the `Api` constructor is logged in debug logs.
    4. **Remediation (as part of test, to demonstrate mitigation):**
        - Modify the `_get_and_submit_form` function in `/code/github_nonpublic_api/api.py` to redact sensitive fields before logging. For example:
          ```python
          def _get_and_submit_form(session, url: str, data_callback=None, form_matcher=lambda form: True):
              # ... (rest of the function) ...
              log_data = data.copy()
              if 'password' in log_data:
                  log_data['password'] = '********' # Redact password
              logging.debug("Form data: %s", str(log_data)) # Log redacted data
              # ... (rest of the function) ...
          ```
        - Re-run the test script after applying the redaction.
        - Verify that the password field in the "Form data:" log entry is now redacted (e.g., shows '********') while other non-sensitive data is still logged.