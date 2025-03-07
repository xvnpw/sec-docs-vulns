### Vulnerability List

- Vulnerability Name: Unauthenticated HAR Sanitization API Endpoint

- Description:
  1. An attacker sets up a malicious instance of the HAR Sanitizer API.
  2. The attacker hosts this malicious instance at a publicly accessible URL.
  3. The attacker tricks a user into using their malicious HAR Sanitizer API endpoint instead of the legitimate one (e.g., via phishing, DNS spoofing, or social engineering).
  4. The user, intending to sanitize their HAR file, uploads the HAR file to the attacker's malicious API endpoint through the web tool or directly via API calls.
  5. The attacker's malicious API endpoint receives the raw, unsanitized HAR file.
  6. The attacker logs or exfiltrates the complete, sensitive contents of the unsanitized HAR file.
  7. The user is unaware that their HAR file has been compromised.

- Impact:
  * Confidentiality breach: Sensitive information contained within the HAR file, such as passwords, cookies, authentication tokens, and personal data, is exposed to the attacker.
  * Privacy violation: User's private web browsing activity and potentially sensitive personal information are compromised.
  * Potential for further attacks: Stolen credentials or session tokens can be used to gain unauthorized access to user accounts and systems.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
  * None. The API endpoints in `harsan_api.py` are publicly accessible without any form of authentication or authorization. The `@decorators.accept` and `@decorators.require` decorators only validate the content type of the request, not the identity of the requester.

- Missing Mitigations:
  * Implement authentication and authorization mechanisms for the API endpoints, especially `/scrub_har`.
    * **Mutual TLS (mTLS):**  Require clients to authenticate with a client certificate. This provides strong authentication and encryption.
    * **API Key Authentication:** Require clients to include a valid API key in their requests. This is a simpler approach but less secure than mTLS if API keys are compromised.
  * Educate users about the risks of using untrusted HAR Sanitizer instances and provide guidance on verifying the legitimacy of the service they are using.

- Preconditions:
  * An attacker needs to set up a publicly accessible, malicious instance of the HAR Sanitizer API.
  * The attacker needs to trick a user into using the malicious instance.

- Source Code Analysis:
  1. **`harsanitizer/harsan_api.py`**: This file defines the Flask API endpoints.
  2. **`app = Flask(__name__)`**:  A Flask application is initialized, creating the API.
  3. **`@app.route("/scrub_har", methods=["POST"])`**: This decorator defines the `/scrub_har` endpoint, which is the core function for sanitizing HAR files.
  4. **`@decorators.accept("application/json")` and `@decorators.require("application/json")`**: These decorators are applied to the `/scrub_har` endpoint.
  5. **`def scrub():`**: This function handles the request to `/scrub_har`. It retrieves the HAR data from the request (`data = request.json`), initializes `HarSanitizer`, and calls the `scrub` function to sanitize the HAR file.
  6. **Absence of Authentication**: There is no code in `harsan_api.py` or `decorators.py` that implements any form of authentication or authorization to restrict access to the `/scrub_har` endpoint or other API endpoints.  The decorators only check the `Content-Type` and `Accept` headers to ensure the request and response types are `application/json`.
  7. **Public Accessibility**: The `app.run(host="0.0.0.0", port=8080, debug=False)` line in `harsan_api.py` makes the Flask application publicly accessible on all network interfaces (0.0.0.0) on port 8080.


- Security Test Case:
  1. **Setup Malicious Instance:**
     - Deploy a copy of the `har-sanitizer` project code to a publicly accessible server.
     - Modify the `harsan_api.py` file in the malicious instance to log the raw HAR file content when the `/scrub_har` endpoint is called. Add the following lines within the `scrub()` function, before `sanitized_har = hs.scrub(har, **hs_kwargs)`:
       ```python
       import logging
       logging.basicConfig(filename='malicious_log.txt', level=logging.INFO)
       logging.info("Received HAR file: {}".format(data["har"]))
       ```
     - Start the malicious Flask application: `PYTHONPATH=. python ./harsanitizer/harsan_api.py`

  2. **Obtain Victim's HAR File:**
     - Prepare a demo HAR file (or use `tests/python-tests/demo.har`) that contains sensitive information like cookies, headers, or parameters.

  3. **Trick Victim to Use Malicious Instance:**
     - Assume the malicious instance is running at `http://malicious-har-sanitizer.com:8080`.
     - Trick the victim into using `http://malicious-har-sanitizer.com:8080` as the API endpoint. This could be done by:
       - Modifying the Javascript code of the web tool (if hosted by the attacker) to point to the malicious API endpoint.
       - Phishing the user with a link to a modified version of the web tool or instructions to use the malicious API directly.
       - Socially engineering the user to use the malicious URL.

  4. **Victim Uploads HAR File:**
     - The victim uses the (potentially modified) web tool or directly sends a POST request to `http://malicious-har-sanitizer.com:8080/scrub_har` with their sensitive HAR file in the request body.

  5. **Verify HAR File Capture on Malicious Instance:**
     - On the attacker's server, check the `malicious_log.txt` file.
     - Verify that the complete, unsanitized HAR file content, including sensitive information, is logged in `malicious_log.txt`.

  6. **Expected Result:** The security test case successfully demonstrates that an attacker can intercept and steal unsanitized HAR files by setting up a malicious HAR Sanitizer API instance due to the lack of authentication on the API endpoints.