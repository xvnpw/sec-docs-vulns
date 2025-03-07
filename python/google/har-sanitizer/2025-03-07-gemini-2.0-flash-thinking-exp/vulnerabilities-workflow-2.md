## Vulnerabilities Found

### Vulnerability Name: Unauthenticated HAR Sanitization API Endpoint

Description:
1. An attacker sets up a malicious instance of the HAR Sanitizer API.
2. The attacker hosts this malicious instance at a publicly accessible URL.
3. The attacker tricks a user into using their malicious HAR Sanitizer API endpoint instead of the legitimate one (e.g., via phishing, DNS spoofing, or social engineering).
4. The user, intending to sanitize their HAR file, uploads the HAR file to the attacker's malicious API endpoint through the web tool or directly via API calls.
5. The attacker's malicious API endpoint receives the raw, unsanitized HAR file.
6. The attacker logs or exfiltrates the complete, sensitive contents of the unsanitized HAR file.
7. The user is unaware that their HAR file has been compromised.

Impact:
* Confidentiality breach: Sensitive information contained within the HAR file, such as passwords, cookies, authentication tokens, and personal data, is exposed to the attacker.
* Privacy violation: User's private web browsing activity and potentially sensitive personal information are compromised.
* Potential for further attacks: Stolen credentials or session tokens can be used to gain unauthorized access to user accounts and systems.

Vulnerability Rank: High

Currently Implemented Mitigations:
* None. The API endpoints in `harsan_api.py` are publicly accessible without any form of authentication or authorization. The `@decorators.accept` and `@decorators.require` decorators only validate the content type of the request, not the identity of the requester.

Missing Mitigations:
* Implement authentication and authorization mechanisms for the API endpoints, especially `/scrub_har`.
    * **Mutual TLS (mTLS):**  Require clients to authenticate with a client certificate. This provides strong authentication and encryption.
    * **API Key Authentication:** Require clients to include a valid API key in their requests. This is a simpler approach but less secure than mTLS if API keys are compromised.
* Educate users about the risks of using untrusted HAR Sanitizer instances and provide guidance on verifying the legitimacy of the service they are using.

Preconditions:
* An attacker needs to set up a publicly accessible, malicious instance of the HAR Sanitizer API.
* The attacker needs to trick a user into using the malicious instance.

Source Code Analysis:
1. **`harsanitizer/harsan_api.py`**: This file defines the Flask API endpoints.
2. **`app = Flask(__name__)`**:  A Flask application is initialized, creating the API.
3. **`@app.route("/scrub_har", methods=["POST"])`**: This decorator defines the `/scrub_har` endpoint, which is the core function for sanitizing HAR files.
4. **`@decorators.accept("application/json")` and `@decorators.require("application/json")`**: These decorators are applied to the `/scrub_har` endpoint.
5. **`def scrub():`**: This function handles the request to `/scrub_har`. It retrieves the HAR data from the request (`data = request.json`), initializes `HarSanitizer`, and calls the `scrub` function to sanitize the HAR file.
6. **Absence of Authentication**: There is no code in `harsan_api.py` or `decorators.py` that implements any form of authentication or authorization to restrict access to the `/scrub_har` endpoint or other API endpoints.  The decorators only check the `Content-Type` and `Accept` headers to ensure the request and response types are `application/json`.
7. **Public Accessibility**: The `app.run(host="0.0.0.0", port=8080, debug=False)` line in `harsan_api.py` makes the Flask application publicly accessible on all network interfaces (0.0.0.0) on port 8080.


Security Test Case:
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

### Vulnerability Name: HAR Parameter Injection leading to Sanitization Bypass

Description:
1. An attacker crafts a malicious HAR file.
2. This HAR file contains a crafted entry with a `request` object.
3. Inside the `request` object, the attacker injects a parameter within `queryString` or `params` array that has a `name` field designed to interfere with the sanitization logic. For example, an attacker can inject a parameter with `name` set to `"__proto__"` or `"constructor"` or similar JavaScript prototype pollution or object property manipulation keywords.
4. When the `/scrub_har` endpoint processes this HAR file, the `iter_eval_exec` function in `HarSanitizer` might be vulnerable to property reassignment or unexpected behavior due to the injected parameter name.
5. This could potentially bypass the intended sanitization logic by modifying internal states of the `Har` or `HarSanitizer` objects, leading to sensitive data not being redacted.

Impact:
- Sensitive information from the HAR file, intended to be sanitized, may be exposed.
- Attackers can potentially exfiltrate passwords, cookies, headers, or other private data contained within the HAR file by bypassing sanitization.
- In a worst-case scenario, depending on how the injected parameter is processed, it might be possible to cause unexpected behavior or errors in the server-side application.

Vulnerability Rank: High

Currently Implemented Mitigations:
- The code uses decorators `@accept("application/json")` and `@require("application/json")` for the `/scrub_har` endpoint in `harsan_api.py`, ensuring that the API only accepts and requires JSON data. This mitigates against some types of basic injection attacks that rely on different content types.
- The `Har` class in `harsanitizer.py` performs basic validation to ensure the input is a valid HAR structure during initialization in `load_har` function, which raises `ValueError` for invalid HAR formats. This prevents the API from crashing with completely malformed input.

Missing Mitigations:
- Input sanitization and validation are insufficient. The application lacks specific checks to validate the `name` fields within the `queryString` and `params` arrays of the HAR file to prevent injection of potentially harmful parameter names like JavaScript prototype properties or internal object keywords.
- There is no explicit input validation within the `iter_eval_exec` function in `harsanitizer.py` to prevent manipulation via crafted keys in the HAR data. The code relies on `eval(cond)` for conditional checks, but does not validate the keys and values being processed to avoid logic bypasses.

Preconditions:
- The attacker needs to be able to craft a HAR file and send it to the `/scrub_har` endpoint of the Flask API.
- The Flask API instance of the HAR sanitizer must be publicly accessible or accessible to the attacker.

Source Code Analysis:
1. **`harsanitizer.py` - `HarSanitizer.iter_eval_exec` function:**
    ```python
    def iter_eval_exec(self, my_iter, cond_table):
        if isinstance(my_iter, dict):
          for key, value in my_iter.iteritems():
            # Makes it run faster, even though it seems counterintuitive
            if any([eval(cond) for cond in cond_table.keys()]): # [POINT OF CONCERN] - eval usage and key processing
              for cond, callback in cond_table.iteritems():
                # Security risks have been mitigated by
                # preventing any possible code-injection
                # attempt into cond_table keys
                if eval(cond): # [POINT OF CONCERN] - eval usage and condition evaluation
                  callback(self, my_iter, key, value) # [POINT OF CONCERN] - callback execution with potentially manipulated key/value
            elif isinstance(value, (dict, list)):
              self.iter_eval_exec(
                  value,
                  cond_table)
        elif isinstance(my_iter, list):
          for value in my_iter:
            self.iter_eval_exec(
                value,
                cond_table)

        return my_iter
    ```
    - The `iter_eval_exec` function iterates through the HAR dictionary structure.
    - It uses `eval(cond)` to evaluate conditions defined in `cond_table.keys()`. While the comment mentions mitigation against code injection in `cond_table` keys, the code itself doesn't perform validation on the `key` and `value` variables extracted from the HAR data during iteration.
    - If an attacker can control the `key` value in the HAR structure (e.g., by injecting a parameter name like `__proto__` in `queryString`), and a condition in `cond_table` relies on this `key`, the `eval(cond)` might lead to unintended behavior or allow for logic bypass. For example, if a condition is `"key == 'cookie'"` and an attacker injects a parameter with `name` as `"cookie"` within `queryString`, this condition would evaluate to true even if the context is not actually a cookie object, potentially leading to misapplication of sanitization logic.
    - The callback function `callback(self, my_iter, key, value)` is executed if `eval(cond)` is true. If the `key` or `value` has been manipulated, the callback might operate on unintended data or in an unintended way.

2. **`harsanitizer.py` - `HarSanitizer.gen_hartype_names_pattern` function:**
    ```python
    def gen_hartype_names_pattern(self, har, hartype):
        # ...
        def outer_callback(self, my_iter, key, value):
          def inner_callback(self, my_iter, key, value):
            if value in har.category[hartype]:
              har.category[hartype][value] += 1
            else:
              har.category[hartype][value] = 1

          self.iter_eval_exec(
              value,
              {"key == 'name'": inner_callback} # [POINT OF CONCERN] - Condition relies on 'name' key from HAR, which is attacker-controlled.
          )

        har.category[hartype] = {}

        cond_table = {
            "key == '{}'".format(hartype): outer_callback # [POINT OF CONCERN] - Condition relies on hartype, but iteration context is not strictly validated.
        }

        return cond_table
    ```
    - This function generates conditions to extract names of different HAR types (cookies, headers, params).
    - Both `outer_callback` and `inner_callback` rely on conditions based on `key` values from the HAR structure (`key == '{}'".format(hartype)` and `"key == 'name'"`). If an attacker can inject parameters with `name` that matches these conditions, the logic might be misled.
    - For instance, if `hartype` is 'queryString', and an attacker injects a parameter with `name` set to 'queryString', the `outer_callback` might be triggered in unintended contexts during the iteration process.

Security Test Case:
1. **Setup:** Run the Flask API locally or use a publicly available instance.
2. **Craft Malicious HAR:** Create a HAR file (e.g., `malicious.har`) with the following structure. This HAR file injects a parameter with `name` set to `__proto__` within the `queryString`.
    ```json
    {
      "log": {
        "entries": [
          {
            "request": {
              "queryString": [
                {
                  "name": "__proto__",
                  "value": "injected_value"
                },
                {
                  "name": "sensitive_param",
                  "value": "sensitive_value_to_exfiltrate"
                }
              ],
              "url": "http://example.com/api/resource?sensitive_param=sensitive_value_to_exfiltrate"
            },
            "response": {
              "content": {
                "mimeType": "text/plain",
                "text": "This is a response with sensitive data: sensitive_response_data"
              }
            }
          }
        ]
      }
    }
    ```
3. **Send Malicious HAR to `/scrub_har`:** Use `curl` or `requests` to send a POST request to the `/scrub_har` endpoint with the crafted `malicious.har` file as JSON data.
    ```bash
    curl -X POST -H "Content-Type: application/json" -d @malicious.har http://localhost:8080/scrub_har > scrubbed_har.json
    ```
4. **Analyze Scrubbed HAR:** Examine the `scrubbed_har.json` file. Check if the `sensitive_param` value (`sensitive_value_to_exfiltrate` in `queryString` and in URL) and `sensitive_response_data` within the `content.text` are properly redacted.
5. **Expected vs. Actual Result:**
    - **Expected (Sanitization Works):** Both `sensitive_param` and `sensitive_response_data` should be redacted in the output `scrubbed_har.json`.
    - **Actual (Vulnerability Exists):** If the vulnerability is successfully exploited, the sanitization logic might be bypassed or weakened due to the injected `__proto__` parameter, and `sensitive_param` or `sensitive_response_data` might **not** be fully redacted in `scrubbed_har.json`, or the sanitization might be incomplete or exhibit unexpected behavior. Specifically, check if "sensitive_value_to_exfiltrate" or "sensitive_response_data" is still present in the scrubbed HAR.

### Vulnerability Name: Cross-Site Scripting (XSS) in HAR Preview

Description:
1. An attacker crafts a malicious HAR file containing a JavaScript payload. For example, the payload can be placed within a URL query parameter or response content in the HAR file.
2. A user opens the HAR Sanitizer web tool in their browser.
3. The user loads the malicious HAR file into the web tool using the "Load HAR" functionality.
4. The web tool parses the HAR file and displays a preview of its content to the user, likely including details from requests and responses.
5. Due to insufficient sanitization of the HAR content before rendering the preview, the JavaScript payload embedded in the HAR file is executed within the user's browser in the context of the web tool application. This occurs because the web tool directly renders the HAR content without properly escaping HTML entities or removing potentially malicious scripts.

Impact:
Successful exploitation of this vulnerability allows an attacker to execute arbitrary JavaScript code in the victim's browser. This can lead to various malicious activities, including:
- Account hijacking: Stealing session cookies or other authentication tokens to gain unauthorized access to the user's accounts.
- Data theft: Accessing sensitive information displayed in the web tool or other data accessible within the browser's context.
- Redirection to malicious sites: Redirecting the user to attacker-controlled websites, potentially for phishing or malware distribution.
- Defacement: Altering the visual appearance of the web tool interface.
- Further attacks: Using the XSS vulnerability as a stepping stone for more complex attacks against the user or the web application.

Vulnerability Rank: High

Currently Implemented Mitigations:
- The project implements backend sanitization in the `/scrub_har` API endpoint using the `HarSanitizer.scrub()` method. This sanitization is intended to redact sensitive information from HAR files before they are exported or used further.
- However, this backend sanitization is not applied to the HAR content *before* it is displayed in the web tool for preview. The preview functionality, likely implemented in the frontend (JavaScript within `index.html`), is where the vulnerability lies because it renders unsanitized HAR content.

Missing Mitigations:
- **Frontend-side sanitization:** The web tool needs to implement robust sanitization of HAR content *before* displaying it for preview. This should include:
    - HTML entity encoding: Encoding HTML special characters (e.g., `<`, `>`, `&`, `"`, `'`) to prevent the browser from interpreting them as HTML tags or attributes.
    - JavaScript removal: Stripping out or neutralizing any JavaScript code found within the HAR content.
    - Context-sensitive output encoding: Applying different encoding techniques depending on the context where the HAR data is being rendered (e.g., URL encoding for URLs, HTML encoding for HTML content, JavaScript escaping for JavaScript strings).
- **Content Security Policy (CSP):** Implementing a strict Content Security Policy (CSP) can help mitigate the impact of XSS vulnerabilities by restricting the sources from which the browser is allowed to load resources (scripts, stylesheets, etc.) and by controlling inline script execution.

Preconditions:
- The attacker needs to be able to craft a malicious HAR file. This is a trivial precondition as HAR files are simply JSON and can be easily created or modified.
- The victim user must use the HAR Sanitizer web tool and load the malicious HAR file into it for preview. This is a realistic scenario as users are expected to load HAR files into the tool for sanitization purposes.

Source Code Analysis:
1. **`harsanitizer/harsan_api.py` - Serving the Web Tool:**
    - The `/` route in `harsanitizer/harsan_api.py` is responsible for serving the web tool's HTML (`index.html`).
    - ```python
      @app.route("/")
      def index():
        if STATIC_FOLDER[:4] == "http":
          index_html_str = urllib2.urlopen(INDEX_PATH).read()
        else:
          with open(INDEX_PATH, "r") as index_file:
            index_html_str = index_file.read()
        return render_template_string(index_html_str, static_files=STATIC_FOLDER)
      ```
    - This code reads the `index.html` content and serves it using `render_template_string`.  `render_template_string` by default in Flask escapes HTML content to prevent XSS when variables are passed into the template. However, in this case, `index_html_str` is directly rendered as a string without any variable substitution or explicit sanitization at the backend level before being sent to the browser.
    - The vulnerability is not in this Python backend code itself, but rather in how the frontend JavaScript code within `index.html` handles and displays the HAR content.

2. **Frontend Code (`index.html` - Not Provided):**
    - Since `index.html` is not provided in the project files, we must infer its functionality based on the project description and the attack vector.
    - It is highly likely that the `index.html` contains JavaScript code that performs the following actions when a HAR file is loaded:
        - Parses the HAR JSON content.
        - Extracts data from various HAR fields (e.g., `request.url`, `response.content.text`, `request.headers`, etc.).
        - Dynamically generates HTML to display a preview of the HAR content in the web browser.
    - **The critical vulnerability point is the lack of sanitization in this frontend JavaScript code.** If the JavaScript code directly injects HAR data into the HTML DOM (e.g., using `innerHTML` or by creating DOM elements and setting their `textContent` or `innerHTML` properties without proper encoding), it will be vulnerable to XSS.
    - For example, if the JavaScript code does something like this to display a request URL:
      ```javascript
      const urlElement = document.getElementById('requestUrlDisplay');
      urlElement.innerHTML = harEntry.request.url; // Vulnerable!
      ```
      And if `harEntry.request.url` contains `<script>alert('XSS')</script>`, this script will be executed.

3. **Backend Sanitization (`/scrub_har` Endpoint):**
    - The `/scrub_har` endpoint in `harsanitizer/harsan_api.py` uses the `HarSanitizer.scrub()` method to sanitize the HAR data.
    - This backend sanitization is effective for the API functionality, but it does not protect against XSS in the *preview* functionality of the web tool because the preview is displayed *before* the user initiates the sanitization process via the API.

Security Test Case:
1. **Craft a malicious HAR file (e.g., `malicious.har`):**
    ```json
    {
      "log": {
        "entries": [
          {
            "request": {
              "url": "https://example.com/?param=<img src=x onerror=alert('XSS-Request-URL')>"
            },
            "response": {
              "status": 200,
              "content": {
                "mimeType": "text/html",
                "text": "<html><body><h1>Response</h1><div id='content'><script>alert('XSS-Response-Content')</script></div></body></html>"
              }
            }
          }
        ]
      }
    }
    ```
2. **Set up the HAR Sanitizer:**
    - Follow the installation instructions in `README.md` to set up the HAR Sanitizer locally.
    - Start the Flask server: `PYTHONPATH=. python ./harsanitizer/harsan_api.py`
    - Access the web tool in a browser: `http://localhost:8080` (or the configured port).
3. **Load the malicious HAR file:**
    - In the web tool, click the "Load HAR" button.
    - Select the `malicious.har` file you created.
4. **Observe for XSS:**
    - After loading the HAR file, observe if JavaScript alert boxes pop up in your browser.
    - You should expect to see at least one alert box, potentially two (one from the request URL and one from the response content), depending on how the web tool displays the HAR preview.
    - If the alert boxes appear, it confirms the XSS vulnerability.

This test case demonstrates that an attacker can inject malicious JavaScript code into a HAR file, and this code will be executed in the user's browser when they preview the HAR file in the HAR Sanitizer web tool, confirming the XSS vulnerability.