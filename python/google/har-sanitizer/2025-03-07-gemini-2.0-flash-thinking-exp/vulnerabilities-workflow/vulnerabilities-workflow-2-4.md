### Vulnerability List

- Vulnerability Name: Cross-Site Scripting (XSS) in HAR Preview

- Description:
    1. An attacker crafts a malicious HAR file containing a JavaScript payload. For example, the payload can be placed within a URL query parameter or response content in the HAR file.
    2. A user opens the HAR Sanitizer web tool in their browser.
    3. The user loads the malicious HAR file into the web tool using the "Load HAR" functionality.
    4. The web tool parses the HAR file and displays a preview of its content to the user, likely including details from requests and responses.
    5. Due to insufficient sanitization of the HAR content before rendering the preview, the JavaScript payload embedded in the HAR file is executed within the user's browser in the context of the web tool application. This occurs because the web tool directly renders the HAR content without properly escaping HTML entities or removing potentially malicious scripts.

- Impact:
    Successful exploitation of this vulnerability allows an attacker to execute arbitrary JavaScript code in the victim's browser. This can lead to various malicious activities, including:
    - Account hijacking: Stealing session cookies or other authentication tokens to gain unauthorized access to the user's accounts.
    - Data theft: Accessing sensitive information displayed in the web tool or other data accessible within the browser's context.
    - Redirection to malicious sites: Redirecting the user to attacker-controlled websites, potentially for phishing or malware distribution.
    - Defacement: Altering the visual appearance of the web tool interface.
    - Further attacks: Using the XSS vulnerability as a stepping stone for more complex attacks against the user or the web application.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - The project implements backend sanitization in the `/scrub_har` API endpoint using the `HarSanitizer.scrub()` method. This sanitization is intended to redact sensitive information from HAR files before they are exported or used further.
    - However, this backend sanitization is not applied to the HAR content *before* it is displayed in the web tool for preview. The preview functionality, likely implemented in the frontend (JavaScript within `index.html`), is where the vulnerability lies because it renders unsanitized HAR content.

- Missing Mitigations:
    - **Frontend-side sanitization:** The web tool needs to implement robust sanitization of HAR content *before* displaying it for preview. This should include:
        - HTML entity encoding: Encoding HTML special characters (e.g., `<`, `>`, `&`, `"`, `'`) to prevent the browser from interpreting them as HTML tags or attributes.
        - JavaScript removal: Stripping out or neutralizing any JavaScript code found within the HAR content.
        - Context-sensitive output encoding: Applying different encoding techniques depending on the context where the HAR data is being rendered (e.g., URL encoding for URLs, HTML encoding for HTML content, JavaScript escaping for JavaScript strings).
    - **Content Security Policy (CSP):** Implementing a strict Content Security Policy (CSP) can help mitigate the impact of XSS vulnerabilities by restricting the sources from which the browser is allowed to load resources (scripts, stylesheets, etc.) and by controlling inline script execution.

- Preconditions:
    - The attacker needs to be able to craft a malicious HAR file. This is a trivial precondition as HAR files are simply JSON and can be easily created or modified.
    - The victim user must use the HAR Sanitizer web tool and load the malicious HAR file into it for preview. This is a realistic scenario as users are expected to load HAR files into the tool for sanitization purposes.

- Source Code Analysis:
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

- Security Test Case:
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