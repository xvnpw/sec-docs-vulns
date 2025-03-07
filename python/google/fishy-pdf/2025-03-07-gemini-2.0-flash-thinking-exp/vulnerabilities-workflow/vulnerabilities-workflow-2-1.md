- Vulnerability Name: Potential JavaScript Execution via Malicious PDF (Based on CVE-2024-4367)
- Description:
    1. An attacker crafts a malicious PDF file specifically designed to exploit a known or unknown JavaScript execution vulnerability within Mozilla's PDF.js library, similar to CVE-2024-4367.
    2. A user opens this malicious PDF using FishyPDF.
    3. If the version of PDF.js (3.10.111) integrated into FishyPDF is vulnerable to the exploited JavaScript execution flaw, the malicious JavaScript embedded in the PDF can be executed within the context of the FishyPDF viewer in the user's browser.
    4. Successful JavaScript execution can occur if the Content Security Policy (CSP) implemented by FishyPDF is not sufficiently strict to prevent or mitigate the specific type of JavaScript execution triggered by the malicious PDF, or if there are bypasses in the CSP configuration.
- Impact:
    - Successful execution of JavaScript within the FishyPDF viewer can have several security implications:
        - Information Disclosure: Malicious scripts could access sensitive information accessible within the viewer's scope, such as the content of the viewed PDF document, browser cookies, local storage data (if any is used by the viewer), or potentially data from other origins if the CSP is misconfigured and allows cross-origin requests.
        - Cross-Site Scripting (XSS) like attacks: Although the context is within the PDF viewer, if the viewer interacts with other parts of the application or if the CSP is weak, the attacker might be able to use the JavaScript execution to perform actions on behalf of the user within the FishyPDF domain or related domains.
        - Further Exploitation: Depending on the environment and the viewer's functionalities, successful JavaScript execution could be a stepping stone for more advanced attacks, such as exploiting other browser vulnerabilities or gaining further access.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations:
    - Content Security Policy (CSP): FishyPDF utilizes a Content Security Policy, configured via the `_headers` file and enforced by the `pdfjs-server.py` script. The server reads the CSP directives from the `_headers` file and sets the `Content-Security-Policy` HTTP header in responses. This is intended to restrict the capabilities of the PDF viewer and mitigate the impact of potential JavaScript execution vulnerabilities.
- Missing Mitigations:
    - Review and Harden CSP: The effectiveness of the current mitigation depends entirely on the strength and correctness of the CSP defined in the `_headers` file (which is not provided in the project files). A thorough review of the CSP is necessary to ensure it effectively prevents or significantly limits the impact of JavaScript execution from PDFs. Ideally, the CSP should:
        - Disallow 'unsafe-inline' and 'unsafe-eval' for script-src.
        - Strictly define allowed sources for scripts, styles, and other resources.
        - Consider using 'nonce' or 'hash' based CSP for inline scripts if absolutely necessary (though ideally inline scripts should be avoided).
    - Regular PDF.js Updates: While FishyPDF uses PDF.js version 3.10.111, maintaining up-to-date version of PDF.js is crucial. Regularly checking for and applying updates to PDF.js is essential to patch newly discovered vulnerabilities and ensure the viewer is protected against latest threats.
- Preconditions:
    - An attacker must be able to create or obtain a malicious PDF file that exploits a JavaScript execution vulnerability in the specific version of PDF.js used by FishyPDF (or a similar vulnerability).
    - A user must open this malicious PDF file using a publicly accessible instance of FishyPDF.
    - The Content Security Policy configured for FishyPDF must not be sufficiently restrictive to prevent the execution of the malicious JavaScript code in the PDF, or there must be a bypass in the implemented CSP.
- Source Code Analysis:
    - `pdfjs-server.py`:
        ```python
        import os
        from http.server import HTTPServer, SimpleHTTPRequestHandler, test

        WEBROOT = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'third_party/pdfjs')

        def get_csp():
            with open(os.path.join(WEBROOT, '_headers')) as f:
              CSP_PREFIX = 'Content-Security-Policy: '
              lines = [l.strip() for l in f.readlines()]
              lines = [l for l in lines if l.startswith(CSP_PREFIX)]
              if len(lines) != 1:
                raise ValueError("Expected exactly one CSP line in _headers. Found: " + str(lines))
              return lines[0].removeprefix(CSP_PREFIX)

        class CSPRequestHandler(SimpleHTTPRequestHandler):
          def __init__(self, request, client_address, server):
            SimpleHTTPRequestHandler.__init__(self, request, client_address, server, directory=WEBROOT)

          def end_headers (self):
            self.send_header('Content-Security-Policy', get_csp())
            SimpleHTTPRequestHandler.end_headers(self)

        print('serving from ' + WEBROOT)
        print('go to http://127.0.0.1:8123/web/viewer.html')
        test(CSPRequestHandler, HTTPServer, port=8123, bind='127.0.0.1')
        ```
        - The `pdfjs-server.py` script is responsible for serving the PDF viewer.
        - The `get_csp()` function reads the Content Security Policy from a file named `_headers` located in the `WEBROOT` directory (`third_party/pdfjs/_headers`).
        - It expects exactly one line starting with `Content-Security-Policy: ` in the `_headers` file.
        - The `CSPRequestHandler` class inherits from `SimpleHTTPRequestHandler` and overrides the `end_headers()` method.
        - In `end_headers()`, it calls `get_csp()` to retrieve the CSP string and sets the `Content-Security-Policy` HTTP header before calling the parent class's `end_headers()` to send other standard headers.
        - **Vulnerability Point:** The security relies entirely on the content of the `_headers` file. If the `_headers` file is missing, contains an improperly configured CSP, or a CSP that is not strong enough to prevent JavaScript execution from malicious PDFs, then the application will be vulnerable. Without inspecting the `_headers` file, it's impossible to determine the effectiveness of the CSP mitigation.
- Security Test Case:
    1. **Setup:** Deploy FishyPDF using `pdfjs-server.py` or a similar deployment method that serves the `third_party/pdfjs` directory as the webroot and applies the CSP from `_headers`. Access FishyPDF through a web browser (e.g., `http://127.0.0.1:8123/web/viewer.html`).
    2. **Prepare Malicious PDF:** Create a malicious PDF file that attempts to execute JavaScript code. A simple test payload could be a PDF that tries to execute `alert('FishyPDF Vulnerability')` using JavaScript within the PDF. You can use online tools or libraries to create PDFs with embedded JavaScript. For example, you might use `app.alert({cMsg: "FishyPDF Vulnerability", nIcon: 3});` in a PDF action.
    3. **Open Malicious PDF in FishyPDF:** In the FishyPDF viewer, open the malicious PDF file prepared in the previous step.
    4. **Observe for JavaScript Execution:** Check if the JavaScript code from the PDF is executed. Look for:
        - An alert dialog box appearing in the browser displaying "FishyPDF Vulnerability".
        - Errors or messages related to JavaScript execution in the browser's developer console (usually opened by pressing F12).
        - Any other observable behavior indicating JavaScript execution (e.g., changes to the page content, network requests if the script attempts to make them).
    5. **Analyze CSP (If JavaScript Executes):** If the JavaScript code executes successfully, use the browser's developer tools (Network tab or Security tab) to inspect the `Content-Security-Policy` header sent by the server. Analyze the CSP directives to understand why it did not prevent the JavaScript execution. Look for weaknesses such as:
        - `unsafe-inline` or `unsafe-eval` in `script-src`.
        - Wildcard origins or overly permissive whitelists in `script-src`.
        - Missing or misconfigured directives that should restrict JavaScript execution.
    6. **Vulnerability Confirmation:** If you observe JavaScript execution from the malicious PDF, and the CSP is either weak or bypassed, then the vulnerability is confirmed. The severity should be evaluated based on the level of JavaScript execution control achieved and the potential impact on the FishyPDF application and users. If the JavaScript is blocked due to CSP, then test with different CSP bypass techniques or different PDF.js vulnerabilities if known.

This vulnerability highlights the risk of relying on client-side PDF viewers to handle potentially malicious PDF files and emphasizes the importance of a strong Content Security Policy and regular updates to the underlying PDF.js library.