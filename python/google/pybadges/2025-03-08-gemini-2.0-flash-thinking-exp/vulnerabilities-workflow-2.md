## Combined Vulnerability List

### 1. Cross-Site Scripting (XSS) via SVG Injection in Badge Text Parameters

- Description:
    1. An attacker can craft a malicious payload containing SVG code.
    2. The attacker injects this payload into the `left-text` or `right-text` parameters of the `badge` function or the command-line interface.
    3. The `pybadges` library directly embeds these parameters into the generated SVG badge without sufficient sanitization.
    4. When a user opens or embeds this maliciously crafted SVG badge in a web browser, the injected SVG code is executed as part of the SVG document.
    5. This can lead to Cross-Site Scripting (XSS) attacks, potentially allowing the attacker to execute arbitrary JavaScript code in the user's browser within the context of the domain where the SVG is viewed (if served from a web server).

- Impact:
    - **High**: Successful exploitation can lead to Cross-Site Scripting (XSS). An attacker could execute arbitrary JavaScript code in a user's browser when they view the generated badge. This could allow the attacker to:
        - Steal sensitive information like cookies or session tokens.
        - Perform actions on behalf of the user, such as making unauthorized requests.
        - Deface websites or redirect users to malicious sites.
        - Injects malware or further compromise the user's system.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None: The code does not implement any input sanitization or output encoding for the `left-text` and `right-text` parameters before embedding them into the SVG badge. The `badge` function in `/code/pybadges/__init__.py` directly uses these inputs in the Jinja2 template. The template `badge-template-full.svg` then renders these inputs as plain text within `<text>` elements.

- Missing Mitigations:
    - **Input Sanitization**: The application is missing input sanitization for `left-text`, `right-text`, and potentially other text-based parameters (`left_title`, `right_title`, `whole_title`, `center_title`).  All text parameters that are rendered into the SVG should be sanitized to remove or escape potentially harmful characters and code, especially SVG or HTML tags and JavaScript code.
    - **Context-Aware Output Encoding**: The application should implement context-aware output encoding. In this case, since the output is SVG, the text content should be properly XML-encoded to prevent interpretation of injected code as SVG elements. Specifically, characters like `<`, `>`, `&`, `"`, and `'` should be encoded as XML entities (e.g., `&lt;`, `&gt;`, `&amp;`, `&quot;`, `&apos;`).

- Preconditions:
    - The attacker needs to be able to control the `left-text` or `right-text` parameters that are passed to the `badge` function or the command-line interface. This could be through a web application that uses `pybadges` to generate badges based on user input, or by directly manipulating command-line arguments.
    - The generated SVG badge must be viewed in a web browser or an application that renders SVG images and executes embedded scripts.

- Source Code Analysis:
    1. **Vulnerable Code Location**: `/code/pybadges/__init__.py` and `/code/pybadges/badge-template-full.svg`
    2. **`badge` function in `__init__.py`**:
        ```python
        def badge(
            left_text: str,
            right_text: Optional[str] = None,
            ...
        ) -> str:
            ...
            template = _JINJA2_ENVIRONMENT.get_template('badge-template-full.svg')

            svg = template.render(
                left_text=left_text,
                right_text=right_text,
                ...
            )
            ...
            return xml.documentElement.toxml()
        ```
        The `badge` function takes `left_text` and `right_text` directly from the function arguments and passes them to the `template.render()` method.
    3. **`badge-template-full.svg`**:
        ```xml
        <svg ...>
          ...
          <g id="left-text">
            <rect ... fill="{{ left_color }}" />
            <text ...>{{ left_text }}</text>
          </g>
          ...
          <g id="right-text">
            <rect ... fill="{{ right_color }}" />
            <text ...>{{ right_text }}</text>
          </g>
          ...
        </svg>
        ```
        The Jinja2 template directly uses `{{ left_text }}` and `{{ right_text }}` within the `<text>` elements. Jinja2's default autoescape setting for SVG (as configured in `_JINJA2_ENVIRONMENT` with `autoescape=jinja2.select_autoescape(['svg']))` only escapes HTML-unsafe characters in attributes, not in text content within tags in SVG context. Therefore, if malicious SVG or JavaScript code is injected into `left_text` or `right_text`, it will be rendered as code within the SVG, leading to XSS.
    4. **Visualization**:
        ```
        User Input (left_text, right_text) --> badge() function (__init__.py) --> Jinja2 Template (badge-template-full.svg) --> SVG Output (Vulnerable) --> Browser (XSS)
        ```
        The user input directly flows into the SVG output via Jinja2 templating without any sanitization, creating the XSS vulnerability.

- Security Test Case:
    1. **Setup**: Use the command-line interface of `pybadges`. Ensure `pybadges` is installed (`pip install pybadges`).
    2. **Craft Malicious Payload**: Create a payload that will execute JavaScript code when rendered as SVG. For example:
        ```xml
        <svg xmlns="http://www.w3.org/2000/svg">
          <script>alert("XSS Vulnerability");</script>
        </svg>
        ```
        For easier injection as text, URL encode the payload and use it as right-text. However, direct injection also works. Let's use direct injection for simplicity.
    3. **Inject Payload via Command Line**: Execute the `pybadges` command-line tool, injecting the payload into the `--right-text` parameter:
        ```sh
        python -m pybadges --left-text=test --right-text='<svg xmlns="http://www.w3.org/2000/svg"><script>alert("XSS Vulnerability");</script></svg>' --browser
        ```
        Or a simpler payload that still demonstrates XSS:
        ```sh
        python -m pybadges --left-text=test --right-text='</text><script>alert("XSS Vulnerability");</script><text>' --browser
        ```
    4. **Observe Behavior**: The `--browser` flag will open the generated SVG badge in a web browser.
    5. **Expected Outcome**: When the badge opens in the browser, an alert box with the message "XSS Vulnerability" should appear. This demonstrates that the injected JavaScript code from the `right-text` parameter was executed, confirming the XSS vulnerability.
    6. **Verification**: Examine the generated SVG source code (e.g., by inspecting the element in the browser's developer tools). You should see the injected `<script>` tag directly within the SVG, confirming that the input was not sanitized.

This test case demonstrates that an attacker can inject malicious SVG code through the `right-text` parameter (and similarly through `left-text`) and achieve Cross-Site Scripting when the generated badge is viewed in a browser.

### 2. SVG Logo URL Injection

- Description:
    1. An attacker can control the `--logo` parameter when using the `pybadges` command-line tool or library.
    2. If the `--embed-logo` option is not used (or is set to `no`), the provided URL in the `--logo` parameter is directly embedded into the generated SVG badge as the `xlink:href` attribute of an `<image>` tag.
    3. An attacker can provide a malicious URL pointing to a crafted SVG file containing embedded JavaScript.
    4. When a user views the generated badge (e.g., on a GitHub page or website), the browser will attempt to load and render the SVG from the attacker-controlled URL.
    5. If the malicious SVG contains JavaScript, the browser will execute it in the context of the viewer's browser session, potentially leading to Cross-Site Scripting (XSS).

- Impact:
    - Cross-Site Scripting (XSS) vulnerability.
    - An attacker could potentially execute arbitrary JavaScript code in the context of a user viewing the badge.
    - This could lead to session hijacking, cookie theft, redirection to malicious websites, or other client-side attacks.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None. The code directly embeds the provided URL into the SVG without any sanitization when `--embed-logo` is not used.

- Missing Mitigations:
    - Input sanitization of the `--logo` URL to prevent embedding of malicious URLs.
    - Validation of the URL scheme to only allow `http://`, `https://`, or `data:` schemes, and disallow `javascript:`, `vbscript:`, etc.
    - If external URLs are allowed, consider using a Content Security Policy (CSP) to restrict the capabilities of loaded SVG content.

- Preconditions:
    - The attacker needs to be able to control the `--logo` parameter of the `pybadges` tool. This is typically possible if the tool is used in an automated system where parameters are not strictly controlled or validated, or if a user can be tricked into using a malicious command.
    - The generated SVG badge needs to be viewed in a browser that renders SVG images and executes JavaScript embedded within them (if present in the malicious SVG).

- Source Code Analysis:
    1. **`pybadges/__main__.py`**:
        - The `main()` function uses `argparse` to parse command-line arguments, including `--logo`.
        - The value of `--logo` is directly passed as the `logo` argument to the `pybadges.badge()` function without any sanitization or validation.

        ```python
        args = parser.parse_args()
        # ...
        badge = pybadges.badge(..., logo=args.logo, ...)
        ```

    2. **`pybadges/__init__.py`**:
        - The `badge()` function receives the `logo` argument.
        - When `embed_logo` is `False`, the `logo` URL is directly passed to the Jinja2 template without any sanitization.

        ```python
        def badge(..., logo: Optional[str] = None, embed_logo: bool = False, ...):
            # ...
            if logo and embed_logo:
                logo = _embed_image(logo) # This is only called when embed_logo is True

            template = _JINJA2_ENVIRONMENT.get_template('badge-template-full.svg')

            svg = template.render(..., logo=logo, ...)
            # ...
            return xml.documentElement.toxml()
        ```
    3. **`badge-template-full.svg` (assumed template based on code):**
        - The Jinja2 template likely uses the `logo` variable to set the `xlink:href` attribute of an `<image>` tag.

        ```xml
        ...
        {% if logo %}
        <image x="0" y="0" width="20" height="20" xlink:href="{{ logo }}" />
        <rect x="20" width="{{ left_width }}" height="20" fill="{{ left_color }}" />
        {% else %}
        <rect x="0" width="{{ left_width }}" height="20" fill="{{ left_color }}" />
        {% endif %}
        ...
        ```
        - **Visualization:**
          ```
          [Command Line Input: --logo='MALICIOUS_SVG_URL' --embed-logo=no]
              |
              V
          [pybadges/__main__.py: Argument Parsing]
              |
              V
          [pybadges/__init__.py: badge() function]
              |
              V
          [badge-template-full.svg: Jinja2 Template Rendering]
              |  logo variable (MALICIOUS_SVG_URL) is directly inserted into xlink:href
              V
          [Generated SVG Badge]
              |  <image ... xlink:href="MALICIOUS_SVG_URL" ... />
              V
          [User Browser Views Badge]
              |  Browser loads MALICIOUS_SVG_URL and executes malicious script if present
              V
          [XSS Vulnerability Triggered]
          ```

- Security Test Case:
    1. Create a malicious SVG file (e.g., `malicious.svg`) hosted on a web server accessible to the test environment. This SVG file should contain embedded JavaScript that, for example, displays an alert box.

        ```xml
        <!-- malicious.svg -->
        <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
          <script type="text/javascript">
            alert('XSS Vulnerability!');
          </script>
          <rect width="100" height="100" fill="red"/>
        </svg>
        ```

    2. Use the `pybadges` command-line tool to generate a badge, providing the URL of the malicious SVG file as the `--logo` parameter and ensuring `--embed-logo` is not used.

        ```sh
        python -m pybadges --left-text=Test --right-text=Badge --logo='http://YOUR_SERVER/malicious.svg' --browser --embed-logo=no
        ```
        *(Replace `http://YOUR_SERVER/malicious.svg` with the actual URL where you hosted `malicious.svg`)*

    3. Observe the generated badge in the browser.
    4. **Expected Result:** An alert box with "XSS Vulnerability!" should appear in the browser, demonstrating that the JavaScript code from the malicious SVG URL was executed. If the `--browser` flag is not used, manually open the generated SVG file in a browser.

This test case confirms that the `--logo` parameter, when not embedded, is vulnerable to SVG URL injection, leading to potential XSS.

### 3. Server-Side Request Forgery (SSRF) in logo embedding

- Description:
    - An attacker can trigger a Server-Side Request Forgery (SSRF) vulnerability by manipulating the `logo` parameter when the `embed-logo` option is enabled.
    - Step 1: The attacker identifies an application using the pybadges library that allows user-controlled input to the `badge` function, specifically the `logo` parameter and enables the `embed_logo` option. A typical example is the provided `server-example/app.py`.
    - Step 2: The attacker crafts a malicious URL and provides it as the value for the `logo` parameter. This URL can point to internal network resources, external websites, or services that the server should not directly access.
    - Step 3: The server-side application, using pybadges library with `embed_logo=True`, attempts to fetch the resource from the attacker-supplied URL using the `requests` library.
    - Step 4: If the server successfully fetches the resource, it embeds the content (or attempts to) into the generated SVG badge.
    - Step 5: The attacker can observe the response behavior (e.g., timeout, error messages, or response content if they control the destination server) to infer information about the server's internal network or services, or potentially interact with internal services if the request is successful.

- Impact:
    - Information Disclosure: An attacker can potentially scan internal networks and identify open ports and services. Error messages or response times might reveal information about internal resources.
    - Access to Internal Resources: If internal services are not properly secured and accessible via HTTP, an attacker might be able to interact with these services through the vulnerable server, potentially reading sensitive data or triggering actions.
    - In some scenarios, depending on the internal service, further exploitation like Remote Code Execution might be possible, but this is less likely and depends heavily on the specifics of the internal network and services.
    - In the context of pybadges, the primary impact is information disclosure and potential access to internal resources via SSRF.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - There are no mitigations implemented in the provided code to prevent SSRF. The `_embed_image` function fetches the URL without any validation.

- Missing Mitigations:
    - Input validation and sanitization for the `logo` URL are missing.
    - A whitelist of allowed URL schemes (e.g., only `data` and `https` if external URLs are genuinely needed, although `data` scheme should be sufficient for embedding) should be implemented.
    - If external URLs are necessary, implement strict URL parsing and validation to prevent access to internal networks (e.g., block private IP ranges, localhost, etc.).
    - Consider using a dedicated library for URL parsing and validation to avoid common bypasses.

- Preconditions:
    - The application must use the `pybadges.badge` function and allow user-controlled input for the `logo` parameter.
    - The `embed_logo` option must be enabled (or controllable by the attacker).
    - The server must have network connectivity to the target internal or external resources the attacker wants to access.
    - The `server-example/app.py` provides a vulnerable endpoint out-of-the-box.

- Source Code Analysis:
    - The vulnerability lies in the `_embed_image` function within `/code/pybadges/__init__.py`:
    ```python
    def _embed_image(url: str) -> str:
        parsed_url = urllib.parse.urlparse(url)

        if parsed_url.scheme == 'data':
            return url
        elif parsed_url.scheme.startswith('http'): # Vulnerable code block
            r = requests.get(url) # No URL validation before request
            r.raise_for_status()
            content_type = r.headers.get('content-type')
            if content_type is None:
                raise ValueError('no "Content-Type" header')
            content_type, image_type = content_type.split('/')
            if content_type != 'image':
                raise ValueError(
                    'expected an image, got "{0}"'.format(content_type))
            image_data = r.content
        elif parsed_url.scheme:
            raise ValueError('unsupported scheme "{0}"'.format(parsed_url.scheme))
        else:
            # ... file path handling ...
            pass

        encoded_image = base64.b64encode(image_data).decode('ascii')
        return 'data:image/{};base64,{}'.format(image_type, encoded_image)
    ```
    - Visualization:
        ```
        User Input (logo URL) --> badge() --> _embed_image() --> requests.get(url) --> Target URL
        ```
    - Step-by-step analysis:
        1. The `badge` function is called with a `logo` URL from user input and `embed_logo=True`.
        2. Inside `badge`, the `_embed_image(logo)` function is called because `embed_logo` is true.
        3. `_embed_image` parses the URL using `urllib.parse.urlparse`.
        4. It checks if the scheme is `data`, if so, it returns the URL directly.
        5. If the scheme starts with `http`, it proceeds to fetch the URL using `requests.get(url)` *without any validation*.
        6. The response is checked for `content-type` header and if it is an image.
        7. The image data is then base64 encoded and embedded into a data URL.
        8. The lack of URL validation in step 5 allows an attacker to provide a malicious URL, leading to SSRF.
    - The `server-example/app.py` exposes this vulnerability in the `/img` endpoint:
    ```python
    @app.route('/img')
    def serve_badge():
        """Serve a badge image based on the request query string."""
        badge = pybadges.badge(left_text=flask.request.args.get('left_text'),
                               right_text=flask.request.args.get('right_text'),
                               left_color=flask.request.args.get('left_color'),
                               right_color=flask.request.args.get('right_color'),
                               logo=flask.request.args.get('logo'), # User controlled input
                               embed_logo=True) # Embed logo is enabled

        response = flask.make_response(badge)
        response.content_type = 'image/svg+xml'
        return response
    ```
    - The `logo` parameter from the query string is directly passed to the `pybadges.badge` function with `embed_logo=True`, making it vulnerable.

- Security Test Case:
    - Preconditions:
        - Deploy the `server-example/app.py`.
        - Ensure the server is running and accessible (e.g., at http://127.0.0.1:5000/).
        - Attacker has network access to the deployed server.
    - Steps:
        1. Identify the vulnerable endpoint: `/img` in the `server-example/app.py`.
        2. Craft a malicious URL to test for SSRF. For example, to test access to localhost, use `http://127.0.0.1/`. To test for access to an external site you control for logging purposes, use `http://<attacker-controlled-domain>/test`.
        3. Send a GET request to the `/img` endpoint with the crafted malicious URL as the `logo` parameter. For example:
           `http://127.0.0.1:5000/img?left_text=test&right_text=ssrf&logo=http://127.0.0.1/&embed_logo=yes`
        4. Observe the server's behavior.
            - If the server attempts to access `http://127.0.0.1/`, this confirms the SSRF vulnerability. You might see a delay in response, or an error message if the server times out trying to connect to localhost if no service is running there.
            - If you use an attacker-controlled domain, check the access logs of your domain. If you see a request originating from the server's IP address when you sent the request in step 3, it confirms the SSRF.
        5. To further confirm the vulnerability, try accessing a known internal resource if you have access to the network where the server is deployed, or try different schemes like `file:///etc/passwd` (though `requests` might prevent `file://` scheme; testing with `http://localhost` is sufficient to demonstrate SSRF in this case).
    - Expected result:
        - The server should attempt to make a request to the provided malicious URL (e.g., `http://127.0.0.1/`). This can be verified by observing server logs, network traffic, or response behavior (timeouts, errors).
        - If the server is vulnerable, you will be able to observe the SSRF behavior as described in step 4.