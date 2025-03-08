### Vulnerability List:

#### 1. SVG Logo URL Injection

* Description:
    1. An attacker can control the `--logo` parameter when using the `pybadges` command-line tool or library.
    2. If the `--embed-logo` option is not used (or is set to `no`), the provided URL in the `--logo` parameter is directly embedded into the generated SVG badge as the `xlink:href` attribute of an `<image>` tag.
    3. An attacker can provide a malicious URL pointing to a crafted SVG file containing embedded JavaScript.
    4. When a user views the generated badge (e.g., on a GitHub page or website), the browser will attempt to load and render the SVG from the attacker-controlled URL.
    5. If the malicious SVG contains JavaScript, the browser will execute it in the context of the viewer's browser session, potentially leading to Cross-Site Scripting (XSS).

* Impact:
    - Cross-Site Scripting (XSS) vulnerability.
    - An attacker could potentially execute arbitrary JavaScript code in the context of a user viewing the badge.
    - This could lead to session hijacking, cookie theft, redirection to malicious websites, or other client-side attacks.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - None. The code directly embeds the provided URL into the SVG without any sanitization when `--embed-logo` is not used.

* Missing Mitigations:
    - Input sanitization of the `--logo` URL to prevent embedding of malicious URLs.
    - Validation of the URL scheme to only allow `http://`, `https://`, or `data:` schemes, and disallow `javascript:`, `vbscript:`, etc.
    - If external URLs are allowed, consider using a Content Security Policy (CSP) to restrict the capabilities of loaded SVG content.

* Preconditions:
    - The attacker needs to be able to control the `--logo` parameter of the `pybadges` tool. This is typically possible if the tool is used in an automated system where parameters are not strictly controlled or validated, or if a user can be tricked into using a malicious command.
    - The generated SVG badge needs to be viewed in a browser that renders SVG images and executes JavaScript embedded within them (if present in the malicious SVG).

* Source Code Analysis:
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

* Security Test Case:
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