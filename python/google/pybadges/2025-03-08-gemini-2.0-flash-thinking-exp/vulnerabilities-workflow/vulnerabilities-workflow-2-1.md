### Vulnerability List

- Vulnerability Name: Cross-Site Scripting (XSS) via SVG Injection in Badge Text Parameters

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