- vulnerability name: Server-Side Request Forgery (SSRF) in logo embedding
- description:
    - An attacker can trigger a Server-Side Request Forgery (SSRF) vulnerability by manipulating the `logo` parameter when the `embed-logo` option is enabled.
    - Step 1: The attacker identifies an application using the pybadges library that allows user-controlled input to the `badge` function, specifically the `logo` parameter and enables the `embed_logo` option. A typical example is the provided `server-example/app.py`.
    - Step 2: The attacker crafts a malicious URL and provides it as the value for the `logo` parameter. This URL can point to internal network resources, external websites, or services that the server should not directly access.
    - Step 3: The server-side application, using pybadges library with `embed_logo=True`, attempts to fetch the resource from the attacker-supplied URL using the `requests` library.
    - Step 4: If the server successfully fetches the resource, it embeds the content (or attempts to) into the generated SVG badge.
    - Step 5: The attacker can observe the response behavior (e.g., timeout, error messages, or response content if they control the destination server) to infer information about the server's internal network or services, or potentially interact with internal services if the request is successful.
- impact:
    - Information Disclosure: An attacker can potentially scan internal networks and identify open ports and services. Error messages or response times might reveal information about internal resources.
    - Access to Internal Resources: If internal services are not properly secured and accessible via HTTP, an attacker might be able to interact with these services through the vulnerable server, potentially reading sensitive data or triggering actions.
    - In some scenarios, depending on the internal service, further exploitation like Remote Code Execution might be possible, but this is less likely and depends heavily on the specifics of the internal network and services.
    - In the context of pybadges, the primary impact is information disclosure and potential access to internal resources via SSRF.
- vulnerability rank: high
- currently implemented mitigations:
    - There are no mitigations implemented in the provided code to prevent SSRF. The `_embed_image` function fetches the URL without any validation.
- missing mitigations:
    - Input validation and sanitization for the `logo` URL are missing.
    - A whitelist of allowed URL schemes (e.g., only `data` and `https` if external URLs are genuinely needed, although `data` scheme should be sufficient for embedding) should be implemented.
    - If external URLs are necessary, implement strict URL parsing and validation to prevent access to internal networks (e.g., block private IP ranges, localhost, etc.).
    - Consider using a dedicated library for URL parsing and validation to avoid common bypasses.
- preconditions:
    - The application must use the `pybadges.badge` function and allow user-controlled input for the `logo` parameter.
    - The `embed_logo` option must be enabled (or controllable by the attacker).
    - The server must have network connectivity to the target internal or external resources the attacker wants to access.
    - The `server-example/app.py` provides a vulnerable endpoint out-of-the-box.
- source code analysis:
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
- security test case:
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