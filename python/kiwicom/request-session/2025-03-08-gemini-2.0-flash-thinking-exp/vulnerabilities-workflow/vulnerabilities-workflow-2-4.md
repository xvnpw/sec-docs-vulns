- Vulnerability Name: Server-Side Request Forgery (SSRF) via Host Parameter
- Description:
    - An attacker can induce a Server-Side Request Forgery (SSRF) vulnerability if an application utilizing the `request-session` library constructs the `host` parameter of the `RequestSession` class from user-provided input without adequate validation.
    - Step-by-step trigger:
        1. An application using `request-session` takes user input to define the `host` for a `RequestSession` instance. For example, the application might accept a URL or hostname from a user through a form field, URL parameter, or API request.
        2. The application directly uses this user-provided input as the `host` parameter when creating a `RequestSession` object, without performing sufficient validation or sanitization to ensure it points to an intended and safe destination.
        3. An attacker provides a malicious URL or hostname as input. This malicious input could be an internal IP address, a loopback address, or a URL pointing to an attacker-controlled external server.
        4. The application then uses this `RequestSession` instance to make HTTP requests using methods like `get`, `post`, etc., with a path parameter.
        5. Due to the lack of validation, the `request-session` library constructs the full request URL by joining the attacker-controlled `host` with the provided `path`.
        6. The application, through `request-session`, sends an HTTP request to the URL specified by the attacker in the `host` parameter.
- Impact:
    - Server-Side Request Forgery (SSRF).
    - An attacker can make the server-side application send requests to unintended locations, potentially internal systems or external resources.
    - This can lead to:
        - Access to internal services and data behind firewalls that are not intended to be publicly accessible.
        - Port scanning of internal networks to discover running services.
        - Reading sensitive data from internal services (e.g., configuration files, internal APIs).
        - In some cases, potential for Remote Code Execution (RCE) if vulnerable internal services are exposed.
        - Information disclosure by accessing metadata endpoints of cloud providers.
        - Denial of Service (DoS) by targeting internal services or external resources.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - No direct mitigations are implemented within the `request-session` library itself to prevent SSRF based on the `host` parameter.
    - The library relies on the application developer to properly validate and sanitize the `host` input before passing it to `RequestSession`.
- Missing Mitigations:
    - Input validation and sanitization for the `host` parameter within the `RequestSession` library.
    - While it is generally the responsibility of the application to validate user inputs, providing guidance or helper functions within `request-session` to assist with host validation could reduce the risk. However, automatic validation might be too restrictive and limit legitimate use cases. The primary missing mitigation is clear documentation and warnings about the SSRF risk when using user-controlled input for the `host` parameter.
- Preconditions:
    - The application must use the `request-session` library.
    - The application must construct a `RequestSession` instance with the `host` parameter being directly or indirectly derived from user-controlled input.
    - The application must fail to implement proper validation and sanitization of this user-controlled `host` input.
- Source Code Analysis:
    - **Initialization of `RequestSession`:**
        ```python
        class RequestSession(object):
            def __init__(
                self,
                host=None,  # type: str
                # ... other parameters
            ):
                self.host = host
                # ... rest of init
        ```
        - The `__init__` method of `RequestSession` directly assigns the provided `host` parameter to `self.host` without any validation or sanitization. This means if a malicious string is passed as `host`, it will be directly used.

    - **URL Construction in HTTP methods (`get`, `post`, etc.):**
        ```python
        def get(self, path, **kwargs):
            url = urljoin(self.host, path) if self.host else path
            return self._process("get", url, **kwargs)
        ```
        - The `get`, `post`, `put`, `patch`, and `delete` methods use `urljoin(self.host, path)` to construct the full URL.
        - `urljoin` from `request_session._compat` (which uses `urllib.parse.urljoin` or `urlparse.urljoin` depending on Python version) will join the base URL (`self.host`) with the relative URL (`path`).
        - If `self.host` is attacker-controlled, the attacker effectively dictates the base URL for all subsequent requests made with this `RequestSession` instance.

    - **`_process` method:**
        ```python
        def _process(
            self,
            request_type,
            url, # attacker controlled if host is controlled
            # ... other parameters
        ):
            # ...
            request_params = {
                "url": url, # url is used directly in request
                "timeout": self.timeout,
                "verify": self.verify,
                "params": None,
            }
            request_params.update(request_kwargs)
            response = self._send_request(
                request_type, request_params, tags, run, request_category
            )
            # ...
        ```
        - The `_process` method receives the `url` (which is built using `self.host`) and directly uses it in the `request_params` dictionary which is then passed to `_send_request` and ultimately to `requests.session.request`.
        - No further validation of the `url` is performed within `_process` or `_send_request`.

    - **Visualization:**

    ```
    User Input (Malicious Host) --> Application --> RequestSession(host=userInput) -->  urljoin(RequestSession.host, path) --> requests.session.request(url=attackerControlledURL) --> SSRF
    ```

- Security Test Case:
    - Step-by-step test:
        1. **Setup:** Assume a vulnerable application uses `request-session` and allows users to specify a target host (e.g., through a form field named `target_host`). The application creates a `RequestSession` instance using this user-provided `target_host`.
        2. **Attacker Action:** An attacker crafts a malicious input for the `target_host` field. For example, the attacker sets `target_host` to `http://127.0.0.1:8080`. Assume there is a service running on `http://127.0.0.1:8080` that should not be accessible from the outside.
        3. **Application Request:** The attacker then triggers an action in the application that uses the `RequestSession` instance (created with the attacker-controlled `host`) to make a `get` request with a path, for example, `/api/data`.
        4. **Verification:** The `request-session` library, within the application, will construct the URL as `urljoin('http://127.0.0.1:8080', '/api/data')`, resulting in the final URL `http://127.0.0.1:8080/api/data`. The application will then send a GET request to `http://127.0.0.1:8080/api/data`.
        5. **SSRF Confirmation:** If the attacker can observe a response from `http://127.0.0.1:8080/api/data` (e.g., through application logs, network traffic if they control the 127.0.0.1:8080 service, or indirectly if the application's behavior changes based on the response), it confirms the SSRF vulnerability.

    - Example using `curl` to simulate the attacker's input and application behavior (assuming a simplified example where you can directly control the host passed to `RequestSession`):

    ```python
    import requests
    from request_session import RequestSession

    # Simulate attacker-controlled host (in a real scenario, this would come from user input)
    attacker_controlled_host = "http://127.0.0.1:8080" # Attacker wants to target localhost port 8080

    # Vulnerable application code (simplified)
    client = RequestSession(host=attacker_controlled_host)
    try:
        response = client.get(path="/api/internal-service-data") # Application intends to access data from its own service, but...
        print(f"Response Status Code: {response.status_code}")
        print(f"Response Content: {response.text}")
    except Exception as e:
        print(f"Request failed: {e}")
    ```

    - To make this a complete test case, you would need to set up a listener on `http://127.0.0.1:8080` (e.g., using `netcat` or a simple HTTP server) to verify that the request indeed reaches the attacker-specified destination. You would also need to demonstrate how an attacker could exploit this to access internal resources in a realistic application scenario. For a test within the `request-session` library itself, you would mock the `host` parameter to be a malicious URL and verify that the request is made to that URL when using `client.get()` etc.