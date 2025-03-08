## Combined Vulnerability List

### 1. Path Traversal via Unsanitized Path Parameter

* Description:
    1. An application using the `request-session` library receives user input that is intended to define the API endpoint path.
    2. This user input is directly used to construct the `path` parameter when calling methods like `get`, `post`, `put`, `patch`, or `delete` of a `RequestSession` instance.
    3. An attacker crafts a malicious user input string containing path traversal sequences such as `../` or similar.
    4. The `request-session` library's `urljoin` function combines the base `host` and the attacker-controlled `path` without sanitization.
    5. This results in a crafted URL that points to a resource outside the intended API path, potentially allowing access to unauthorized API endpoints or resources within the same domain.

* Impact:
    * Unauthorized access to sensitive API endpoints or resources that were not intended to be publicly accessible.
    * Potential for information disclosure if unauthorized endpoints expose sensitive data.
    * Depending on the nature of the accessed endpoints, it might be possible to perform unintended actions or modifications.

* Vulnerability rank: High

* Currently implemented mitigations:
    * None. The `request-session` library does not perform any sanitization or validation of the `path` parameter. It relies on the user of the library to provide a safe and sanitized path.

* Missing mitigations:
    * Input sanitization within the `request-session` library to remove or neutralize path traversal sequences from the `path` parameter before constructing the final URL.
    * Clear documentation within the `request-session` library explicitly warning users about the security risks of using unsanitized user input for the `path` parameter and recommending proper sanitization on the application side.

* Preconditions:
    * An application must be using the `request-session` library.
    * The application must construct the `path` parameter for `RequestSession` methods based on user-controlled input.
    * The application must fail to sanitize or validate the user-provided input before using it as the `path`.

* Source code analysis:
    1. **File: /code/request_session/request_session.py**
    2. Look at the `get`, `post`, `put`, `patch`, `delete` methods. For example, the `get` method:
    ```python
    def get(self, path, **kwargs):
        # type: (str, Any) -> Optional[requests.Response]
        r"""Get request against a service.
        ...
        """
        url = urljoin(self.host, path) if self.host else path # Vulnerable line
        return self._process("get", url, **kwargs)
    ```
    3. The `path` parameter, which is directly passed from the user call to `get`, is used in `urljoin(self.host, path)`.
    4. `urljoin` from `urllib.parse` (or `urlparse` in older Python versions) is designed to intelligently join a base URL (`self.host`) with a relative URL (`path`). However, it does not sanitize path traversal sequences like `../`.
    5. If `path` contains `../`, `urljoin` will resolve the path upwards in the directory hierarchy relative to `self.host`.
    6. For example, if `self.host` is `https://example.com/api/v1/` and `path` is `../../admin`, `urljoin` will produce `https://example.com/admin`.
    7. The `_process` method then uses this constructed `url` to make the request without any further checks or sanitization.

* Security test case:
    1. **Setup:** Assume you have an instance of an application using `request-session` library running at `https://example.com`. Assume this application uses `RequestSession` with `host="https://example.com/api/v1/"`. And it has an endpoint `/user` that takes user input for the path and uses `request_session` to make a GET request.
    2. **Attacker Action:** As an attacker, craft a request to the application's `/user` endpoint with a malicious `path` parameter: `../../admin`.
    3. **Request Construction:** The application, without sanitizing the input, constructs the `path` for `request-session` as `../../admin`.
    4. **`RequestSession` Call:** The application then calls `client.get(path='../../admin')` where `client` is a `RequestSession` instance with `host="https://example.com/api/v1/"`.
    5. **URL Resolution:** `request-session`'s `urljoin` combines `https://example.com/api/v1/` and `../../admin` resulting in the final URL `https://example.com/admin`.
    6. **HTTP Request:** `request-session` makes an HTTP GET request to `https://example.com/admin`.
    7. **Verification:** Observe the response from `https://example.com/admin`. If the attacker receives a response from the `/admin` endpoint (e.g., a login page, admin panel content, or a different API response than expected from `/api/v1/`), it confirms the path traversal vulnerability. If the intended behavior was to only allow access within the `/api/v1/` path, then accessing `/admin` is a security breach.

### 2. Insecure Logging of Sensitive Request Parameters

* Description:
    1. A developer initializes `RequestSession` with `verbose_logging=True`.
    2. The developer makes HTTP requests using `RequestSession` methods (e.g., `get`, `post`).
    3. The requests include sensitive information in the request parameters, such as API keys in query parameters or request body, or personal data in the request body.
    4. The `_log_with_params` method in `request_session.py` is executed after each request to log request details.
    5. If the keys for sensitive parameters are not added to the `request_param_logging_blacklist`, these parameters are serialized into JSON format using `json.dumps` and included in the log message in plain text.
    6. If these logs are stored or transmitted insecurely, or accessed by unauthorized personnel, attackers can potentially gain access to the sensitive information contained within the logs.

* Impact:
    Exposure of sensitive information (API keys, passwords, personal data, etc.) to unauthorized parties who have access to the logs. This can lead to serious security breaches, including unauthorized access to systems, data theft, and compliance violations.

* Vulnerability rank: High

* Currently implemented mitigations:
    * The `request_param_logging_blacklist` parameter in the `RequestSession` class constructor, which defaults to `("auth", "headers")`. This allows developers to specify request parameters that should be excluded from logging.
    * Source code: `/code/request_session/request_session.py`:
      ```python
      extra_params = (
          {
              "request_params": json.dumps(
                  {
                      k: v
                      for k, v in deepcopy(request_params).items()
                      if k not in self.request_param_logging_blacklist
                  }
              ),
              "response_text": self.get_response_text(response),
          }
          if self.verbose_logging
          else {}
      )
      ```

* Missing mitigations:
    * **Documentation and warnings:** Lack of explicit documentation and warnings in the library's documentation about the security risks associated with enabling `verbose_logging` and the importance of sanitizing or excluding sensitive request parameters from logs.
    * **Default blacklist expansion:** The default `request_param_logging_blacklist` is limited to `("auth", "headers")`. It does not include common parameter names that might contain sensitive data (e.g., "api_key", "password", "secret").
    * **Automatic sensitive data detection:** No automatic mechanism to detect and sanitize potentially sensitive data in request parameters.
    * **Secure logging practices guidance:** Lack of recommendations or best practices for secure logging when using `request-session`, such as guidance on log rotation, secure storage, and access control for logs.

* Preconditions:
    * The `RequestSession` object must be initialized with `verbose_logging=True`.
    * Sensitive information must be present in the request parameters (query parameters, request body, etc.).
    * The keys for sensitive parameters must not be included in the `request_param_logging_blacklist` during `RequestSession` initialization.
    * An attacker must gain unauthorized access to the logs where sensitive information is recorded.

* Source code analysis:
    - In `/code/request_session/request_session.py`, the `_log_with_params` method is responsible for logging request parameters when `verbose_logging` is enabled.
    - The relevant code snippet is:
      ```python
      extra_params = (
          {
              "request_params": json.dumps(
                  {
                      k: v
                      for k, v in deepcopy(request_params).items()
                      if k not in self.request_param_logging_blacklist
                  }
              ),
              "response_text": self.get_response_text(response),
          }
          if self.verbose_logging
          else {}
      )
      ```
    - This code iterates through the `request_params` dictionary, excludes keys present in `request_param_logging_blacklist`, and converts the remaining parameters to a JSON string using `json.dumps`.
    - This JSON string is then included in the log message.
    - If `verbose_logging` is enabled and sensitive parameter keys are not blacklisted, they will be logged in plain text.

* Security test case:
    1. **Setup:** Use a tool like `httpbin` or a simple mock server to capture requests and responses. Configure logging to capture stdout or a file, where logs from `request-session` will be written.
    2. **Vulnerable Request:**
        - Initialize `RequestSession` with `verbose_logging=True` and default `request_param_logging_blacklist`:
          ```python
          from request_session import RequestSession
          import logging
          import sys

          logging.basicConfig(stream=sys.stdout, level=logging.INFO)
          session = RequestSession(host="http://localhost:8080", request_category="test_log_vuln", verbose_logging=True) # Replace with your test server URL
          ```
        - Make a GET request with a sensitive query parameter (e.g., `api_key`):
          ```python
          response = session.get(path="/get", params={"api_key": "sensitive_api_key_value"})
          ```
        - **Verification:** Examine the logs. The logs should contain a line with `request_params` that includes `"api_key": "sensitive_api_key_value"` in plain text.
    3. **Mitigated Request:**
        - Initialize `RequestSession` with `verbose_logging=True` and extend `request_param_logging_blacklist` to include 'params' to blacklist all parameters or 'api_key' to blacklist only api key:
          ```python
          from request_session import RequestSession
          import logging
          import sys

          logging.basicConfig(stream=sys.stdout, level=logging.INFO)
          session = RequestSession(
              host="http://localhost:8080",
              request_category="test_log_vuln_mitigated",
              verbose_logging=True,
              request_param_logging_blacklist=("auth", "headers", "params") # or request_param_logging_blacklist=("auth", "headers", "api_key")
          ) # Replace with your test server URL
          ```
        - Make the same GET request with the sensitive query parameter:
          ```python
          response = session.get(path="/get", params={"api_key": "sensitive_api_key_value"})
          ```
        - **Verification:** Examine the logs. The logs should either not contain the `request_params` at all, or the `request_params` should be present but without the sensitive parameter (e.g., `"request_params": "{}"` or `"request_params": "{}"` if 'params' was blacklisted or  `"request_params": "{}"` or `"request_params": "{}"` if 'api_key' was blacklisted, depending on the blacklist configuration).

### 3. Format String Vulnerability in Logging via `request_category`

* Description: An application using the `request-session` library might be vulnerable to a format string attack if it allows user-controlled input to be used as the `request_category` parameter and if the logging system used by the application is susceptible to format string vulnerabilities. When the `request-session` library logs information, it includes the `request_category` in the log messages. If a malicious user can control the `request_category` and inject format string specifiers (e.g., `%x`, `%s`, `%n`), these specifiers might be interpreted by a vulnerable logging system. This could lead to information disclosure (reading server memory), denial of service, or potentially arbitrary code execution on the server, depending on the capabilities of the logging system and the format string vulnerability.

* Impact: Information Disclosure, Denial of Service, potentially Arbitrary Code Execution. The severity depends on the logging system's vulnerability and the extent to which an attacker can control the `request_category` parameter.

* Vulnerability rank: High

* Currently implemented mitigations: No direct mitigations are implemented in the `request-session` library itself. The library relies on the security of the logging system configured by the application using it.

* Missing mitigations:
    * Input sanitization: The `request-session` library could sanitize the `request_category` parameter to remove or escape format string specifiers before including it in log messages. However, this might not be desirable as it could alter the intended logging behavior and might not be a complete solution.
    * Documentation warning: The documentation should explicitly warn users about the potential security risks of using user-provided input as `request_category` if their logging system is vulnerable to format string injection. It should advise users to sanitize or validate the `request_category` parameter if it originates from untrusted sources.
    * Consider structured logging: Encourage users to employ structured logging practices, which are less prone to format string vulnerabilities compared to traditional string formatting in logging.

* Preconditions:
    * An application is using the `request-session` library.
    * The application allows user-controlled input to influence or directly set the `request_category` parameter when making requests using `RequestSession`.
    * The logging system configured in the application is vulnerable to format string injection or similar issues when processing log event names or messages that include user-provided input.

* Source code analysis:
    - In the `request_session.py` file, the `log` method in the `RequestSession` class constructs the log event name using the `request_category` parameter. For example, in `_log_with_params` and `_exception_log_and_metrics` methods, the `request_category` or a string derived from it becomes part of the `event` parameter passed to the `log` method.
    - The `log` method then forms `event_name = f"{self.log_prefix}.{event}"` and calls the logger using `getattr(self.logger, level)(event_name, **kwargs)`.
    - If the `request_category`, which becomes part of `event_name`, contains format string specifiers and if the `self.logger` (the actual logger configured by the application) interprets these format specifiers, a format string vulnerability arises.
    - The vulnerability is triggered when user input, intended or unintended, containing format string characters is passed as `request_category` and processed by a vulnerable logger via the `request_session` library's logging mechanism.

* Security test case:
    - Step 1: Set up a Python application that uses the `request-session` library and configures a basic logger (e.g., `logging.getLogger()`). For demonstration purposes, assume this logger is vulnerable to format string (although standard Python logging is not directly vulnerable in this way with f-strings, the principle can be shown if a hypothetical vulnerable logger is used or if a vulnerable logging configuration is present).
    - Step 2: Create an API endpoint in the application that uses `RequestSession` to make a GET request. This endpoint should accept a parameter (e.g., query parameter `category`) and pass its value as the `request_category` to the `client.get()` method of `RequestSession`.
    - Step 3: As an attacker, send a request to this endpoint with a crafted `category` parameter value that includes format string specifiers. For example: `/?category=%25x%20%25x%20%25x%20%25x`. The `%25x` is URL-encoded `%x`.
    - Step 4: Examine the application logs. If the logging system is vulnerable to format string injection, the logs will show output resulting from the interpretation of the format string specifiers (e.g., hexadecimal values from memory, program crash, or other unexpected behavior instead of literal `%x %x %x %x`). This would confirm the format string vulnerability via the `request_category` parameter.
    - Step 5: To further demonstrate impact, try more dangerous format string specifiers if applicable to the hypothetical vulnerable logger to check for potential for code execution or more significant information disclosure. For real-world testing, it's crucial to use a genuinely vulnerable logger setup or simulate the behavior of one. For standard Python logging, this test case primarily highlights a potential risk if users were to replace the default logger with a vulnerable one and expose `request_category` to user input.

### 4. Server-Side Request Forgery (SSRF) via Host Parameter

* Description:
    - An attacker can induce a Server-Side Request Forgery (SSRF) vulnerability if an application utilizing the `request-session` library constructs the `host` parameter of the `RequestSession` class from user-provided input without adequate validation.
    - Step-by-step trigger:
        1. An application using `request-session` takes user input to define the `host` for a `RequestSession` instance. For example, the application might accept a URL or hostname from a user through a form field, URL parameter, or API request.
        2. The application directly uses this user-provided input as the `host` parameter when creating a `RequestSession` object, without performing sufficient validation or sanitization to ensure it points to an intended and safe destination.
        3. An attacker provides a malicious URL or hostname as input. This malicious input could be an internal IP address, a loopback address, or a URL pointing to an attacker-controlled external server.
        4. The application then uses this `RequestSession` instance to make HTTP requests using methods like `get`, `post`, etc., with a path parameter.
        5. Due to the lack of validation, the `request-session` library constructs the full request URL by joining the attacker-controlled `host` with the provided `path`.
        6. The application, through `request-session`, sends an HTTP request to the URL specified by the attacker in the `host` parameter.
* Impact:
    - Server-Side Request Forgery (SSRF).
    - An attacker can make the server-side application send requests to unintended locations, potentially internal systems or external resources.
    - This can lead to:
        - Access to internal services and data behind firewalls that are not intended to be publicly accessible.
        - Port scanning of internal networks to discover running services.
        - Reading sensitive data from internal services (e.g., configuration files, internal APIs).
        - In some cases, potential for Remote Code Execution (RCE) if vulnerable internal services are exposed.
        - Information disclosure by accessing metadata endpoints of cloud providers.
        - Denial of Service (DoS) by targeting internal services or external resources.

* Vulnerability rank: High

* Currently implemented mitigations:
    - No direct mitigations are implemented within the `request-session` library itself to prevent SSRF based on the `host` parameter.
    - The library relies on the application developer to properly validate and sanitize the `host` input before passing it to `RequestSession`.

* Missing Mitigations:
    - Input validation and sanitization for the `host` parameter within the `RequestSession` library.
    - While it is generally the responsibility of the application to validate user inputs, providing guidance or helper functions within `request-session` to assist with host validation could reduce the risk. However, automatic validation might be too restrictive and limit legitimate use cases. The primary missing mitigation is clear documentation and warnings about the SSRF risk when using user-controlled input for the `host` parameter.

* Preconditions:
    - The application must use the `request-session` library.
    - The application must construct a `RequestSession` instance with the `host` parameter being directly or indirectly derived from user-controlled input.
    - The application must fail to implement proper validation and sanitization of this user-controlled `host` input.

* Source Code Analysis:
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

* Security Test Case:
    - Step-by-step test:
        1. **Setup:** Assume a vulnerable application uses `request-session` and allows users to specify a target host (e.g., through a form field named `target_host`). The application creates a `RequestSession` instance using this user-provided `target_host`.
        2. **Attacker Action:** An attacker crafts a malicious input for the `target_host` field. For example, the attacker sets `target_host` to `http://127.0.0.1:8080`. Assume there is a service running on `http://127.0.0.1:8080` that should not be accessible from the outside.
        3. **Application Request:** The attacker then triggers an action in the application that uses the `RequestSession` instance (created with the attacker-controlled `host`) to make a `get` request with a path, for example, `/api/data`.
        4. **Verification:** The `request-session` library, within the application, will construct the URL as `urljoin('http://127.0.0.1:8080', '/api/data')`, resulting in the final URL `http://127.0.0.1:8080/api/data`. The application will then send a GET request to `http://127.0.0.1:8080/api/data`.
        5. **SSRF Confirmation:** If the attacker can observe a response from `http://127.0.0.1:8080/api/data` (e.g., through application logs, network traffic if they control the 127.0.0.1:8080 service, or indirectly if the application's behavior changes based on the response), it confirms the SSRF vulnerability.