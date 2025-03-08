- ### Vulnerability 1: Insecure Logging of Sensitive Request Parameters

    - Description:
        1. A developer initializes `RequestSession` with `verbose_logging=True`.
        2. The developer makes HTTP requests using `RequestSession` methods (e.g., `get`, `post`).
        3. The requests include sensitive information in the request parameters, such as API keys in query parameters or request body, or personal data in the request body.
        4. The `_log_with_params` method in `request_session.py` is executed after each request to log request details.
        5. If the keys for sensitive parameters are not added to the `request_param_logging_blacklist`, these parameters are serialized into JSON format using `json.dumps` and included in the log message in plain text.
        6. If these logs are stored or transmitted insecurely, or accessed by unauthorized personnel, attackers can potentially gain access to the sensitive information contained within the logs.

    - Impact:
        Exposure of sensitive information (API keys, passwords, personal data, etc.) to unauthorized parties who have access to the logs. This can lead to serious security breaches, including unauthorized access to systems, data theft, and compliance violations.

    - Vulnerability rank: High

    - Currently implemented mitigations:
        - The `request_param_logging_blacklist` parameter in the `RequestSession` class constructor, which defaults to `("auth", "headers")`. This allows developers to specify request parameters that should be excluded from logging.
        - Source code: `/code/request_session/request_session.py`:
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

    - Missing mitigations:
        - **Documentation and warnings:** Lack of explicit documentation and warnings in the library's documentation about the security risks associated with enabling `verbose_logging` and the importance of sanitizing or excluding sensitive request parameters from logs.
        - **Default blacklist expansion:** The default `request_param_logging_blacklist` is limited to `("auth", "headers")`. It does not include common parameter names that might contain sensitive data (e.g., "api_key", "password", "secret").
        - **Automatic sensitive data detection:** No automatic mechanism to detect and sanitize potentially sensitive data in request parameters.
        - **Secure logging practices guidance:** Lack of recommendations or best practices for secure logging when using `request-session`, such as guidance on log rotation, secure storage, and access control for logs.

    - Preconditions:
        - The `RequestSession` object must be initialized with `verbose_logging=True`.
        - Sensitive information must be present in the request parameters (query parameters, request body, etc.).
        - The keys for sensitive parameters must not be included in the `request_param_logging_blacklist` during `RequestSession` initialization.
        - An attacker must gain unauthorized access to the logs where sensitive information is recorded.

    - Source code analysis:
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

    - Security test case:
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