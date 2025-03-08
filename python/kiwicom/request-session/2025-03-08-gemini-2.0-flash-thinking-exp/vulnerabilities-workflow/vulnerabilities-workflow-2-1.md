### Vulnerability List

#### 1. Path Traversal via Unsanitized Path Parameter

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