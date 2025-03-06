- Vulnerability Name: Whitelisting Bypass via Service Name Manipulation
- Description:
    1. The AWS Jupyter Proxy uses an environment variable `AWS_JUPYTER_PROXY_WHITELISTED_SERVICES` to restrict access to specific AWS services.
    2. The whitelisting mechanism checks the service name extracted from the `Credential` field of the `Authorization` header of the incoming request.
    3. However, the proxy determines the target AWS service endpoint and constructs the downstream request URL based on the request path, which is independent of the service name in the `Authorization` header.
    4. An attacker can craft a request with an `Authorization` header that claims to be for a whitelisted service (e.g., "sagemaker").
    5. Simultaneously, the attacker can modify the request path (URI after `/awsproxy/`) to target a different, non-whitelisted AWS service (e.g., "s3").
    6. The proxy will incorrectly check the whitelisting against the *claimed* service ("sagemaker" in this example), which passes if "sagemaker" is whitelisted.
    7. The proxy then constructs the downstream request URL based on the path, effectively sending the request to the *unintended* and potentially non-whitelisted service (e.g., S3).
    8. This allows an attacker to bypass the intended service whitelisting and access AWS services that were not meant to be exposed through the proxy.
- Impact:
    - Bypass of intended service whitelisting.
    - Unauthorized access to AWS services not meant to be exposed through the proxy.
    - Potential unauthorized actions within the AWS account, depending on the permissions associated with the IAM role used by the Jupyter server. For example, if only "sagemaker" is intended to be whitelisted, but an attacker bypasses this to access "s3", they could potentially read, write, or delete objects in S3 buckets if the Jupyter server's IAM role has sufficient S3 permissions.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - Service whitelisting is implemented using the `AWS_JUPYTER_PROXY_WHITELISTED_SERVICES` environment variable in `aws_jupyter_proxy/awsproxy.py` within the `AwsProxyRequest.execute_downstream` method.
    - However, the whitelisting is based on the service name from the `Authorization` header, which is insufficient to prevent the described bypass.
- Missing Mitigations:
    - The whitelisting mechanism should be improved to validate the target AWS service based on the request path (URI after `/awsproxy/`) instead of solely relying on the service name from the `Authorization` header.
    - Ideally, the proxy should parse the request path to determine the intended AWS service and then verify if this *intended service* is in the whitelist.
- Preconditions:
    - Service whitelisting must be enabled by setting the `AWS_JUPYTER_PROXY_WHITELISTED_SERVICES` environment variable to a comma-separated list of allowed services.
    - An attacker must have the ability to send HTTP requests to the Jupyter server's `/awsproxy` endpoint.
    - The attacker needs to understand how to construct a valid AWS SigV4 `Authorization` header, even if they only need to modify the service name part to claim a whitelisted service.
- Source Code Analysis:
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

- Security Test Case:
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