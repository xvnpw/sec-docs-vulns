### Vulnerability List

- Vulnerability Name: **Endpoint Override to Non-AWS Domain**
- Description: An attacker can bypass the intended AWS service and redirect requests to an arbitrary external domain by providing a crafted `X-service-endpoint-url` header. This occurs because the endpoint override validation only checks for AWS domains (`aws.dev`, `amazonaws.com`, `aws.a2z.com`) but does not enforce that the overridden endpoint belongs to the intended AWS service or even AWS at all if a subdomain of a valid AWS domain is used.
- Impact: **High**
    - An attacker can potentially exfiltrate AWS credentials or sensitive data by redirecting the proxy to an attacker-controlled server.
    - An attacker could perform actions on behalf of the Jupyter server on the attacker-controlled server, potentially leading to further compromise.
- Vulnerability Rank: **High**
- Currently Implemented Mitigations:
    - The code checks if the `endpoint_override` matches a regular expression `r"https:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.(aws.dev|amazonaws.com|aws.a2z.com)\b"`. This regex intends to restrict endpoint overrides to AWS domains. This check is implemented in `aws_jupyter_proxy/awsproxy.py` within the `get_service_info` function.
- Missing Mitigations:
    - Proper validation of the overridden endpoint to ensure it belongs to the intended AWS service and ideally enforce usage of official AWS service endpoints.
    - Restrict endpoint override functionality or provide a more restrictive configuration for allowed override endpoints.
- Preconditions:
    - The attacker needs to be able to send requests to the `/awsproxy` endpoint.
    - The attacker needs to know the name of a whitelisted service to bypass the service whitelist check (if enabled).
- Source Code Analysis:
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

- Security Test Case:
    1.  Set up a simple HTTP server (e.g., using `netcat` or `python -m http.server`) to listen on a public domain, for example, `https://attacker.amazonaws.com`.
    2.  Start the Jupyter server with the `aws-jupyter-proxy` extension installed and enabled. Ensure that `sagemaker` service is whitelisted if service whitelisting is enabled.
    3.  In a Jupyter notebook, use the AWS JavaScript SDK to make a request to a whitelisted AWS service (e.g., SageMaker) through the `/awsproxy` endpoint.
    4.  Include the header `X-service-endpoint-url: https://attacker.amazonaws.com` in the request.
    5.  Send the request.
    6.  Observe the HTTP server logs on `https://attacker.amazonaws.com`. You should see the incoming request, including AWS credentials in the `Authorization` header, being sent to your server instead of AWS SageMaker.
    7.  Verify that the Jupyter server responds with a success code (200) if the attacker server responds with 200, indicating that the proxy successfully forwarded the request to the attacker's endpoint and relayed the response back to the client.

- Vulnerability Name: **Service Whitelist Bypass via Case Manipulation**
- Description: The service whitelist check in `AwsProxyRequest` is case-sensitive. An attacker can bypass the whitelist by providing a service name with a different case than what is configured in the `AWS_JUPYTER_PROXY_WHITELISTED_SERVICES` environment variable. For example, if `sagemaker` is whitelisted, an attacker might be able to bypass the whitelist by requesting the `SageMaker` service.
- Impact: **Medium**
    - An attacker can access AWS services that are not intended to be accessible through the proxy, potentially leading to unauthorized actions and data access within the AWS account.
- Vulnerability Rank: **Medium**
- Currently Implemented Mitigations:
    - Service whitelisting is implemented using the `AWS_JUPYTER_PROXY_WHITELISTED_SERVICES` environment variable. The `AwsProxyRequest.execute_downstream` function checks if the requested service is in the whitelist.
    - ```python
      if (
          self.whitelisted_services is not None
          and self.service_info.service_name not in self.whitelisted_services
      ):
          raise HTTPError(
              403,
              message=f"Service {self.service_info.service_name} is not whitelisted for proxying requests",
          )
      ```
- Missing Mitigations:
    - The service whitelist check should be case-insensitive.
    - Input sanitization or normalization of service names before performing the whitelist check.
- Preconditions:
    - Service whitelisting must be enabled by setting the `AWS_JUPYTER_PROXY_WHITELISTED_SERVICES` environment variable.
    - The attacker needs to know the name of a service that is *not* whitelisted but can be accessed by manipulating the case of a whitelisted service name.
- Source Code Analysis:
    - In `aws_jupyter_proxy/awsproxy.py`, the `AwsProxyRequest.execute_downstream` function performs the whitelist check.
    - The code retrieves the whitelisted services from the environment variable and splits them into a list:
      ```python
      self.whitelisted_services = (
          os.getenv("AWS_JUPYTER_PROXY_WHITELISTED_SERVICES").strip(",").split(",")
          if os.getenv("AWS_JUPYTER_PROXY_WHITELISTED_SERVICES") is not None
          else None
      )
      ```
    - The service name from the request is obtained from `self.service_info.service_name`.
    - The check `self.service_info.service_name not in self.whitelisted_services` performs a case-sensitive comparison.
    - If the case of the service name in the request does not exactly match the case in the whitelist, the check will fail, even if the service name is the same ignoring case.

- Security Test Case:
    1.  Start the Jupyter server with the `aws-jupyter-proxy` extension installed and enabled.
    2.  Set the environment variable `AWS_JUPYTER_PROXY_WHITELISTED_SERVICES` to `sagemaker`.
    3.  In a Jupyter notebook, use the AWS JavaScript SDK to make a request to the SageMaker service (note the uppercase 'S') through the `/awsproxy` endpoint.
    4.  Send a SageMaker API request (e.g., `listNotebookInstances`).
    5.  Observe that the request is successfully proxied to AWS SageMaker, even though the whitelist is configured with `sagemaker` (lowercase 's'). This indicates a bypass of the case-sensitive whitelist.
    6.  If the request is successful, change the case in the whitelist environment variable to `SageMaker` and retry with `sagemaker` (lowercase 's') in the request. Verify that it is now blocked.