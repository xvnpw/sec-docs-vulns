- Vulnerability Name: Cross-Site Request Forgery (CSRF) in `/awsproxy` endpoint

- Description:
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

- Impact:
    - An attacker can perform actions on AWS services using the credentials of an authenticated Jupyter user.
    - This could lead to unauthorized access to sensitive data stored in AWS, modification or deletion of AWS resources, or even financial costs due to unauthorized usage of AWS services.
    - The severity of the impact depends on the permissions associated with the AWS credentials used by the Jupyter server and the specific AWS API actions the attacker can successfully forge.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
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

- Missing Mitigations:
    - Server-side CSRF protection is missing.
    - The server should validate the presence and correctness of a CSRF token in requests to the `/awsproxy` endpoint.
    - Common CSRF mitigation techniques include:
        - Synchronizer Token Pattern: Generate a unique token for each user session and embed it in forms and requests. The server verifies this token before processing the request. Jupyter server framework likely provides built-in mechanisms for this.
        - Double-Submit Cookie: Set a random value in a cookie and as a request parameter. The server verifies if both values match.
        - Checking the Origin or Referer header: While less reliable, these headers can be used to check if the request originated from the same origin as the server.

- Preconditions:
    - An authenticated Jupyter user must be logged into a Jupyter server instance with the `aws-jupyter-proxy` extension enabled.
    - The attacker needs to be able to induce the authenticated user to visit a malicious web page or execute malicious code in their browser while logged into Jupyter.
    - The targeted AWS service must be whitelisted or no whitelist should be configured for the proxy to forward the request.

- Source Code Analysis:
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

- Security Test Case:
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