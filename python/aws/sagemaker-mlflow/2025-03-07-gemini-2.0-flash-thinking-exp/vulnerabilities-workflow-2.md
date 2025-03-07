### Combined Vulnerability List

* Vulnerability: Uncontrolled Presigned URL Expiration Time

    * Description:
        1. The `get_presigned_url` function in `sagemaker_mlflow/presigned_url.py` generates presigned URLs for accessing the SageMaker MLflow tracking server.
        2. This function accepts optional parameters `url_expiration_duration` and `session_duration` to control the expiration of the generated URL and session.
        3. The provided code directly passes these parameters to the `create_presigned_mlflow_tracking_server_url` API call without any validation or restriction on the maximum allowed values.
        4. An attacker who can control or influence these parameters, or if default values are excessively high, can request presigned URLs with very long expiration times.
        5. If such a long-lived presigned URL is leaked or intercepted, it can be used by an unauthorized party to access the SageMaker MLflow tracking server for an extended period.

    * Impact:
        - Unauthorized access to the SageMaker MLflow tracking server.
        - Potential data exfiltration or manipulation within the MLflow tracking server by an attacker using a leaked, long-lived presigned URL.
        - Compromise of machine learning models and associated metadata stored in the tracking server.

    * Vulnerability Rank: Medium

    * Currently Implemented Mitigations:
        - None. The code directly uses the provided expiration durations without any validation or limitations.

    * Missing Mitigations:
        - Input validation for `url_expiration_duration` and `session_duration` within the `get_presigned_url` function.
        - Implementation of maximum allowed values for both `url_expiration_duration` and `session_duration` to limit the lifespan of presigned URLs.
        - Security best practice documentation advising users on the risks of long-lived presigned URLs and guidance on secure handling and management of these URLs.

    * Preconditions:
        - An attacker needs to be able to influence the `url_expiration_duration` and `session_duration` parameters when calling `get_presigned_url`, or rely on insecure default values if they are too high. This might occur if the application using this plugin exposes functionality to generate presigned URLs with user-controlled expiration.
        - A generated presigned URL with an extended expiration time needs to be leaked to the attacker. This could happen through insecure logging, network interception, or accidental exposure.

    * Source Code Analysis:
        - File: `/code/sagemaker_mlflow/presigned_url.py`
        ```python
        def get_presigned_url(url_expiration_duration=300, session_duration=5000) -> str:
            """ Creates a presigned url

            :param url_expiration_duration: First use expiration time of the presigned url
            :param session_duration: Session duration of the presigned url

            :returns: Authorized Url

            """
            arn = validate_and_parse_arn(mlflow.get_tracking_uri())
            custom_endpoint = os.environ.get("SAGEMAKER_ENDPOINT_URL", "")
            if not custom_endpoint:
               sagemaker_client = boto3.client("sagemaker", region_name=arn.region)
            else:
                sagemaker_client = boto3.client("sagemaker", endpoint_url=custom_endpoint, region_name=arn.region)

            config = {
                "TrackingServerName": arn.resource_id,
                "ExpiresInSeconds": url_expiration_duration,
                "SessionExpirationDurationInSeconds": session_duration
            }
            response = sagemaker_client.create_presigned_mlflow_tracking_server_url(**config)
            return response["AuthorizedUrl"]
        ```
        - The code directly uses `url_expiration_duration` and `session_duration` from the function parameters to construct the `config` dictionary, which is then passed to `create_presigned_mlflow_tracking_server_url`.
        - There is no input validation or upper limit enforcement on these parameters before they are sent to the AWS API.

    * Security Test Case:
        1. Set up a SageMaker MLflow tracking server and obtain its ARN.
        2. Set the `MLFLOW_TRACKING_URI` environment variable to the tracking server ARN.
        3. Call the `sagemaker_mlflow.presigned_url.get_presigned_url` function with a very large value for `url_expiration_duration`, for example, `url_expiration_duration=86400` (24 hours).
        4. Capture the generated presigned URL.
        5. Wait for a significant duration (e.g., a few hours, but less than the requested expiration).
        6. Using a different machine or network context (to simulate an attacker who obtained a leaked URL), attempt to access the SageMaker MLflow tracking server using the captured presigned URL by sending a GET request to it.
        7. Verify that the request is successful and returns a 200 OK status code, indicating that the presigned URL is still valid and grants access to the tracking server after a long duration.
        8. This confirms that an attacker with a leaked URL could maintain access for an extended period due to the lack of expiration time control.

* Vulnerability: Unvalidated Custom Endpoint URL leading to Server-Side Request Forgery (SSRF)

    * Description:
        1. The `get_tracking_server_url` function in `sagemaker_mlflow/mlflow_sagemaker_helpers.py` retrieves the value of the `SAGEMAKER_MLFLOW_CUSTOM_ENDPOINT` environment variable.
        2. If the `SAGEMAKER_MLFLOW_CUSTOM_ENDPOINT` environment variable is set, the function directly returns its value as the tracking server URL without any validation.
        3. This custom endpoint URL is then used in subsequent requests to the MLflow tracking server.
        4. An attacker who can control the `SAGEMAKER_MLFLOW_CUSTOM_ENDPOINT` environment variable can set it to a malicious URL.
        5. When the MLflow plugin makes requests to the tracking server, these requests will be redirected to the attacker-controlled URL, leading to a Server-Side Request Forgery (SSRF) vulnerability.

    * Impact:
        An attacker can redirect requests originating from the server running the MLflow plugin to an arbitrary URL under their control. This can have several impacts:
        - **Data Exfiltration:** Sensitive data intended for the MLflow tracking server could be intercepted and exfiltrated to the attacker's server.
        - **Internal Network Scanning:** The attacker could use the server running the MLflow plugin to scan internal network resources that are not directly accessible from the outside.
        - **Denial of Service:** The attacker could redirect requests to a resource that causes the server to become overloaded or unresponsive.
        - **Credential Exposure:** If the MLflow plugin sends authentication credentials with the requests (though in this case it uses SigV4), these could be exposed if redirected to a non-HTTPS endpoint or a malicious server.

    * Vulnerability Rank: Medium

    * Currently Implemented Mitigations:
        - None. The code directly uses the custom endpoint URL without any validation if the `SAGEMAKER_MLFLOW_CUSTOM_ENDPOINT` environment variable is set.

    * Missing Mitigations:
        - **URL Validation:** Implement validation for the `SAGEMAKER_MLFLOW_CUSTOM_ENDPOINT` environment variable. This should include:
            - **Protocol Check:** Ensure the URL uses HTTPS protocol to protect data in transit.
            - **Domain Whitelist/Blacklist:**  Ideally, restrict the allowed domains to a whitelist of trusted domains or implement a blacklist to prevent known malicious domains. If only connections to SageMaker are intended, consider enforcing that the domain must be within the `sagemaker.aws` or similar domain.
            - **Format Validation:** Validate the URL format to prevent unexpected or malicious URL structures.
        - **Documentation Warning:** Add a clear warning in the documentation about the security risks of using `SAGEMAKER_MLFLOW_CUSTOM_ENDPOINT` and advise users to only use it if absolutely necessary and with extreme caution.

    * Preconditions:
        - The attacker must be able to control the environment variable `SAGEMAKER_MLFLOW_CUSTOM_ENDPOINT` where the MLflow plugin is running. This could be achieved through various means depending on the deployment environment, such as:
            - Compromising the server where the MLflow application is running.
            - Supply chain attack if the environment variables are set during build or deployment process.
            - In some misconfigured cloud environments, environment variables might be inadvertently exposed or modifiable.

    * Source Code Analysis:
        - File: `/code/sagemaker_mlflow/mlflow_sagemaker_helpers.py`
        - Function: `get_tracking_server_url`
        ```python
        def get_tracking_server_url(tracking_server_arn: str) -> str:
            """Returns the url used by SageMaker MLflow

            Args:
               tracking_server_arn (str): Tracking Server Arn
            Returns:
                str: Tracking Server URL.
            """
            custom_endpoint = os.environ.get("SAGEMAKER_MLFLOW_CUSTOM_ENDPOINT", "")
            if custom_endpoint:
                logging.info(f"Using custom endpoint {custom_endpoint}")
                return custom_endpoint # Vulnerability: Directly returns custom endpoint without validation
            arn = validate_and_parse_arn(tracking_server_arn)
            dns_suffix = get_dns_suffix(arn.partition)
            endpoint = f"https://{arn.region}.experiments.sagemaker.{dns_suffix}"
            return endpoint
        ```
        - The code snippet shows that if `custom_endpoint` is not empty (i.e., `SAGEMAKER_MLFLOW_CUSTOM_ENDPOINT` is set), the function immediately returns the value of `custom_endpoint` without any validation.
        - The `validate_and_parse_arn` function is only called if `SAGEMAKER_MLFLOW_CUSTOM_ENDPOINT` is not set, meaning the validation is bypassed when a custom endpoint is provided.

    * Security Test Case:
        1. **Setup Attacker Server:**  Set up a simple HTTP server (e.g., using `netcat` or Python's `http.server`) on `attacker.com` to listen on port 80 and log incoming requests. For example, using python: `python -m http.server 80`
        2. **Set Environment Variable:** In the environment where the MLflow plugin is running, set the environment variable `SAGEMAKER_MLFLOW_CUSTOM_ENDPOINT` to `http://attacker.com`.
        3. **Set MLFLOW_TRACKING_URI:** Set the `MLFLOW_TRACKING_URI` environment variable to a valid SageMaker ARN, for example: `arn:aws:sagemaker:us-west-2:000000000000:mlflow-tracking-server/test-server`. This is needed to satisfy other parts of the plugin initialization, but the custom endpoint should override it.
        4. **Execute MLflow Operation:** Run a simple MLflow operation that triggers a request to the tracking server. For example, execute the following Python code:
        ```python
        import mlflow
        mlflow.set_tracking_uri("arn") # "arn" will trigger the plugin
        mlflow.create_experiment("test_experiment_ssrf")
        ```
        5. **Observe SSRF:** Check the logs of the attacker's HTTP server (`attacker.com`). You should see an HTTP request logged, indicating that the MLflow plugin's request was redirected to `http://attacker.com` due to the `SAGEMAKER_MLFLOW_CUSTOM_ENDPOINT` setting. The request details in the logs will confirm the SSRF.

* Vulnerability: Unrestricted Presigned URL Generation

    * Description:
        1. An attacker gains access to an MLflow tracking server that is configured with the SageMaker MLflow plugin. This access could be obtained through various means, such as exploiting vulnerabilities in MLflow itself or compromising MLflow user credentials if basic authentication is enabled alongside SigV4. For the purpose of this vulnerability, we assume the attacker has a valid way to interact with the MLflow tracking server, even with limited permissions.
        2. The IAM role associated with the SageMaker MLflow tracking server is configured with the `sagemaker:CreatePresignedMlflowTrackingServerUrl` permission. This permission is necessary for the `get_presigned_url` function in the plugin to work.
        3. The attacker, now having access to the MLflow tracking server (and thus indirectly using the plugin), can invoke the `sagemaker_mlflow.presigned_url.get_presigned_url()` function. This function is intended to generate presigned URLs for accessing the SageMaker MLflow tracking server.
        4. Upon invocation, `get_presigned_url` function uses the configured AWS credentials (assumed by the MLflow tracking server's IAM role) to call the `create_presigned_mlflow_tracking_server_url` API, generating a presigned URL.
        5. This generated presigned URL provides temporary, credential-less access to the SageMaker MLflow tracking server API endpoints.
        6. If the IAM policy attached to the tracking server's role grants overly broad permissions for `sagemaker:CreatePresignedMlflowTrackingServerUrl`, the generated presigned URL might inadvertently grant access to a wider range of SageMaker MLflow actions than the attacker was initially authorized for through their MLflow access. This is because the presigned URL's permissions are tied to the IAM role of the tracking server, not necessarily restricted to the initial MLflow user's intended access level.

    * Impact:
        - **Unauthorized Access to SageMaker MLflow APIs:** An attacker with limited access to the MLflow tracking server can potentially escalate their privileges to perform actions they are not supposed to, by leveraging presigned URLs.
        - **Data Manipulation or Exfiltration:** If the overly permissive IAM policy allows, the attacker could use the presigned URL to access sensitive data managed by the SageMaker MLflow tracking server or even manipulate models and experiments.
        - **Circumvention of Intended Access Controls:** The presigned URL mechanism, if not carefully permissioned, can bypass the intended access control mechanisms for the SageMaker MLflow service, leading to security breaches.

    * Vulnerability Rank: Medium

    * Currently Implemented Mitigations:
        - None in the code. The plugin itself does not implement any mitigations for this vulnerability. The security relies entirely on the user correctly configuring IAM roles with the principle of least privilege.

    * Missing Mitigations:
        - **Guidance on IAM Permissions:** The plugin's documentation should prominently feature strong warnings and best practices regarding IAM role configuration. It should emphasize the principle of least privilege for the IAM role associated with the MLflow tracking server, specifically concerning the `sagemaker:CreatePresignedMlflowTrackingServerUrl` permission.
        - **Mechanism to Restrict Presigned URL Scope (Ideal but complex):** Ideally, although complex and potentially outside the current scope of the plugin, a mechanism could be introduced to allow administrators to restrict the scope or capabilities of generated presigned URLs. This could involve options to limit expiration time, restrict accessible API actions via the presigned URL, or enforce additional authorization checks.

    * Preconditions:
        - A SageMaker MLflow tracking server is deployed and configured to use this plugin.
        - The IAM role associated with the tracking server is granted the `sagemaker:CreatePresignedMlflowTrackingServerUrl` permission.
        - An attacker has some form of access to the MLflow tracking server, allowing them to interact with the plugin's functionalities indirectly (e.g., as a legitimate MLflow user with limited permissions, or through some other form of compromised access).

    * Source Code Analysis:
        - **`sagemaker_mlflow/presigned_url.py` - `get_presigned_url` function:**
        ```python
        def get_presigned_url(url_expiration_duration=300, session_duration=5000) -> str:
            """ Creates a presigned url
            ...
            """
            arn = validate_and_parse_arn(mlflow.get_tracking_uri())
            custom_endpoint = os.environ.get("SAGEMAKER_ENDPOINT_URL", "")
            if not custom_endpoint:
               sagemaker_client = boto3.client("sagemaker", region_name=arn.region)
            else:
                sagemaker_client = boto3.client("sagemaker", endpoint_url=custom_endpoint, region_name=arn.region)

            config = {
                "TrackingServerName": arn.resource_id,
                "ExpiresInSeconds": url_expiration_duration,
                "SessionExpirationDurationInSeconds": session_duration
            }
            response = sagemaker_client.create_presigned_mlflow_tracking_server_url(**config)
            return response["AuthorizedUrl"]
        ```
        - The code directly uses `boto3.client('sagemaker')` to create a SageMaker client. This client will assume the IAM role configured for the environment where the MLflow tracking server is running.
        - It then calls `create_presigned_mlflow_tracking_server_url` without any additional permission checks or scope restrictions beyond what the IAM role allows.
        - The function is readily accessible and can be invoked by anyone who can interact with the MLflow tracking server and potentially trigger plugin functionality.

    * Security Test Case:
        1. **Setup:** Deploy a SageMaker MLflow tracking server using this plugin. Ensure the IAM role associated with this tracking server has the `sagemaker:CreatePresignedMlflowTrackingServerUrl` permission, and for testing purposes, also grant it broader `sagemaker:*` or similar permissions to clearly demonstrate the potential impact.
        2. **Access MLflow Tracking Server:** Obtain credentials to interact with the MLflow tracking server. This could be done as a legitimate user or by simulating a compromised MLflow access scenario.
        3. **Generate Presigned URL:** Using the MLflow client (configured to use the SageMaker MLflow plugin), or by directly invoking the `sagemaker_mlflow.presigned_url.get_presigned_url()` function (if directly accessible in the environment), generate a presigned URL.  For example, if you are in a python environment where the plugin is installed and MLflow tracking URI is set:
            ```python
            import sagemaker_mlflow.presigned_url
            presigned_url = sagemaker_mlflow.presigned_url.get_presigned_url()
            print(presigned_url)
            ```
        4. **Use Presigned URL:**  Use the generated `presigned_url` to make a request to a SageMaker MLflow Tracking Server API endpoint. For example, using `curl` or `requests` in Python, try to access an endpoint that would typically require higher permissions than what the attacker is assumed to have initially within MLflow. A simple test would be to try and list experiments or models using the presigned URL.
            ```bash
            curl "<presigned_url>/experiments/list"
            ```
        5. **Verify Unauthorized Access:** Check if the request to the SageMaker MLflow Tracking Server API endpoint using the presigned URL is successful. If it is, and if the action performed (e.g., listing experiments) is something the attacker should not have been able to do based on their initial assumed limited MLflow access, then the vulnerability is confirmed.
        6. **IAM Policy Refinement (Mitigation Test):** As a mitigation test, refine the IAM policy for the tracking server's role to grant only the necessary minimum permissions. Ideally, for `sagemaker:CreatePresignedMlflowTrackingServerUrl`, restrict the resources and actions further if possible (though the granularity of this permission might be limited by AWS SageMaker service capabilities). Re-run the test case to see if the refined IAM policy effectively restricts the scope of the presigned URLs and mitigates the vulnerability.