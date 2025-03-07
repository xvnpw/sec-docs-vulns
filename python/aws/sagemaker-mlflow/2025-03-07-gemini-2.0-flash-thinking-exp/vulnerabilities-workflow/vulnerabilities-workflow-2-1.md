### Vulnerability List:

- Vulnerability Name: Uncontrolled Presigned URL Expiration Time

- Description:
    1. The `get_presigned_url` function in `sagemaker_mlflow/presigned_url.py` generates presigned URLs for accessing the SageMaker MLflow tracking server.
    2. This function accepts optional parameters `url_expiration_duration` and `session_duration` to control the expiration of the generated URL and session.
    3. The provided code directly passes these parameters to the `create_presigned_mlflow_tracking_server_url` API call without any validation or restriction on the maximum allowed values.
    4. An attacker who can control or influence these parameters, or if default values are excessively high, can request presigned URLs with very long expiration times.
    5. If such a long-lived presigned URL is leaked or intercepted, it can be used by an unauthorized party to access the SageMaker MLflow tracking server for an extended period.

- Impact:
    - Unauthorized access to the SageMaker MLflow tracking server.
    - Potential data exfiltration or manipulation within the MLflow tracking server by an attacker using a leaked, long-lived presigned URL.
    - Compromise of machine learning models and associated metadata stored in the tracking server.

- Vulnerability Rank: Medium

- Currently Implemented Mitigations:
    - None. The code directly uses the provided expiration durations without any validation or limitations.

- Missing Mitigations:
    - Input validation for `url_expiration_duration` and `session_duration` within the `get_presigned_url` function.
    - Implementation of maximum allowed values for both `url_expiration_duration` and `session_duration` to limit the lifespan of presigned URLs.
    - Security best practice documentation advising users on the risks of long-lived presigned URLs and guidance on secure handling and management of these URLs.

- Preconditions:
    - An attacker needs to be able to influence the `url_expiration_duration` and `session_duration` parameters when calling `get_presigned_url`, or rely on insecure default values if they are too high. This might occur if the application using this plugin exposes functionality to generate presigned URLs with user-controlled expiration.
    - A generated presigned URL with an extended expiration time needs to be leaked to the attacker. This could happen through insecure logging, network interception, or accidental exposure.

- Source Code Analysis:
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

- Security Test Case:
    1. Set up a SageMaker MLflow tracking server and obtain its ARN.
    2. Set the `MLFLOW_TRACKING_URI` environment variable to the tracking server ARN.
    3. Call the `sagemaker_mlflow.presigned_url.get_presigned_url` function with a very large value for `url_expiration_duration`, for example, `url_expiration_duration=86400` (24 hours).
    4. Capture the generated presigned URL.
    5. Wait for a significant duration (e.g., a few hours, but less than the requested expiration).
    6. Using a different machine or network context (to simulate an attacker who obtained a leaked URL), attempt to access the SageMaker MLflow tracking server using the captured presigned URL by sending a GET request to it.
    7. Verify that the request is successful and returns a 200 OK status code, indicating that the presigned URL is still valid and grants access to the tracking server after a long duration.
    8. This confirms that an attacker with a leaked URL could maintain access for an extended period due to the lack of expiration time control.