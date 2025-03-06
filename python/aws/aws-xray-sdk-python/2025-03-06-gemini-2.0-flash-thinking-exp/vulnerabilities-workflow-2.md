## Vulnerability List for AWS X-Ray SDK for Python

### 1. Information Disclosure via Unsanitized Metadata and Annotations

- **Description:**
    - A developer instruments their Python application with the AWS X-Ray SDK for Python.
    - The developer uses the `put_annotation` or `put_metadata` methods provided by the SDK to add custom data to X-Ray segments and subsegments.
    - Unintentionally, the developer includes sensitive information such as API keys, passwords, Personally Identifiable Information (PII), or confidential business data as values in these annotations or metadata.
    - The AWS X-Ray SDK for Python serializes all annotations and metadata and transmits them to the AWS X-Ray service.
    - An attacker who gains access to the AWS X-Ray console or retrieves X-Ray trace data programmatically can view this sensitive information within the annotations or metadata of the segments and subsegments.

- **Impact:**
    - Exposure of sensitive information to unauthorized parties.
    - Potential compromise of accounts and systems if credentials or API keys are exposed.
    - Risk of data breaches if PII or confidential business data is disclosed.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - None. The SDK does not implement any sanitization or checks to prevent developers from logging sensitive data.
    - The README.md provides guidance on sampling and oversampling mitigation, but it does not address the risk of logging sensitive data through annotations or metadata.

- **Missing Mitigations:**
    - Documentation Enhancement: Add a prominent warning in the SDK documentation, specifically in sections describing `put_annotation` and `put_metadata`, explicitly advising developers against logging sensitive data in annotations and metadata. Provide examples of data types that should be excluded from logging.
    - Input Sanitization/Validation (Consideration): While challenging to implement effectively without hindering SDK functionality, consider exploring options for input sanitization or validation. This could involve:
        - Basic checks for common credential patterns (e.g., looking for strings resembling API keys or passwords).
        - Allowing developers to configure regular expressions or patterns to blocklist certain data from being logged.
        - However, emphasize that documentation warning is the primary and most practical mitigation due to the complexity and potential inflexibility of automatic sanitization and validation.

- **Preconditions:**
    - The target application must be instrumented with the AWS X-Ray SDK for Python.
    - Developers must be utilizing the `put_annotation` or `put_metadata` features of the SDK.
    - Developers must inadvertently include sensitive data as annotation or metadata values.
    - An attacker must have legitimate or illegitimate access to the AWS X-Ray console or the ability to programmatically retrieve X-Ray trace data (e.g., through compromised AWS credentials or if X-Ray data is inadvertently exposed).

- **Source Code Analysis:**
    - Vulnerable Code Locations:
        - `aws_xray_sdk/core/models/segment.py`:
            - `put_annotation(self, key, value)`: This method directly stores the provided `value` without any sanitization or validation into the `annotations` dictionary of the `Segment` object.
            - `put_metadata(self, key, value, namespace='default')`: This method directly stores the provided `value` without sanitization or validation into the `metadata` dictionary of the `Segment` object.
        - `aws_xray_sdk/core/models/subsegment.py`:
            - `put_annotation(self, key, value)`:  Similar to the Segment's method, this directly stores the `value` without sanitization.
            - `put_metadata(self, key, value, namespace='default')`: Similar to the Segment's method, this directly stores the `value` without sanitization.
        - `aws_xray_sdk/core/models/entity.py`:
            - `serialize(self)` and `to_dict(self)`: These methods recursively convert the Segment and Subsegment objects, including the `annotations` and `metadata` dictionaries, into a JSON serializable format. This serialized data is then sent to the AWS X-Ray service without any filtering or sanitization of the annotation or metadata values.
    - Code Flow Visualization:
        ```
        Developer Application Code -->  xray_recorder.put_annotation/put_metadata() --> Segment/Subsegment Object (stores data) --> serialize() (in Entity class) --> JSON Payload --> AWS X-Ray Daemon --> AWS X-Ray Service --> Attacker Access (X-Ray Console/API)
        ```
    - Step-by-step vulnerability trigger:
        1. A developer initializes the AWS X-Ray SDK in their Python application.
        2. In the application code, the developer calls `xray_recorder.put_annotation('apiKey', 'AKIA...SECRET...')` or `xray_recorder.put_metadata('dbPassword', 'P@$$wOrd', 'db_config')`.
        3. The `put_annotation` or `put_metadata` method in the `Segment` or `Subsegment` class stores the provided sensitive value directly into the respective data structure.
        4. When the segment or subsegment is closed, the `serialize()` method is invoked to prepare the trace data for transmission.
        5. The `serialize()` method includes the unsanitized annotation or metadata values in the JSON payload.
        6. The AWS X-Ray SDK's emitter sends this JSON payload over UDP to the X-Ray daemon.
        7. The X-Ray daemon forwards the trace data to the AWS X-Ray service.
        8. An attacker with access to the AWS X-Ray console or through the AWS X-Ray API can retrieve and examine the trace data, including the segment or subsegment containing the sensitive information in annotations or metadata.

- **Security Test Case:**
    1. Setup:
        - Ensure you have an AWS account and the AWS CLI configured.
        - Deploy the provided `sample-apps/flask/application.py` to AWS Lambda or a similar environment where it can be publicly accessed. Ensure the AWS X-Ray SDK is correctly configured and tracing is enabled.
        - Install the AWS CLI and jq (command-line JSON processor) on your local machine.
    2. Modify Application:
        - Edit the `sample-apps/flask/application.py` file.
        - In the `/` route handler function (`default()`), add the following lines to inject sensitive metadata:
            ```python
            @app.route('/')
            def default():
                xray_recorder.put_metadata('sensitiveApiKey', 'THIS_IS_A_TEST_API_KEY_DO_NOT_USE_IN_PRODUCTION', 'SensitiveData')
                return "healthcheck"
            ```
        - Redeploy the Flask application.
    3. Trigger Trace Generation:
        - Access the root URL of your deployed Flask application (e.g., `https://<your-app-endpoint>/`). This will trigger the execution of the `/` route and generate an X-Ray trace containing the injected metadata.
    4. Retrieve Trace Data:
        - Use the AWS CLI to retrieve traces. You might need to wait a few minutes for the trace data to be available in X-Ray.
        - Execute the following AWS CLI command to query traces (you may need to adjust the time range):
            ```bash
            aws xray get-trace-summaries --start-time $(date -d "5 minutes ago" +%s) --end-time $(date +%s) | jq '.TraceSummaries[] | .TraceId'
            ```
        - Copy one of the `traceIds` from the output.
        - Use the copied `traceId` to get the full trace details:
            ```bash
            TRACE_ID="<your_copied_trace_id>"
            aws xray get-trace --trace-id $TRACE_ID > trace.json
            ```
    5. Verify Vulnerability:
        - Examine the `trace.json` file. You can use `jq` to easily search for the injected metadata:
            ```bash
            cat trace.json | jq '.Trace.Segments[0].Document | fromjson | .metadata.SensitiveData'
            ```
        - If the vulnerability is present, the command output will include the sensitive API key value: `"THIS_IS_A_TEST_API_KEY_DO_NOT_USE_IN_PRODUCTION"`.
        - Alternatively, you can manually inspect `trace.json` to find the `metadata` section within the segment document and verify the presence of the `sensitiveApiKey` and its value.

This security test case confirms that sensitive information logged as metadata is captured in X-Ray traces and can be retrieved by an attacker with access to the trace data.