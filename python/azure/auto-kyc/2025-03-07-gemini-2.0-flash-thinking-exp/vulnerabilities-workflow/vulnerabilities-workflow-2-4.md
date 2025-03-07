- Vulnerability Name: Insecure Liveness Check Configuration
- Description:
    1. An attacker intercepts the API request to `/api/detectLiveness`.
    2. The attacker modifies the `livenessOperationMode` parameter in the request body, changing it from a more secure mode (if available, though not specified in the code) to a less secure or even "passive" mode if such an option existed in the Face API (which is not standard, but represents a potential misconfiguration risk).
    3. The attacker replays the modified request to the server.
    4. The backend, without proper validation of the `livenessOperationMode`, passes this attacker-controlled parameter directly to the Azure Face Liveness API.
    5. If the Azure Face API and the client-side UI allow for less secure modes or if the default mode is already weak, the liveness check becomes easier to bypass. For instance, if a "passive" mode existed and was selected, it might only rely on simple checks that are easily fooled by sophisticated deepfakes or masks.
    6. The attacker then proceeds with the identity verification process, potentially using deepfake or mask, as the liveness check is now weakened due to the attacker-controlled configuration.
- Impact: Successful bypass of the face liveness detection allows an attacker to impersonate a legitimate user and potentially gain unauthorized access to services or sensitive information that the KYC process is designed to protect. This undermines the identity verification process.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations:
    - The code uses Azure Face Liveness API, which is designed to perform liveness detection.
    - The `FaceLivenessDetectionService` in `/code/code/utils/face_liveness.py` encapsulates the interaction with the Azure Face API.
    - The API endpoint `/api/detectLiveness` in `/code/api.py` is used to initiate the liveness check.
- Missing Mitigations:
    - **Server-side validation of `livenessOperationMode`**: The backend should validate and sanitize the `livenessOperationMode` parameter received from the client. It should enforce the use of the most secure liveness detection mode and prevent the client from downgrading to less secure modes. Currently, the code in `/code/api.py` directly parses the `parameters` string into `LivenessSessionRequest` and passes it to `FaceLivenessDetectionService` without any validation.
    - **Configuration Management**: Securely manage the allowed `livenessOperationMode` configurations, ideally setting it to the most robust option and preventing easy modification.
- Preconditions:
    - Attacker's ability to intercept or manipulate API requests to `/api/detectLiveness`.
    - Vulnerability relies on the assumption that Azure Face API (or a future version) might offer different liveness operation modes with varying security levels, or that the default mode is not sufficiently robust against sophisticated attacks.
    - The client-side UI must be designed to send a `livenessOperationMode` parameter that the attacker can then modify.
- Source Code Analysis:
    - File: `/code/api.py`
    ```python
    @app.post("/api/detectLiveness", response_model=LivenessSessionResponse)
    async def detect_liveness(
        parameters: str = Form(...),
        verify_image: UploadFile = File(None)
    ):
        # Log incoming data for debugging
        print("Received parameters:", parameters)
        print("Received verify_image:", verify_image.filename if verify_image else None)

        # Parse the parameters
        session_request = LivenessSessionRequest.parse_raw(parameters)

        # Read the verify image if provided
        verify_image_content = None
        if verify_image is not None:
            verify_image_content = await verify_image.read()

        flc = FaceLivenessDetectionService()
        session = await flc.startLivenessDetection(session_request, verify_image_content)

        return {
            "authToken": session.auth_token,
            "session_id": session.session_id
        }
    ```
    - The `detect_liveness` function in `/code/api.py` takes `parameters` as a `Form` input and directly parses it into `LivenessSessionRequest`.
    - File: `/code/code/utils/face_liveness.py`
    ```python
    class LivenessSessionRequest(BaseModel):
        livenessOperationMode: str
        sendResultsToClient: bool
        deviceCorrelationId: str

    class FaceLivenessDetectionService:
        # ...
        async def startLivenessDetection(self, live_session_content=None, verify_image_content=None):
            if verify_image_content is not None:
                # Create liveness session with verification
                created_session = self.face_session_client.create_liveness_with_verify_session(
                    CreateLivenessWithVerifySessionContent(
                        liveness_operation_mode=live_session_content.livenessOperationMode, # <--- livenessOperationMode from request
                        device_correlation_id=live_session_content.deviceCorrelationId,
                        send_results_to_client=live_session_content.sendResultsToClient,
                        auth_token_time_to_live_in_seconds=self.auth_token_time_to_live_in_seconds,
                    ),
                    verify_image=verify_image_content,
                )
            else:
                # Create liveness session without verification
                created_session = self.face_session_client.create_liveness_session(
                    CreateLivenessSessionContent(
                        liveness_operation_mode=live_session_content.livenessOperationMode, # <--- livenessOperationMode from request
                        device_correlation_id=live_session_content.deviceCorrelationId,
                        send_results_to_client=live_session_content.sendResultsToClient,
                        auth_token_time_to_live_in_seconds=self.auth_token_time_to_live_in_seconds,
                    )
                )
            # ...
    ```
    - The `startLivenessDetection` function in `/code/code/utils/face_liveness.py` receives `live_session_content` which is a `LivenessSessionRequest` object.
    - The `livenessOperationMode` attribute from this object, which originates directly from the client request, is passed to `CreateLivenessSessionContent` or `CreateLivenessWithVerifySessionContent` without any server-side checks.
    - Visualization:

    ```
    Client Request (Modified livenessOperationMode) --> /api/detectLiveness (api.py) --> LivenessSessionRequest (parse_raw) --> FaceLivenessDetectionService.startLivenessDetection (face_liveness.py) --> Azure Face API (livenessOperationMode parameter used directly) --> Liveness Check Result (potentially weakened)
    ```

- Security Test Case:
    1. **Setup**: Ensure the KYC application is running and accessible. Have a tool to intercept and modify HTTP requests (e.g., Burp Suite, OWASP ZAP, or browser developer tools).
    2. **Initiate Liveness Check**: Using the frontend UI, start the face liveness detection process. Capture the API request sent to `/api/detectLiveness`.
    3. **Modify Request**: In the intercepted request, locate the `parameters` field (which is a JSON string). Modify the `livenessOperationMode` value within this JSON string. For example, if the original value is "active", try changing it to a hypothetical less secure mode like "passive" or even an invalid value to observe the behavior.
    4. **Replay Request**: Replay the modified request to the `/api/detectLiveness` endpoint.
    5. **Observe Response**: Check the API response. If the server does not validate `livenessOperationMode`, it might accept the modified value.
    6. **Attempt Liveness Bypass**: Proceed with the liveness detection process using a sophisticated deepfake video or a high-quality mask. If the `livenessOperationMode` modification was successful in weakening the check, the deepfake or mask might now bypass the liveness detection, even if it would have been detected under a more secure configuration.
    7. **Verify Bypass**: If the liveness check is bypassed, and the application proceeds as if the liveness check was successful, the vulnerability is confirmed.

This vulnerability highlights a potential insecure design where client-provided configuration parameters for security-sensitive operations are not validated on the server-side, allowing for potential downgrading of security measures by an attacker.