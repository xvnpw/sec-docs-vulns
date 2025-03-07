### Vulnerability List for Azure Video Analyzer Project

* Vulnerability Name: Deprecated Software Vulnerability - Potential Memory Corruption in Azure Video Analyzer IoT Edge Module
    * Description:
        1. Azure Video Analyzer (AVA) IoT Edge module is deprecated and no longer maintained.
        2. The code base is not actively monitored for security vulnerabilities, and no patches are being released.
        3. A potential memory corruption vulnerability, such as a buffer overflow, may exist within the AVA IoT Edge module itself.
        4. An attacker could potentially exploit this memory corruption by sending specially crafted video streams to the deprecated AVA IoT Edge module, targeting an endpoint like the RTSP input.
        5. By sending malformed or oversized video data, an attacker might trigger a buffer overflow or other memory corruption issue.
        6. Successful exploitation could lead to arbitrary code execution on the edge device.
    * Impact:
        - Remote Code Execution (RCE) on the IoT Edge device, granting the attacker complete control.
        - Potential data exfiltration, device manipulation, or use of the device as a network entry point.
        - Amplified impact due to deployment in sensitive environments like industrial control systems or surveillance networks.
    * Vulnerability Rank: Critical
    * Currently Implemented Mitigations:
        - None. The software is deprecated, and no further mitigations are being implemented by Microsoft.
        - Project files are for extensions, not the core AVA module, and do not contain mitigations for core AVA vulnerabilities.
    * Missing Mitigations:
        - Code review and patching of potential memory corruption vulnerabilities in the core AVA IoT Edge module.
        - Input validation and sanitization for video streams processed by the AVA IoT Edge module.
        - Memory safety measures in the C/C++ or C# codebase of the AVA IoT Edge module.
        - Regular security updates and patching for the AVA IoT Edge module.
    * Preconditions:
        - Deployed and accessible instance of the deprecated Azure Video Analyzer IoT Edge module.
        - Ability for the attacker to send network traffic (crafted video streams) to the AVA IoT Edge module.
        - Vulnerability existing in the core AVA IoT Edge module.
    * Source Code Analysis:
        - Source code for the core Azure Video Analyzer IoT Edge module is not provided.
        - Direct source code analysis to pinpoint the memory corruption vulnerability is not possible based on the provided files.
        - Project files mainly contain extension modules, setup scripts, and documentation, not revealing core AVA module's video processing logic.
    * Security Test Case:
        1. Set up a test environment with a deployed instance of the Azure Video Analyzer IoT Edge module.
        2. Identify the RTSP input endpoint or other video stream processing endpoints.
        3. Craft malformed video streams with oversized headers, long metadata, or unusual codec parameters using tools like `ffmpeg`.
        4. Send crafted video streams to the identified endpoint of the AVA IoT Edge module.
        5. Monitor the IoT Edge device for signs of memory corruption or crashes, such as system logs for memory allocation errors or module process crashes.
        6. Observe if crashes or memory corruption occur consistently when sending crafted streams, indicating a potential memory corruption vulnerability.

* Vulnerability Name: Buffer Overflow in Image Decoding in gRPC Extension
    * Description:
        1. The gRPC extension for YOLOv3 and Tiny YOLOv3 utilizes OpenCV's `cv2.imdecode` function to decode image data received from the Azure Video Analyzer edge module.
        2. An attacker can send maliciously crafted video streams or image frames as input to the gRPC extension.
        3. `cv2.imdecode`, if vulnerable to buffer overflows when processing malformed image formats (JPEG, PNG, BMP), could lead to memory corruption.
        4. Exploiting a buffer overflow in `cv2.imdecode` could allow an attacker to overwrite critical memory regions.
        5. This memory corruption can be leveraged to achieve arbitrary code execution on the IoT Edge device.
        6. The vulnerability is triggered in the `ProcessMediaStream` function in `inference_engine.py` when calling `GetCvImageFromRawBytes`, which uses `cv2.imdecode`.
    * Impact:
        - Remote Code Execution (RCE) on the IoT Edge device, granting complete control.
        - Potential data exfiltration, denial of service, or further network attacks.
    * Vulnerability Rank: Critical
    * Currently Implemented Mitigations:
        - None identified. The code directly uses `cv2.imdecode` without input validation or sanitization.
    * Missing Mitigations:
        - Input validation: Implement checks on incoming image data before `cv2.imdecode`, including file type validation, header parsing, and size limits.
        - Secure decoding libraries: Consider using safer image decoding libraries with regular security patching.
        - Sandboxing: Run the gRPC extension in a sandboxed environment to limit exploit impact.
        - Memory safety checks: Utilize compiler and runtime memory safety checks to detect buffer overflows.
    * Preconditions:
        - Ability to send video streams or image frames to the Azure Video Analyzer edge module.
        - Live pipeline configured to use the gRPC extension with YOLOv3 or Tiny YOLOv3.
        - IoT Edge device running the vulnerable gRPC extension module.
    * Source Code Analysis:
        - File: `/code/edge-modules/extensions/yolo/tinyyolov3/grpc-cpu/server/inference_engine.py`
        - Function: `GetCvImageFromRawBytes` uses `cv2.imdecode` on raw bytes without validation.
        ```python
        def GetCvImageFromRawBytes(self, clientState, mediaSample):
            try:
                # ...
                cvImage = cv2.imdecode(np.frombuffer(rawBytes, dtype=np.uint8), -1)
                # ...
                return cvImage
            except:
                PrintGetExceptionDetails()
                raise
        ```
        - Visualization:
        ```
        [Video Stream/Image Frame] --> gRPC Extension (inference_engine.py) --> GetCvImageFromRawBytes() --> cv2.imdecode() --> [Potential Buffer Overflow] --> RCE
        ```
    * Security Test Case:
        1. Deploy Azure Video Analyzer edge module and gRPC extension (YOLOv3 or Tiny YOLOv3).
        2. Configure a live pipeline using the gRPC extension.
        3. Obtain the endpoint to send video streams to the Azure Video Analyzer edge module.
        4. Prepare a maliciously crafted JPEG, PNG, or BMP image designed to trigger a buffer overflow in `cv2.imdecode`.
        5. Use a Python script or `grpc_cli` to send a gRPC request with a `MediaStreamMessage` containing the crafted image data.
        6. Monitor the IoT Edge device for crashes, restarts of the gRPC extension, or other signs of exploitation.
        7. Examine logs for errors from `cv2.imdecode` indicating a crash or memory corruption.

* Vulnerability Name: Insecure HTTP/gRPC Endpoints in Edge Modules
    * Description:
        1. Azure Video Analyzer edge module extensions (YOLO, Intel OpenVINO) expose HTTP and gRPC endpoints for video frame processing.
        2. Endpoints like `/score` (HTTP) and `ProcessMediaStream` (gRPC) lack authentication or authorization.
        3. Attackers with network access can send HTTP POST or gRPC requests to these endpoints without credentials.
        4. By sending crafted requests, attackers can trigger inference processing and receive results without authorization.
    * Impact:
        - Unauthorized access to video analytics processing for malicious purposes.
        - Manipulation of video analytics pipeline by injecting malicious video frames, leading to incorrect analytics data.
        - Potential access to video streams in extensions with streaming features.
        - Compromised data integrity of the video analytics system.
    * Vulnerability Rank: Medium
    * Currently Implemented Mitigations:
        - None. Edge module code and configurations lack authentication mechanisms for HTTP and gRPC endpoints.
    * Missing Mitigations:
        - Implement authentication and authorization for all exposed HTTP and gRPC endpoints.
        - Consider API keys, token-based authentication (JWT), or Azure Active Directory integration for access control.
        - Enforce mutual TLS (mTLS) for gRPC endpoints for secure communication.
    * Preconditions:
        - Network connectivity to the IoT Edge device hosting the vulnerable Azure Video Analyzer edge module extension.
        - Deployed and running vulnerable edge module extension (YOLO HTTP/gRPC, Intel OVMS/DL Streamer) with exposed HTTP or gRPC endpoints.
    * Source Code Analysis:
        - **HTTP Endpoints (e.g., `edge-modules/extensions/yolo/tinyyolov3/http-cpu/app/yolov3-app.py`):** Flask routes like `/score` lack authentication decorators.
        ```python
        @app.route("/score", methods=['POST'])
        def score():
            # ... processing logic ...
            return Response(respBody, status= 200, mimetype ='application/json')
        ```
        - **gRPC Endpoints (e.g., `edge-modules/extensions/yolo/tinyyolov3/grpc-cpu/server/server.py`):** `ProcessMediaStream` methods in gRPC servers lack authentication checks.
        ```python
        class InferenceEngine(extension_pb2_grpc.MediaGraphExtensionServicer):
            def ProcessMediaStream(self, requestIterator, context):
                # ... processing logic ...
                yield mediaStreamMessage
        ```
        - Dockerfiles and deployment manifests do not include authentication setup.
    * Security Test Case:
        1. Deploy `avaextension:http-yolov3-tiny-onnx-v1.0` Docker image as `yolo-http-extension` on an IoT Edge device, mapping host port `8080` to container port `80`.
        2. Determine the IoT Edge device IP address.
        3. Prepare a JPEG image file (`test_image.jpg`).
        4. Send an unauthenticated request using `curl`:
        ```bash
        curl -X POST http://192.168.1.100:8080/score -H "Content-Type: image/jpeg" --data-binary @test_image.jpg
        ```
        5. Verify the JSON response containing inference results, indicating successful unauthenticated access.

* Vulnerability Name: Exposed MJPEG Stream without Authentication
    * Description:
        1. The NVIDIA DeepStream extension module exposes an MJPEG stream of processed video via HTTP endpoints `/stream/<id>` and `/mjpeg/<id>`.
        2. These endpoints, intended for visualizing DeepStream pipeline output, lack authentication or access control.
        3. Attackers accessing the exposed port (default 8080) can view the live MJPEG video stream without credentials.
        4. Access is achieved by navigating to URLs like `http://<IP_ADDRESS>:8080/stream/<stream_id>`.
        5. This issue stems from example code directly exposing the stream without authentication.
    * Impact:
        - Unauthorized access to live video streams processed by the DeepStream extension.
        - Privacy violation by exposing camera feeds to unauthorized individuals.
        - Potential data leakage if the video stream contains sensitive information.
        - Unauthorised monitoring of activities captured by video stream.
    * Vulnerability Rank: High
    * Currently Implemented Mitigations:
        - None. Code examples lack authentication for MJPEG stream endpoints.
    * Missing Mitigations:
        - Implement authentication and authorization for MJPEG stream endpoints (e.g., HTTP basic authentication in `grpc_app.py`).
        - Configure network-level access controls (firewall rules, network segmentation) to restrict access to authorized networks/IPs.
        - Document the lack of authentication and recommend security measures for production deployments.
    * Preconditions:
        - DeepStream extension module (`avaextension`) deployed as IoT Edge module.
        - `MJPEG_OUTPUT` environment variable set to `1` in deployment manifest.
        - Port 80 (container port) of `avaextension` exposed and accessible.
        - Attacker knows/guesses IP address and stream ID.
    * Source Code Analysis:
        - File: `/code/edge-modules/extensions/nvidia/deepstream/app/nginx/grpc_app.py`
        - Flask route `/stream/<id>` directly serves MJPEG stream without authentication.
        ```python
        @app.route('/stream/<id>')
        def stream(id):
            respBody = ("<html>"
                        "<h1>MJPEG stream</h1>"
                        "<img src=\"/mjpeg/" + id + "\"/>"
                        "</html>")
            return Response(respBody, status= 200)
        ```
        - Dockerfile exposes port 80, making HTTP endpoints accessible.
    * Security Test Case:
        1. Deploy `avaextension` module (NVIDIA DeepStream extension) with MJPEG output enabled and port 80 exposed.
        2. Ensure IoT Edge device and `avaextension` module are running.
        3. Obtain IoT Edge device IP address (`<TARGET_IP>`).
        4. Determine stream ID (e.g., "SampleGraph1").
        5. Open browser and navigate to `http://<TARGET_IP>:8080/stream/SampleGraph1`.
        6. Observe live MJPEG video stream displayed without authentication.
        7. Repeat with `http://<TARGET_IP>:8080/mjpeg/SampleGraph1`.
        8. Use `curl` or `wget` to access `http://<TARGET_IP>:8080/mjpeg/SampleGraph1` and verify stream download without authentication.