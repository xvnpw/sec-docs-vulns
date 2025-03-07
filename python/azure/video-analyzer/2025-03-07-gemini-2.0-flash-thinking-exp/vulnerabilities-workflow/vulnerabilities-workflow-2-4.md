### Vulnerability List

- Vulnerability Name: Exposed MJPEG Stream without Authentication

- Description:
  - The NVIDIA DeepStream extension module is configured to expose an MJPEG stream of the processed video feed through HTTP endpoints.
  - Specifically, the application running inside the Docker container, `grpc_app.py`, sets up routes at `/stream/<id>` and `/mjpeg/<id>` that serve this MJPEG stream.
  - These endpoints are intended for visualizing the output of the DeepStream pipeline with inference overlays in a browser.
  - However, these endpoints lack any form of authentication or access control.
  - An attacker who can reach the exposed port (default 8080, mapped from container port 80) of the DeepStream extension module can access and view the live MJPEG video stream without any credentials.
  - This can be achieved by simply accessing the URL `http://<IP_ADDRESS>:8080/stream/<stream_id>` or `http://<IP_ADDRESS>:8080/mjpeg/<stream_id>` where `<IP_ADDRESS>` is the IP address of the device running the module and `<stream_id>` is the graph instance name.
  - This issue is present due to the example code directly exposing the stream without implementing any authentication mechanism.

- Impact:
  - Unauthorized access to live video streams processed by the DeepStream extension.
  - Potential privacy violation as video feeds from cameras are exposed to unauthorized individuals.
  - If the video stream contains sensitive information, it could lead to data leakage.
  - An attacker could monitor activities captured by the video stream.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
  - None. The provided code examples do not implement any authentication or access control for the MJPEG stream endpoints.

- Missing Mitigations:
  - Implement authentication and authorization mechanisms for accessing the MJPEG stream endpoints.
  - For example, basic HTTP authentication could be added to `grpc_app.py` to protect the `/stream/<id>` and `/mjpeg/<id>` routes.
  - Alternatively, network-level access controls (firewall rules, network segmentation) should be configured to restrict access to the MJPEG stream port to authorized networks or IP addresses only.
  - Documentation should clearly warn users about the lack of authentication and recommend implementing proper security measures when deploying these example extensions in production-like environments.

- Preconditions:
  - The DeepStream extension module (`avaextension`) must be deployed as an IoT Edge module.
  - The `MJPEG_OUTPUT` environment variable must be set to `1` in the deployment manifest for the `avaextension` module to enable MJPEG streaming.
  - Port 80 (container port) of the `avaextension` module must be exposed and accessible from the attacker's network (e.g., mapped to host port 8080 and firewall rules allowing access to port 8080).
  - The attacker needs to know or guess the IP address and the stream ID (which often corresponds to the graph instance name) to access the stream URL.

- Source Code Analysis:
  - File: `/code/edge-modules/extensions/nvidia/deepstream/app/nginx/grpc_app.py`
  - ```python
    from flask import Flask, request, jsonify, Response
    app = Flask(__name__)

    # ...

    @app.route('/stream/<id>')
    def stream(id):
        respBody = ("<html>"
                    "<h1>MJPEG stream</h1>"
                    "<img src=\"/mjpeg/" + id + "\"/>"
                    "</html>")
        return Response(respBody, status= 200)
    ```
  - The code snippet above shows the Flask route `/stream/<id>` defined in `grpc_app.py`.
  - This route directly serves an HTML page that embeds the MJPEG stream from `/mjpeg/<id>`.
  - There is no authentication or authorization check implemented in this function or in `grpc_app.py` to control access to this stream.
  - The MJPEG stream itself is served by nginx configuration, but the flask app makes it easily accessible without any checks.
  - File: `/code/edge-modules/extensions/nvidia/deepstream/docker/Dockerfile`
  - The Dockerfile exposes port 80 and maps it to host port 8080 in the example deployment manifest, making the HTTP endpoints accessible.

- Security Test Case:
  - Step 1: Deploy the `avaextension` module (NVIDIA DeepStream extension) to an IoT Edge device using the provided deployment manifest template (`deployment.deepstream.template.json`) or a similar configuration that enables MJPEG output (`MJPEG_OUTPUT=1`) and exposes port 80 (e.g., mapping container port 80 to host port 8080).
  - Step 2: Ensure the IoT Edge device is running and the `avaextension` module is in 'running' state.
  - Step 3: Obtain the IP address or hostname of the IoT Edge device where the `avaextension` module is deployed. Let's assume it's `<TARGET_IP>`.
  - Step 4: Determine the stream ID. In the provided example `operations.json` for testing DeepStream, the live pipeline name is "SampleGraph1". This name is often used as the stream ID. Let's assume the stream ID is `SampleGraph1`.
  - Step 5: Open a web browser and navigate to the URL `http://<TARGET_IP>:8080/stream/SampleGraph1`.
  - Step 6: Observe that the live MJPEG video stream with inference overlays is displayed in the browser without requiring any authentication.
  - Step 7: Repeat Step 5 with the URL `http://<TARGET_IP>:8080/mjpeg/SampleGraph1`.
  - Step 8: Observe that the live MJPEG video stream is also accessible through this URL without authentication.
  - Step 9: Use `curl` or `wget` to access the stream directly: `curl http://<TARGET_IP>:8080/mjpeg/SampleGraph1 > stream.mjpeg` or `wget http://<TARGET_IP>:8080/mjpeg/SampleGraph1 -O stream.mjpeg`. Verify that the MJPEG stream can be downloaded and viewed using a media player capable of playing MJPEG streams, again without any authentication.

This test case confirms that the MJPEG stream is indeed exposed without authentication, validating the vulnerability.