### Vulnerability List

- Vulnerability Name: Server-Side Request Forgery (SSRF) via VideoSource

- Description:
  1. An attacker with control over the IoT Hub can modify the `VideoSource` module twin property of the `YoloModule`.
  2. The `device_twin_callback` function in `/code/modules/YoloModule/app/main.py` receives the updated twin properties and extracts the new `VideoSource` URL.
  3. The `setVideoSource` function in `/code/modules/YoloModule/app/VideoCapture.py` is then called with this attacker-controlled URL.
  4. If the attacker sets the `VideoSource` to point to an internal resource (e.g., `http://internal-network-resource`), the `VideoCapture` module running on the IoT Edge device will attempt to access this internal resource.
  5. This can lead to Server-Side Request Forgery (SSRF), potentially granting unauthorized access to internal services or data from the IoT Edge device's network.

- Impact:
  - Unauthorized access to internal network resources.
  - Potential information disclosure from internal services.
  - Possible further exploitation depending on the nature of the internal services, such as accessing APIs or databases behind a firewall.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
  - None. The application directly uses the provided `VideoSource` URL without any validation or sanitization.

- Missing Mitigations:
  - Input validation and sanitization of the `VideoSource` URL within the `device_twin_callback` function in `/code/modules/YoloModule/app/main.py` or within the `setVideoSource` method in `/code/modules/YoloModule/app/VideoCapture.py`.
  - Implementing a whitelist of allowed protocols (e.g., `https`, `rtsp`) and potentially a domain whitelist for external video sources.
  - Network segmentation to isolate the IoT Edge device and limit the potential impact of SSRF by restricting access to sensitive internal resources.
  - Role-Based Access Control (RBAC) in Azure IoT Hub to restrict who can modify module twin properties, reducing the attack surface.

- Preconditions:
  - The attacker must have sufficient permissions to modify module twin properties in the Azure IoT Hub associated with the deployed IoT Edge device.
  - The IoT Edge device must be deployed in a network environment where internal resources are accessible from the device's network.

- Source Code Analysis:
  1. `/code/modules/YoloModule/app/main.py`:
     - The `device_twin_callback` function is defined to handle updates to the module twin.
     - Inside this function, the `VideoSource` property is extracted from the `desired` properties payload:
       ```python
       if "VideoSource" in jsonData:
           strUrl = str(jsonData['VideoSource'])
           print("   - VideoSource     : " + strUrl)
           if strUrl.lower() != videoCapture.videoPath.lower() and strUrl != "":
               videoCapture.setVideoSource(strUrl)
       ```
     - **Vulnerability:** The code directly takes the `strUrl` from the module twin and passes it to `videoCapture.setVideoSource()` without any validation or sanitization. This allows an attacker to inject any URL, including URLs pointing to internal network resources.

  2. `/code/modules/YoloModule/app/VideoCapture.py`:
     - The `setVideoSource` method in the `VideoCapture` class is responsible for setting up the video source based on the provided `newVideoPath`.
     - The method checks the protocol of the `newVideoPath` using `__IsRtsp`, `__IsYoutube`, and `__IsCaptureDev` to determine the source type, but does not validate the hostname or IP address.
     - For each source type (RTSP, YouTube, Webcam), it proceeds to initialize the video capture or streaming using the provided `newVideoPath` without further validation:
       ```python
       def setVideoSource(self, newVideoPath):
           ...
           if self.__IsRtsp(newVideoPath):
               ...
               self.vStream = VideoStream(newVideoPath).start()
               ...
           elif self.__IsYoutube(newVideoPath):
               ...
               self.downloadVideo(newVideoPath)
               ...
           elif self.__IsCaptureDev(newVideoPath):
               ...
               self.vCapture = cv2.VideoCapture(newVideoPath)
               ...
       ```
     - **Vulnerability:** The `setVideoSource` method blindly trusts the `newVideoPath` and uses it directly in functions that can initiate network requests (e.g., `VideoStream`, `youtube-dl` in `downloadVideo`, and potentially `cv2.VideoCapture` depending on the path).

- Security Test Case:
  1. **Prerequisites:**
     - Deploy the `IntelligentEdgeHOL` module to an Azure IoT Edge device within a network that contains an internal HTTP service (e.g., a simple web server listening on port 8080 at `http://internal-service:8080`).
     - Ensure you have credentials with permissions to update module twin properties in the Azure IoT Hub connected to the IoT Edge device.
  2. **Steps:**
     - Open the Azure portal and navigate to your IoT Hub.
     - Locate your IoT Edge device and then find the `YoloModule` module under the modules section.
     - Open the module twin properties for `YoloModule`.
     - Modify the `VideoSource` property in the `desired` properties section to point to the internal HTTP service:
       ```json
       {
         "properties": {
           "desired": {
             "VideoSource": "http://internal-service:8080"
           }
         }
       }
       ```
     - Update the module twin.
     - Monitor the logs of the `YoloModule` on the IoT Edge device using `sudo docker logs -f YoloModule`.
     - Simultaneously, monitor the access logs of the internal HTTP service at `http://internal-service:8080`.
  3. **Expected Result:**
     - In the logs of the internal HTTP service, you should observe HTTP requests originating from the IP address of the IoT Edge device. These requests indicate that the `YoloModule` is attempting to access the internal service as instructed by the modified `VideoSource` property.
     - In the `YoloModule` logs, you may see errors related to video processing or failure to open the video source, as `http://internal-service:8080` is not a valid video stream but a web server.
  4. **Conclusion:**
     - The successful observation of requests to the internal HTTP service from the IoT Edge device confirms the Server-Side Request Forgery vulnerability. The `YoloModule` blindly accepts the `VideoSource` URL from the module twin, allowing an attacker to force the module to make requests to internal resources.