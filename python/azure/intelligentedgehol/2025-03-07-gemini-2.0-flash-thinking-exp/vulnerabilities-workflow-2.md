## Combined Vulnerability Report

The following vulnerabilities were identified after reviewing the provided vulnerability lists. Duplicate entries have been merged, and vulnerabilities that do not meet the specified criteria (e.g., low severity, not realistic, incomplete descriptions) have been excluded.

### 1. Server-Side Request Forgery (SSRF) via VideoSource

- **Description:**
  1. An attacker with control over the IoT Hub can modify the `VideoSource` module twin property of the `YoloModule`.
  2. The `device_twin_callback` function in `/code/modules/YoloModule/app/main.py` receives the updated twin properties and extracts the new `VideoSource` URL.
  3. The `setVideoSource` function in `/code/modules/YoloModule/app/VideoCapture.py` is then called with this attacker-controlled URL.
  4. If the attacker sets the `VideoSource` to point to an internal resource (e.g., `http://internal-network-resource`), the `VideoCapture` module running on the IoT Edge device will attempt to access this internal resource.
  5. This can lead to Server-Side Request Forgery (SSRF), potentially granting unauthorized access to internal services or data from the IoT Edge device's network.

- **Impact:**
  - Unauthorized access to internal network resources.
  - Potential information disclosure from internal services.
  - Possible further exploitation depending on the nature of the internal services, such as accessing APIs or databases behind a firewall.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
  - None. The application directly uses the provided `VideoSource` URL without any validation or sanitization.

- **Missing Mitigations:**
  - Input validation and sanitization of the `VideoSource` URL within the `device_twin_callback` function in `/code/modules/YoloModule/app/main.py` or within the `setVideoSource` method in `/code/modules/YoloModule/app/VideoCapture.py`.
  - Implementing a whitelist of allowed protocols (e.g., `https`, `rtsp`) and potentially a domain whitelist for external video sources.
  - Network segmentation to isolate the IoT Edge device and limit the potential impact of SSRF by restricting access to sensitive internal resources.
  - Role-Based Access Control (RBAC) in Azure IoT Hub to restrict who can modify module twin properties, reducing the attack surface.

- **Preconditions:**
  - The attacker must have sufficient permissions to modify module twin properties in the Azure IoT Hub associated with the deployed IoT Edge device.
  - The IoT Edge device must be deployed in a network environment where internal resources are accessible from the device's network.

- **Source Code Analysis:**
  1. `/code/modules/YoloModule/app/main.py`:
     - The `device_twin_callback` function extracts the `VideoSource` property from the module twin and passes it to `videoCapture.setVideoSource()` without validation:
       ```python
       if "VideoSource" in jsonData:
           strUrl = str(jsonData['VideoSource'])
           print("   - VideoSource     : " + strUrl)
           if strUrl.lower() != videoCapture.videoPath.lower() and strUrl != "":
               videoCapture.setVideoSource(strUrl)
       ```

  2. `/code/modules/YoloModule/app/VideoCapture.py`:
     - The `setVideoSource` method uses the provided `newVideoPath` directly without hostname or IP address validation, leading to potential SSRF when accessing the URL:
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

- **Security Test Case:**
  1. **Prerequisites:** Deploy `YoloModule` to an Azure IoT Edge device in a network with an internal HTTP service (e.g., `http://internal-service:8080`). Have permissions to update module twin properties.
  2. **Steps:**
     - In Azure portal, navigate to your IoT Hub and the `YoloModule` module twin.
     - Modify the `VideoSource` property in `desired` properties to `"http://internal-service:8080"`.
     - Update the module twin.
     - Monitor `YoloModule` logs (`sudo docker logs -f YoloModule`) and internal HTTP service logs.
  3. **Expected Result:** Observe HTTP requests from the IoT Edge device's IP in the internal service logs, confirming SSRF.

### 2. Path Traversal in Static File Serving

- **Description:**
  1. The YoloModule uses Tornado to serve static files from the `/code/modules/YoloModule/app/templates` directory.
  2. An attacker can craft URLs with path traversal sequences (e.g., `..`) to access files outside the intended directory.
  3. By sending malicious HTTP requests, an attacker can potentially read sensitive files from the Jetson Nano device, such as configuration files or module code.

- **Impact:**
  - **Information Disclosure:** Reading sensitive files like configuration files, credentials, or source code.
  - **Privilege Escalation (potential):** If exposed files contain sensitive information, it could lead to further exploitation.
  - **Loss of Confidentiality:** Compromising the security of the IoT Edge device and IoT solution.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
  - None: The project relies on Tornado's default `StaticFileHandler` protections, which may be insufficient.

- **Missing Mitigations:**
  - Input validation and sanitization to prevent path traversal sequences in requested file paths.
  - Restricting the static file serving directory to only necessary files, excluding sensitive directories.
  - Consider using a Web Application Firewall (WAF) to detect and block path traversal attempts.
  - Regular security audits and penetration testing.

- **Preconditions:**
  - YoloModule deployed and running on a Jetson Nano device.
  - Web server exposed by YoloModule (port 80 or configured port) accessible to the attacker.
  - Attacker knows or guesses the Jetson Nano device's IP address or hostname.

- **Source Code Analysis:**
  - File: `/code/modules/YoloModule/app/ImageServer.py`
  ```python
  indexPath = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'templates')
  app = tornado.web.Application([
      (r"/stream", ImageStreamHandler, {'videoCapture': self.videoCapture}),
      (r"/(.*)", tornado.web.StaticFileHandler, {'path': indexPath, 'default_filename': 'index.html'})
  ])
  ```
  - `tornado.web.StaticFileHandler` serves files from `indexPath` (templates directory).
  - The path pattern `r"/(.*)"` captures any path, potentially allowing traversal outside the intended directory.

- **Security Test Case:**
  1. Deploy YoloModule and ensure the web server is accessible (e.g., `http://<jetson-nano-ip>`).
  2. Craft a URL: `http://<jetson-nano-ip>/../../../../../etc/passwd`.
  3. Send the URL and check the server response.
  4. **Expected Vulnerable Behavior:** Server responds with `/etc/passwd` content, indicating path traversal.
  5. Test with other sensitive paths like `/../../../../../code/modules/YoloModule/app/main.py`.

### 3. Command Injection via YouTube URL in VideoSource

- **Description:**
  1. An attacker controls the `VideoSource` configuration (module twin or environment variable).
  2. When `VideoSource` is a YouTube URL, `downloadVideo` function in `/code/modules/YoloModule/app/VideoCapture.py` is triggered.
  3. `downloadVideo` constructs a command string: `"youtube-dl -o /app/video.mp4 -f mp4 " + videoUrl`.
  4. This command is executed using `os.system()`.
  5. Injecting shell metacharacters in the YouTube URL leads to command injection.

- **Impact:**
  - **Remote Code Execution:** Arbitrary commands on the Jetson Nano device.
  - **System Compromise:** Full system control, data exfiltration, malware installation, DoS, lateral movement.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
  - None: `os.system` is used without input sanitization.

- **Missing Mitigations:**
  - Input sanitization and validation for `VideoSource` URLs, especially YouTube URLs.
  - Replace `os.system` with `subprocess` using argument lists for safe command execution.
  - Consider using a Python YouTube library to avoid external command-line tools.

- **Preconditions:**
  - Attacker can modify YoloModule's configuration (module twin or `VIDEO_PATH` environment variable).
  - Jetson Nano device has internet connectivity.

- **Source Code Analysis:**
  - File: `/code/modules/YoloModule/app/VideoCapture.py`
  - Function: `downloadVideo(self, videoUrl)`
  ```python
  def downloadVideo(self, videoUrl):
      # ...
      print("Start downloading video")
      os.system("youtube-dl -o /app/video.mp4 -f mp4 " + videoUrl) # Vulnerable line
      # ...
  ```
  - `os.system` executes `youtube-dl` with the unsanitized `videoUrl`, enabling command injection.

- **Security Test Case:**
  1. **Prerequisites:** Deploy YoloModule, have Azure IoT Hub access to modify module twin, and access to Jetson Nano filesystem (SSH or direct methods).
  2. **Steps:**
     - In Azure portal, modify `YoloModule` twin's `properties.desired.VideoSource` to: `"https://www.youtube.com/watch?v=xxxxxxxxxx;touch /tmp/pwned_by_youtube_url_injection"`.
     - Update module twin.
     - Access Jetson Nano via SSH and run `ls /tmp/pwned_by_youtube_url_injection`.
  3. **Verification:** If `/tmp/pwned_by_youtube_url_injection` exists, command injection is confirmed.