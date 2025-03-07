### Vulnerability List

- Vulnerability Name: Command Injection via YouTube URL in VideoSource

- Description:
    1. An attacker can control the `VideoSource` configuration of the YoloModule by modifying the module twin or environment variable `VIDEO_PATH`.
    2. When the `VideoSource` is set to a YouTube URL (a URL containing `www.youtube.com` or `youtu.be`), the `downloadVideo` function in `/code/modules/YoloModule/app/VideoCapture.py` is triggered.
    3. The `downloadVideo` function constructs a command string by concatenating `"youtube-dl -o /app/video.mp4 -f mp4 "` with the provided `videoUrl`.
    4. This command string is then executed using `os.system()`.
    5. If an attacker injects shell metacharacters within the YouTube URL, these characters will be interpreted by the shell during command execution, leading to command injection.
    6. For example, a malicious `VideoSource` URL could be crafted as: `https://www.youtube.com/watch?v=XYZ;$(malicious_command)`.

- Impact:
    - Remote Code Execution: Successful exploitation of this vulnerability allows an attacker to execute arbitrary commands on the underlying Jetson Nano device.
    - System Compromise: This can lead to a full system compromise, enabling attackers to perform various malicious activities such as:
        - Data exfiltration: Stealing sensitive data from the device.
        - Malware installation: Installing persistent malware for long-term control.
        - Denial of Service (DoS): Disrupting the normal operation of the device or network.
        - Lateral movement: Using the compromised device as a stepping stone to attack other systems in the network.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - None: The code directly uses `os.system` to execute the `youtube-dl` command without any input sanitization or validation of the `VideoSource` URL.

- Missing Mitigations:
    - Input Sanitization and Validation: Implement robust input sanitization and validation for the `VideoSource` URL, specifically when it's identified as a YouTube URL. This should include stripping or escaping shell metacharacters before passing the URL to `os.system`.
    - Use `subprocess` with Argument Escaping: Replace `os.system` with Python's `subprocess` module, using argument lists instead of shell strings. This allows for proper escaping of arguments and prevents shell injection. For example, use `subprocess.run(['youtube-dl', '-o', '/app/video.mp4', '-f', 'mp4', videoUrl])`.
    - Use a Python YouTube Library: Consider using a dedicated Python library for interacting with YouTube APIs (like `pytube`). This would eliminate the need to rely on external command-line tools like `youtube-dl` and reduce the risk of command injection.

- Preconditions:
    - Access to Module Twin or Environment Variables: The attacker must have the ability to modify the YoloModule's configuration, either through updating the module twin in Azure IoT Hub or by setting the `VIDEO_PATH` environment variable if exposed.
    - Network Connectivity: The Jetson Nano device must have internet connectivity to download the malicious YouTube URL and potentially for the attacker to receive command execution results.

- Source Code Analysis:
    - File: `/code/modules/YoloModule/app/VideoCapture.py`
    - Function: `downloadVideo(self, videoUrl)`
    ```python
    def downloadVideo(self, videoUrl):
        if self.captureInProgress:
            bRestartCapture = True
            time.sleep(1.0)
            if self.vCapture:
                print("Relase vCapture")
                self.vCapture.release()
                self.vCapture = None
        else:
            bRestartCapture = False

        if os.path.isfile('/app/video.mp4'):
            os.remove("/app/video.mp4")

        print("Start downloading video")
        os.system("youtube-dl -o /app/video.mp4 -f mp4 " + videoUrl) # Vulnerable line
        print("Download Complete")
        self.vCapture = cv2.VideoCapture("/app/video.mp4")
        time.sleep(1.0)
        self.frameCount = int(self.vCapture.get(cv2.CAP_PROP_FRAME_COUNT))

        if bRestartCapture:
            self.captureInProgress = True
    ```
    - Visualization:
        ```mermaid
        graph LR
            A[Module Twin Update/Environment Variable] --> B(device_twin_callback in main.py)
            B --> C(setVideoSource in VideoCapture.py)
            C -- YouTube URL --> D(downloadVideo in VideoCapture.py)
            D --> E[os.system("youtube-dl ... " + videoUrl)]
            E -- Command Injection --> F[Jetson Nano System]
        ```
    - The `downloadVideo` function is called when `setVideoSource` detects a YouTube URL.
    - Inside `downloadVideo`, `os.system` is used to execute the `youtube-dl` command.
    - The `videoUrl` variable, directly derived from the potentially attacker-controlled `VideoSource` configuration, is concatenated into the command string without any sanitization.
    - This allows an attacker to inject arbitrary shell commands by crafting a malicious YouTube URL.

- Security Test Case:
    1. Prerequisites:
        - Deploy the IntelligentEdgeHOL project and YoloModule to a Jetson Nano device connected to Azure IoT Hub.
        - Ensure you have permissions to modify the module twin of the deployed YoloModule in the Azure portal or using Azure CLI.
        - Have a method to access the Jetson Nano device's filesystem (e.g., SSH access or Azure IoT Edge direct methods to execute commands like `ls` and check for file creation).
    2. Steps:
        - Open the Azure portal and navigate to your IoT Hub.
        - Find your deployed IoT Edge device and then locate the `YoloModule` module twin.
        - Modify the `properties.desired.VideoSource` property in the module twin to the following malicious URL: `https://www.youtube.com/watch?v=xxxxxxxxxx;touch /tmp/pwned_by_youtube_url_injection`. Replace `xxxxxxxxxx` with any valid YouTube video ID to maintain the URL structure.
        - Update the module twin. This will trigger the `device_twin_callback` and subsequently the `downloadVideo` function on the YoloModule.
        - Wait for a few minutes to allow the module to process the twin update and attempt to download the video.
        - Access the Jetson Nano device via SSH or use Azure IoT Edge direct methods to execute the command `ls /tmp/pwned_by_youtube_url_injection`.
        - Verification:
            - If the command `ls /tmp/pwned_by_youtube_url_injection` shows the file `/tmp/pwned_by_youtube_url_injection` exists, it confirms that the `touch /tmp/pwned_by_youtube_url_injection` command injected via the malicious YouTube URL was successfully executed.
            - This demonstrates a successful command injection vulnerability.