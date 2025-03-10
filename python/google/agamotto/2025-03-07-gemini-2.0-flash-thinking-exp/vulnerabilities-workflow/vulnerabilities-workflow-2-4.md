- Vulnerability name: OpenCV Memory Corruption Vulnerability via Malicious Video Stream
- Description:
    - The Agamotto application utilizes OpenCV to process video streams and files for person counting.
    - By providing a maliciously crafted video stream or video file as input, an attacker can exploit potential memory corruption vulnerabilities within OpenCV's video decoding or processing functions.
    - This can be achieved by manipulating the `input_location` parameter in the `agamotto.yaml` configuration file to point to a malicious video source.
    - When Agamotto processes this malicious video through OpenCV, it may trigger a memory corruption vulnerability due to flaws in OpenCV's handling of specific video codecs, container formats, or malformed video data.
- Impact:
    - Remote Code Execution (RCE).
    - Successful exploitation could allow an attacker to execute arbitrary code on the system running the Agamotto application.
    - This could lead to a complete compromise of the system, including data theft, malware installation, or denial of service.
- Vulnerability rank: Critical
- Currently implemented mitigations:
    - None. The code directly uses OpenCV to process video input without any explicit input validation or security measures.
- Missing mitigations:
    - Input validation and sanitization for video streams and files to ensure they conform to expected formats and do not contain malicious payloads.
    - Sandboxing the video processing: Running the OpenCV video processing in a sandboxed environment to limit the impact of a potential exploit.
    - Regular updates of OpenCV: Keeping the OpenCV library updated to the latest version to patch known vulnerabilities.
    - Memory safety measures: Employing memory safety techniques and compiler flags during the build process to mitigate memory corruption issues.
- Preconditions:
    - The Agamotto application must be deployed and running.
    - The attacker must be able to provide a malicious video stream URL or video file path to the application. This could be achieved by:
        - Modifying the `agamotto.yaml` configuration file if the attacker has write access to it (less likely for an external attacker).
        - Providing a malicious URL if the application is configured to process a stream from a user-provided URL (not directly supported in the provided configuration, but a potential future feature or misconfiguration).
        - Tricking an administrator into placing a malicious video file in a location that the application processes.
- Source code analysis:
    - `agamotto/agamotto/agamotto.py`:
        - `process_media(self, path)` function is responsible for selecting video processing method based on `self._video_is_stream`.
        - `process_stream(self, stream_path)` and `process_video(self, video_path)` functions use `cv2.VideoCapture()` to open the video source specified by `stream_path` and `video_path` respectively. These paths are directly derived from the configuration file (`agamotto.yaml`) under `video.input_location`.
        - No input validation or sanitization is performed on `stream_path` or `video_path` before passing them to `cv2.VideoCapture()`.
    - `stream/video.py`:
        - `Video.__init__(self)` initializes `self.video = cv2.VideoCapture(0)`. While this part handles the webcam stream for the `stream` service, the primary vulnerability vector targets the `agamotto` service processing external video sources defined in `agamotto.yaml`.
    - `agamotto/utils/read_from_yaml.py`:
        - `read_from_yaml(file_name = "agamotto.yaml")` function reads the configuration from `agamotto.yaml`. This configuration, including `video.input_location`, is directly used by `agamotto.py` without validation.

- Security test case:
    - **Setup:**
        - Deploy Agamotto using Docker as described in the `README.md`. Ensure the application is running.
        - Prepare a malicious video file that is designed to trigger a known vulnerability in OpenCV (e.g., a crafted MP4 or AVI file exploiting a parsing flaw). Tools like Medusa fuzzer or online resources for known OpenCV exploit samples can be used to obtain or create such a file.
    - **Configuration:**
        - Modify the `agamotto/agamotto/agamotto.yaml` file within the running Docker container or before building the Docker image.
        - Change the `video.is_stream` value to `False`.
        - Change the `video.input_location` value to the path where the malicious video file will be accessible within the container. For example, if you copy the malicious video file named `malicious.mp4` into the `/code/agamotto/` directory within the container, set `video.input_location: "malicious.mp4"`. You might need to use `docker cp` to copy the file into the container.
    - **Execution:**
        - Restart the `agamotto` container to apply the configuration changes.
        - Observe the behavior of the `agamotto` container.
    - **Verification:**
        - Check the Docker container logs for the `agamotto` service using `docker logs <agamotto_container_name>`.
        - Look for signs of a crash, error messages related to OpenCV, or unexpected program termination. A successful exploit might lead to a segmentation fault or other abnormal termination.
        - For more advanced verification, attempt to detect if remote code execution is possible. This would involve crafting a more sophisticated malicious video designed to execute specific commands upon exploitation and monitoring for those commands' effects (e.g., network connections to an attacker-controlled server, file creation, etc.).
        - If the application crashes or exhibits abnormal behavior when processing the malicious video, and this behavior is not observed with benign video files, it indicates a potential vulnerability.