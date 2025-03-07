### Vulnerability List

- Vulnerability Name: Unvalidated Video Input Path

- Description:
    1. The Agamotto application reads the video input location (either a video file path or a stream URL) directly from the `agamotto.yaml` configuration file, specifically the `video.input_location` parameter.
    2. The `agamotto.process_media` function in `/code/agamotto/agamotto/agamotto.py` uses this unvalidated path directly in `cv2.VideoCapture()` without any sanitization or validation.
    3. If an attacker can modify the `agamotto.yaml` file or control the input to the `process_media` function, they can supply a malicious video path or stream URL.
    4. By providing a path to a crafted video file or stream, the attacker can inject manipulated video frames into the Agamotto processing pipeline.
    5. This allows the attacker to control the person count detected by Agamotto, artificially inflating or deflating the reported numbers.
    6. For example, an attacker could replace the legitimate video input with a pre-recorded video that always shows a high number of people, regardless of the actual occupancy of the monitored location.

- Impact:
    - **Data Manipulation:** Attackers can manipulate the person count data collected by Agamotto.
    - **Misleading Marketing Insights:** Skewed person count data leads to inaccurate marketing campaign analysis and potentially flawed business decisions based on this data.
    - **Reputational Damage:** If the manipulation is discovered, it can damage the credibility of the marketing insights and the Agamotto system itself.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None. The application directly uses the input path from the configuration without any validation.

- Missing Mitigations:
    - **Input Validation and Sanitization:** Implement validation to ensure that the video input path is from an expected and trusted source. For file paths, verify the file extension and possibly the file's integrity (e.g., using checksums if applicable). For stream URLs, implement a whitelist of allowed domains or protocols.
    - **Access Control for Configuration Files:** Restrict access to the `agamotto.yaml` configuration file to prevent unauthorized modification. Ensure that only authorized personnel can modify the configuration.
    - **Principle of Least Privilege:** Run the Agamotto application with minimal necessary privileges to limit the impact of potential exploits.

- Preconditions:
    - The attacker needs to be able to modify the `agamotto.yaml` configuration file or control the input to the `process_media` function.  For an external attacker this might be possible through exploiting other vulnerabilities that allow file modification or influencing configuration through exposed APIs (if any were added later and are not in provided files). For now, assuming direct access to configuration file is the most straightforward precondition within the scope of provided files.

- Source Code Analysis:
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

- Security Test Case:
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

This test case demonstrates how an attacker, by controlling the `video.input_location` in `agamotto.yaml`, can manipulate the video input and thus the person count reported by Agamotto.