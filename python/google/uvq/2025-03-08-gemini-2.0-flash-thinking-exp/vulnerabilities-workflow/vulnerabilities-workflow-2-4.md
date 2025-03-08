### Vulnerability List

- Vulnerability Name: Command Injection via Filename in FFmpeg Command
- Description: The application is vulnerable to command injection because it directly incorporates user-provided input, specifically the video filepath, into an FFmpeg command executed by the system shell. This occurs in the `utils/video_reader.py` file within the `VideoReader.load_video` function. An attacker can exploit this by crafting a malicious video filename that includes shell commands. When the application processes this filename, the embedded commands will be executed by the shell, leading to arbitrary command execution on the server.

  Step-by-step trigger:
    1. The user provides input to `uvq_main.py` using the `--input_files` flag. This input is expected to be in the format "video_id,video_length,filepath".
    2. The `uvq_main.py` script parses this input, extracting the `filepath`.
    3. The `filepath` is passed to the `utils.generate_features` function.
    4. Inside `generate_features`, the `filepath` is passed to `video_reader.VideoReader.load_video`.
    5. In `load_video`, the `filepath` is directly embedded into an FFmpeg command string using `%s` formatting without any sanitization.
    6. This command string is then executed using `subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True)`. The `shell=True` argument is crucial as it allows shell command injection.
    7. If the `filepath` contains shell metacharacters (e.g., `;`, `|`, `&`, `$`, `` ` ``), these will be interpreted and executed by the shell.

- Impact: Arbitrary command execution. An attacker can execute arbitrary commands on the server running the UVQ model. This can lead to complete system compromise, data theft, malware installation, or denial of service.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations: None. The code directly uses user-provided input in a shell command without any sanitization or validation.
- Missing Mitigations:
    - Input sanitization: The `filepath` from user input should be sanitized to remove or escape shell metacharacters before being used in the FFmpeg command.
    - Secure command execution: Instead of using `shell=True` in `subprocess.check_output`, which is known to be dangerous when dealing with unsanitized input, the command should be executed directly as a list of arguments without shell interpretation. If passing the filename to ffmpeg requires shell interpretation, consider using safer alternatives like passing the file via stdin or using a more secure library for interacting with system commands.
- Preconditions:
    - The attacker must be able to control the `--input_files` parameter of the `uvq_main.py` script. This is typically the case for an external attacker who can provide input to the application.
    - FFmpeg must be installed and available in the system's PATH, as required by the application's dependencies.

- Source Code Analysis:
    - File: `/code/utils/video_reader.py`
    - Function: `VideoReader.load_video(filepath, video_length, transpose=False)`

    ```python
    def load_video(filepath, video_length, transpose=False):
        # ...
        cmd = (
            "ffmpeg  -i %s -filter_complex "
            ' "[0:v]%sscale=w=%d:h=%d:flags=bicubic:force_original_aspect_ratio=1,'
            'pad=%d:%d:(ow-iw)/2:(oh-ih)/2,format=rgb24,split=2[out1][tmp],[tmp]scale=%d:%d:flags=bilinear[out2]"'
            " -map [out1] -r %d -f rawvideo -pix_fmt rgb24 -y %s"
            " -map [out2] -r %d -f rawvideo -pix_fmt rgb24 -y %s"
        ) % (
            filepath,
            transpose_param,
            VIDEO_WIDTH,
            VIDEO_HEIGHT,
            VIDEO_WIDTH,
            VIDEO_HEIGHT,
            INPUT_WIDTH_CONTENT,
            INPUT_HEIGHT_CONTENT,
            VIDEO_FPS,
            temp_filename,
            VIDEO_FPS,
            temp_filename_small,
        )

        try:
            logging.info("Run with cmd:% s\n", cmd)
            subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True) # Vulnerable line
        except subprocess.CalledProcessError as error:
            # ...
    ```
    - Visualization:
      ```
      User Input (--input_files) --> uvq_main.py --> utils.generate_features --> video_reader.VideoReader.load_video --> filepath variable --> FFmpeg command string (unsanitized) --> subprocess.check_output(shell=True) --> Command Execution
      ```
    - The code snippet shows that the `filepath` variable, directly derived from user input, is formatted into the `cmd` string and then executed using `subprocess.check_output` with `shell=True`. This `shell=True` argument makes the system vulnerable to command injection if the `filepath` is not properly sanitized.

- Security Test Case:
    1. Create a file named `test.mp4; touch /tmp/uvq_pwned`. This filename contains a shell command `; touch /tmp/uvq_pwned` which will create an empty file named `uvq_pwned` in the `/tmp/` directory when executed by the shell.
    2. Run the `uvq_main.py` script with the crafted filename as input:
       ```bash
       python3 uvq_main.py --input_files="malicious_video,20,'test.mp4; touch /tmp/uvq_pwned'" --output_dir results --model_dir models
       ```
       Note: The filename is quoted to be passed as a single argument to the shell.
    3. After running the command, check if the file `/tmp/uvq_pwned` exists. You can use the following command in the terminal:
       ```bash
       ls /tmp/uvq_pwned
       ```
    4. If the file `/tmp/uvq_pwned` exists, it confirms that the `touch /tmp/uvq_pwned` command embedded in the filename was executed, demonstrating successful command injection.