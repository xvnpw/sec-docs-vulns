- Vulnerability name: Command Injection via `filepath` parameter in FFmpeg call

- Description:
    1. The application processes video files using FFmpeg, a command-line video processing tool.
    2. The `uvq_main.py` script takes user input through the `--input_files` flag, which includes the `filepath` to the video file.
    3. This `filepath` is passed to the `load_video` function in `uvq_utils.py` and then to `VideoReader.load_video` in `video_reader.py`.
    4. Inside `VideoReader.load_video`, the `filepath` is directly embedded into an FFmpeg command string using Python's `%` string formatting.
    5. This command string is then executed using `subprocess.check_output` with `shell=True`.
    6. By crafting a malicious `filepath` that includes shell commands, an attacker can inject arbitrary commands into the FFmpeg call.
    7. When `subprocess.check_output` executes this command with `shell=True`, the injected commands will be executed on the server.

- Impact:
    - An attacker can achieve Remote Code Execution (RCE) on the server.
    - This can lead to complete system compromise, including data theft, malware installation, and denial of service.
    - The attacker can gain full control over the server and potentially pivot to other systems in the network.

- Vulnerability rank: Critical

- Currently implemented mitigations:
    - None. The code directly uses user-provided file paths in a shell command without any sanitization or validation.

- Missing mitigations:
    - Input sanitization: The `filepath` should be carefully sanitized to remove or escape any characters that could be interpreted as shell commands.
    - Parameterized commands: Instead of string formatting, using parameterized commands or libraries that properly escape shell arguments would prevent command injection.
    - Principle of least privilege: Running FFmpeg with minimal necessary privileges would limit the impact of a successful command injection.

- Preconditions:
    - The UVQ application must be running and accessible to an attacker.
    - The attacker needs to be able to provide input to the `--input_files` parameter of the `uvq_main.py` script, either directly if the application exposes command-line interface, or indirectly if there is a web interface or API that uses this script.

- Source code analysis:
    1. File: `/code/uvq_main.py`
    ```python
    flags.DEFINE_string('input_files', '', 'configuration of input files.')
    ...
    def main(_):
      # Input must be in format: video_id,video_length,file_path
      video_id, video_length, filepath = FLAGS.input_files.split(',')
      ...
      utils.generate_features(video_id, video_length, filepath, FLAGS.model_dir,
                            feature_dir, FLAGS.transpose)
    ```
    - The `filepath` is obtained directly from the `FLAGS.input_files` without any validation or sanitization.

    2. File: `/code/uvq_utils.py`
    ```python
    def generate_features(video_id, video_length, filepath, model_dir, output_dir,
                          transpose=False):
      ...
      video, video_resized = video_reader.VideoReader.load_video(filepath, video_length, transpose)
      ...
    ```
    - The `filepath` is passed directly to `video_reader.VideoReader.load_video`.

    3. File: `/code/utils/video_reader.py`
    ```python
    class VideoReader:
        @staticmethod
        def load_video(filepath, video_length, transpose=False):
            ...
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
                subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True)
            except subprocess.CalledProcessError as error:
                ...
    ```
    - The `filepath` variable is directly inserted into the `cmd` string using `%s` formatting.
    - `subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True)` executes the constructed command with `shell=True`, which is vulnerable to command injection.

- Security test case:
    1. Prepare a malicious filepath string that includes a command to be executed. For example: `"Gaming_1080P-0ce6,20,Gaming_1080P-0ce6_orig.mp4; touch /tmp/pwned"`
    2. Run the `uvq_main.py` script with the crafted `--input_files` parameter:
    ```bash
    python3 uvq_main.py --input_files="Gaming_1080P-0ce6,20,Gaming_1080P-0ce6_orig.mp4; touch /tmp/pwned" --output_dir=results --model_dir=models
    ```
    3. After running the command, check if the file `/tmp/pwned` exists on the server.
    4. If the file `/tmp/pwned` is created, it confirms that the command injection vulnerability is present, and arbitrary commands can be executed by an attacker through the `filepath` parameter.
    5. For a more robust test, the injected command could be something that provides network feedback (e.g., a reverse shell or exfiltration of data) to more clearly demonstrate the impact.