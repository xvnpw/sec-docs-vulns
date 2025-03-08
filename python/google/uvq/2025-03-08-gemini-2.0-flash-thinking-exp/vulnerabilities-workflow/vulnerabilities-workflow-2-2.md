### Vulnerability List

- Vulnerability Name: Command Injection via Filename (FFmpeg)
- Description:
    - The `video_reader.py` script utilizes the `subprocess.check_output` function to execute FFmpeg commands.
    - The FFmpeg command string is dynamically constructed by embedding the video filepath, which is provided as user input, directly into the command.
    - Specifically, the `filepath` variable, derived from user-supplied input, is inserted into the FFmpeg command string using `%s` formatting without proper sanitization.
    - Due to the use of `shell=True` in `subprocess.check_output`, the system shell interprets the entire command string.
    - An attacker can craft a malicious video filename that includes shell commands. When this filename is processed by the `VideoReader.load_video` function, the injected shell commands will be executed by the system.
    - For example, a malicious filename could be `"; touch /tmp/pwned"`. When this filename is used, the constructed FFmpeg command becomes something like: `ffmpeg -i "; touch /tmp/pwned".mp4 ...`. The shell will execute `touch /tmp/pwned` before running ffmpeg.
- Impact:
    - Arbitrary code execution on the server or machine running the UVQ tool.
    - An attacker could potentially gain full control over the affected system. This includes the ability to read sensitive data, modify files, install malware, or pivot to other systems on the network.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None. The codebase lacks any input sanitization or command parameterization to prevent command injection. The `filepath` from user input is directly embedded into the shell command.
- Missing Mitigations:
    - **Input Validation and Sanitization**: Implement robust validation and sanitization of the input `filepath`. Sanitize the filename to remove or escape shell-sensitive characters before incorporating it into the FFmpeg command. However, complete sanitization can be complex and error-prone.
    - **Use `subprocess.Popen` with Command List**: The most effective mitigation is to avoid using `shell=True` and string formatting for command construction. Instead, utilize `subprocess.Popen` with a command list. This method passes arguments as a list, preventing shell interpretation of metacharacters and effectively eliminating command injection vulnerabilities. Construct the FFmpeg command as a list where each element is a command or argument, e.g., `['ffmpeg', '-i', filepath, ...]`.
    - **Principle of Least Privilege**: Run the UVQ tool and FFmpeg processes with the minimum necessary privileges. If the UVQ tool is compromised, limiting its privileges reduces the potential damage an attacker can inflict.
- Preconditions:
    - An attacker must be able to provide or influence the filename of the video file processed by the UVQ tool. In the provided command-line interface, this is directly through the `--input_files` argument for `uvq_main.py` and the first positional argument for `uvq_pytorch/inference.py`.
    - The system must have FFmpeg installed and accessible in the system's PATH for the `video_reader.py` script to execute it.
- Source Code Analysis:
    1. File: `/code/utils/video_reader.py`, Function: `VideoReader.load_video`
    2. The `cmd` variable is constructed using an f-string (in Python versions where f-strings are available, or using `%` formatting as seen in the provided code). The `filepath` variable, which originates from user-provided input, is directly embedded into this string without any sanitization or validation.
    ```python
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
    ```
    3. The `subprocess.check_output` function is called with `shell=True`. This is the critical part that enables command injection because it allows the shell to interpret shell metacharacters within the `cmd` string.
    ```python
    subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True)
    ```
    4. In `/code/uvq_main.py` and `/code/uvq_pytorch/inference.py`, the video filepath is obtained from command-line arguments and directly passed to `VideoReader.load_video`.
- Security Test Case:
    1. Create a file with a malicious filename. For example, rename a dummy video file (e.g., an empty `.mp4` file) to `"; touch /tmp/uvq_pwned_tensorflow.txt".mp4`.
    2. Execute the `uvq_main.py` script, providing the malicious filename as input. Replace `<path_to_malicious_video>` with the actual path to the renamed file.
    ```bash
    python3 uvq_main.py --input_files="malicious_video,20,<path_to_malicious_video>" --output_dir results --model_dir models
    ```
    3. Check for successful command injection. Verify if the file `/tmp/uvq_pwned_tensorflow.txt` has been created. If the file exists, it confirms that the `touch /tmp/uvq_pwned_tensorflow.txt` command, injected through the filename, was successfully executed by the system.
    4. Repeat steps 1-3 for the PyTorch implementation using `uvq_pytorch/inference.py`. Rename the dummy video file to `"; touch /tmp/uvq_pwned_pytorch.txt".mp4`.
    ```bash
    python3 uvq_pytorch/inference.py "; touch /tmp/uvq_pwned_pytorch.txt".mp4 20
    ```
    5. Check if the file `/tmp/uvq_pwned_pytorch.txt` has been created. Existence of this file confirms successful command injection in the PyTorch implementation as well.

This test case demonstrates that by controlling the video filename, an attacker can inject and execute arbitrary shell commands on the system running the UVQ tool, confirming the command injection vulnerability.