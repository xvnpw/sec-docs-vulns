- Vulnerability Name: Command Injection via Unsanitized Encoder Arguments
- Description:
  1. The `encode_with_centers.py` script is designed to encode images using the `cjxl` encoder, leveraging predicted attention centers.
  2. It allows users to pass additional arguments to the `cjxl` encoder through the command line, after a `--` separator.
  3. These user-provided arguments are extracted from `sys.argv` and directly passed to the `subprocess.run` function when executing the `cjxl` encoder command.
  4. The script constructs the command for `cjxl` by concatenating fixed flags, attention center flags, and these user-supplied arguments without any sanitization or validation.
  5. This lack of sanitization enables an attacker to inject arbitrary shell commands by crafting malicious arguments as part of the additional encoder flags.
  6. When the `subprocess.run` executes the command, these injected commands are executed by the system, leading to command injection.
- Impact:
  - Arbitrary command execution on the system where `encode_with_centers.py` is executed.
  - Potential for complete system compromise, including unauthorized access, data exfiltration, malware installation, and denial of service.
  - Attackers can leverage this vulnerability to perform any action that the user running the script is authorized to perform.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
  - None. The script does not implement any sanitization, validation, or escaping of user-provided arguments before passing them to the `subprocess.run` function for executing the `cjxl` encoder.
- Missing Mitigations:
  - Input Sanitization: Implement robust input sanitization for all user-provided arguments that are intended to be passed to the `cjxl` encoder. This should include escaping shell metacharacters or disallowing them entirely.
  - Parameterized Execution: Use parameterized queries or similar safe mechanisms to construct the command for `cjxl`, ensuring that user inputs are treated as data and not executable code. In the context of `subprocess.run`, this means carefully constructing the argument list and avoiding shell interpretation of arguments.
  - Principle of Least Privilege:  Advise users to run the script with the minimal necessary privileges to limit the impact of a successful command injection attack.
  - Input Validation: Implement input validation to check if the provided arguments are in the expected format and value range, rejecting any unexpected or potentially malicious inputs.
- Preconditions:
  - The attacker must have the ability to execute the `encode_with_centers.py` script. This could be through direct access to a system where the script is installed, or indirectly by exploiting a web application or service that uses this script.
  - The `cjxl` encoder binary must be installed and accessible to the `encode_with_centers.py` script in the expected location or as configured by the `--encoder` flag.
- Source Code Analysis:
  1. The `main` function in `encode_with_centers.py` retrieves additional encoder flags from the command line arguments using `additional_encoder_flags = argv_for_encoder[1:]`. These are arguments provided after the script name, and intended to be passed to `cjxl` after a `--` separator in command line usage as documented in README.md.
  2. The script constructs the command to execute `cjxl` using a list called `encoder_command`. This list is built by combining:
     - The path to the encoder binary: `encoder` (`_ENCODER.value`).
     - Fixed flags: `group_order_flag = ['--group_order', '1']`.
     - Attention center flags: `center_flags`, dynamically generated based on model prediction.
     - User-provided additional encoder flags: `*additional_encoder_flags`.
     - Input image filename: `filename`.
     - Output image filename: `encoded_image`.
  3. The `subprocess.run(encoder_command)` function is then called to execute the constructed command. Because `encoder_command` is a list, `subprocess.run` executes the command directly without invoking a shell (unless `shell=True` is used, which is not the case here). This prevents direct shell injection into `subprocess.run` itself.
  4. However, the vulnerability arises because the script blindly passes `additional_encoder_flags` to `cjxl`. If `cjxl` or the underlying system command parsing in `cjxl` interprets certain argument patterns as commands, or if `cjxl` itself has vulnerabilities related to argument parsing, then injecting malicious arguments becomes possible.  Specifically, arguments designed for shell command injection can be inserted within `additional_encoder_flags`.
  5. For example, if a user provides `-- --distance '1.0 ; touch injected.txt'`, the `encoder_command` list will contain  `['./libjxl/build/tools/cjxl', '--group_order', '1', '--center_x', '...', '--center_y', '...', '--distance', '1.0 ; touch injected.txt', 'input.jpg', 'output.jxl']`. When `subprocess.run` executes this command, it's possible that parts of the argument string `'1.0 ; touch injected.txt'` are interpreted by the shell or by `cjxl` in a way that leads to execution of `touch injected.txt`. Even though `subprocess.run` is used in list form, the arguments passed to `cjxl` might be later processed by a shell or by vulnerable argument parsing logic within `cjxl` itself. The vulnerability is in passing unsanitized user input as arguments to an external program executed by `subprocess.run`.

- Security Test Case:
  1. Prerequisites:
     - Ensure you have a working environment with Python, TensorFlow Lite, and the compiled `cjxl` encoder from the `libjxl` submodule, as described in the project's README.
     - Navigate to the root directory of the cloned `attention-center` repository.
     - Create a dummy JPEG image named `test.jpg` in the current directory. This image does not need to be valid JPEG for the command injection test itself, but it should exist so the script can proceed without image loading errors.
  2. Execute the `encode_with_centers.py` script with a command injection payload as an additional argument. Use the `--` separator to pass arguments to `cjxl`. In this example, we will attempt to create a file named `injected.txt` in the current directory:
     ```bash
     python encode_with_centers.py --lite_model_file=./model/center.tflite --image_dir=. --output_dir=. -- --distance '1.0 ; touch injected.txt' test.jpg
     ```
     Alternatively, try to redirect the output of `ls -l` to a file:
     ```bash
     python encode_with_centers.py --lite_model_file=./model/center.tflite --image_dir=. --output_dir=. -- --distance '1.0 $(ls -l > listing.txt)' test.jpg
     ```
  3. Verify the outcome:
     - After executing the command, check if a file named `injected.txt` has been created in the same directory where you ran the script.
     - Or, in the second case, check if a file named `listing.txt` has been created and contains the output of the `ls -l` command.
  4. Expected Result:
     - If either `injected.txt` or `listing.txt` is created, it confirms the command injection vulnerability. This indicates that the user-provided arguments are not being properly sanitized and are allowing the execution of arbitrary commands through the `cjxl` encoder invocation.