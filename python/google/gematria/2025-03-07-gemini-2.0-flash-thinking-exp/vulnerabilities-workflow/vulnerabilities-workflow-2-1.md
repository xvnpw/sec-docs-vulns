- Vulnerability Name: Command Injection in `convert_gb_token_model_to_tflite.sh` via graph definition file path
- Description:
    1. The `convert_gb_token_model_to_tflite.sh` script manually parses command-line arguments to get the input graph definition file path using string manipulation `${1:26}` and `${1:25}`.
    2. This manual parsing is vulnerable to command injection if the attacker can control the input graph definition file path, specifically through the `--gematria_input_graphdef` or `--gematria_output_tflite` flags.
    3. An attacker could craft a malicious file path containing backticks or shell commands, which would be executed when the script uses the path in a shell command, e.g., in the `tflite_convert` command execution.
    4. For example, if the attacker provides `--gematria_input_graphdef="/tmp/test`touch injected.txt`"` , the backticks will cause the `touch injected.txt` command to be executed.
- Impact: Arbitrary code execution. An attacker could execute arbitrary shell commands on the system running the `convert_gb_token_model_to_tflite.sh` script, potentially leading to data exfiltration, system compromise, or denial of service.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations: None. The script performs manual flag parsing without any input validation or sanitization.
- Missing Mitigations:
    - Use a robust command-line argument parsing library like `getopt` in shell scripts, or use Python for flag parsing which offers safer argument handling.
    - Validate and sanitize input file paths to ensure they do not contain shell metacharacters or command injection attempts.
    - Avoid using shell commands directly with user-controlled input. If shell commands are necessary, use parameterized commands or safer alternatives to prevent injection.
- Preconditions:
    - The attacker needs to be able to specify the `--gematria_input_graphdef` or `--gematria_output_tflite` arguments when running the `convert_gb_token_model_to_tflite.sh` script. This is likely possible if the script is used as part of a larger system where users can influence the model conversion process.
- Source Code Analysis:
    1. The vulnerability is in the flag parsing logic within the `convert_gb_token_model_to_tflite.sh` script.
    2. Specifically, lines like `gematria_input_graphdef="${1:26}"` and `gematria_output_tflite="${1:25}"` in the `while` loop are vulnerable. These lines use shell string slicing to extract the file paths after the flag names.
    3. The script then directly uses these paths in the `tflite_convert` command:
    ```shell
    tflite_convert \
      --graph_def_file="${gematria_input_graphdef}" \
      --output_file="${gematria_output_tflite}" \
      ...
    ```
    4. Because the file paths are not validated, a malicious path injected via command-line flags will be passed directly to the shell for execution within the `tflite_convert` command.
- Security Test Case:
    1. Create a malicious graph definition file path string: `"/tmp/test`touch injected.txt`"`.
    2. Execute the `convert_gb_token_model_to_tflite.sh` script with the crafted path as the value for `--gematria_input_graphdef`:
    ```shell
    gematria/granite/convert_gb_token_model_to_tflite.sh --gematria_input_graphdef="/tmp/test`touch injected.txt`" --gematria_output_tflite=/tmp/output.tflite
    ```
    3. Check if the file `injected.txt` is created in the `/tmp` directory. If the file is created, it confirms that the command injection vulnerability exists, and arbitrary commands can be executed.
    4. For a safer test without creating files, you can use `$(whoami)` or `$(hostname)` in the path and check the output or logs for unexpected execution of these commands.