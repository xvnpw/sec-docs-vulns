- Vulnerability Name: Command Injection via `image_config.json`

- Description:
  - An attacker can inject malicious commands into the Docker build process by crafting a manipulated `image_config.json` file.
  - The vulnerability lies in the `build_args` section of the `image_config.json` file.
  - The `sagemaker-image-builder build` command parses this `image_config.json` file.
  - It extracts the `build_args` dictionary.
  - These `build_args` are directly incorporated into the `docker build` command as `--build-arg` parameters without any sanitization.
  - The `docker build` command is then executed using `subprocess.check_output`.
  - By injecting malicious commands within the values of `build_args` in `image_config.json`, an attacker can execute arbitrary commands on the system during the Docker image build process.
  - For example, an attacker can set a `build_arg` value to `$(touch /tmp/pwned)` or `; touch /tmp/pwned`. When the `docker build` command is executed, this injected command will also be executed by the shell.

- Impact:
  - Arbitrary code execution on the system where the `sagemaker-image-builder build` command is executed.
  - This can lead to a full system compromise, including:
    - Data exfiltration: Sensitive data from the build environment or accessible systems could be stolen.
    - Malware installation: The attacker could install backdoors or malware for persistent access.
    - Privilege escalation: The attacker could escalate privileges within the build environment.
    - Denial of service: The attacker could disrupt the build process or the entire system.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
  - None. The code directly uses the `build_args` from the `image_config.json` file without any validation or sanitization before passing them to the `subprocess.check_output` to execute the `docker build` command.

- Missing Mitigations:
  - Input validation and sanitization: Implement strict validation and sanitization of the `build_args` values from the `image_config.json` file. Ensure that the values do not contain any shell metacharacters or command injection sequences.
  - Principle of least privilege: Run the `sagemaker-image-builder` tool and the Docker build process with the minimum necessary privileges to reduce the impact of a successful command injection.
  - Consider using Docker SDK: Instead of constructing the `docker build` command as a string and executing it via `subprocess`, use the Docker SDK for Python (`docker-py`). The SDK provides functions to build images programmatically, which can help avoid command injection vulnerabilities if used correctly. However, it's crucial to ensure that even when using the SDK, input sanitization is still performed if user-provided data is used in the build process.

- Preconditions:
  - The attacker must be able to provide or modify the `image_config.json` file that is used by the `sagemaker-image-builder build` command. This could happen if:
    - The attacker has write access to the file system where `image_config.json` is stored.
    - The `image_config.json` file is fetched from an untrusted source controlled by the attacker.
    - A higher-level process or user interface allows an attacker to influence the content of the `image_config.json` file.

- Source Code Analysis:
  - The vulnerability is located in the `build_images` function in `/code/sagemaker_image_builder/main.py`.
  - Step-by-step analysis:
    1. The `build_images` function starts by reading the `image_config.json` file:
       ```python
       with open(args.image_config_file) as jsonfile:
           image_config = json.load(jsonfile)
       ```
    2. It then iterates through each image configuration in the `image_config` list.
    3. For each image configuration, it retrieves the `build_args` dictionary:
       ```python
       build_arg_options = sum([["--build-arg", f"{k}={v}"] for k, v in config["build_args"].items()], [])
       ```
       - This line constructs a list of `--build-arg` options for the `docker build` command. It directly iterates through the `config["build_args"].items()` and formats them as `"--build-arg", "key=value"`.  **No sanitization is performed on keys or values.**
    4. The `docker build` command is constructed as a list of strings:
       ```python
       docker_build_command = ["docker", "build", "--rm", "--pull"] + build_arg_options + [f"./{target_version_dir}"]
       ```
       - The `build_arg_options` list, which contains the unsanitized `build_args` from `image_config.json`, is directly concatenated into the `docker_build_command`.
    5. The `docker_build_command` is executed using `subprocess.check_output`:
       ```python
       try:
           raw_build_result = subprocess.check_output(
               docker_build_command, stderr=subprocess.STDOUT, universal_newlines=True
           )
       except subprocess.CalledProcessError as e:
           print(f"Build failed with exit code {e.returncode}. Output:")
           print(e.output)
           raise
       ```
       - `subprocess.check_output` executes the shell command. Because `build_args` are not sanitized, an attacker can inject shell commands within the values of `build_args`, leading to command injection.

  - Visualization:

    ```
    [image_config.json] --> (read) --> image_config (Python dict)
        |
        |--> build_args (extracted from image_config)
        |
        |--> (construct docker build command) docker_build_command = ["docker", "build", ...] + build_args + [...]
        |
        |--> (execute command) subprocess.check_output(docker_build_command)  <-- VULNERABILITY: Command Injection
        |
        [Docker Image Build]
    ```

- Security Test Case:
  - Step 1: Create a malicious `image_config.json` file with the following content. This example injects the command `touch /tmp/pwned` within a `build_arg` value:
    ```json
    [
      {
        "image_name": "malicious-image",
        "build_args": {
          "MALICIOUS_ARG": "$(touch /tmp/pwned)"
        },
        "env_out_filename": "malicious.env.out",
        "image_type": "malicious-type"
      }
    ]
    ```
  - Step 2: Save this file as `malicious_config.json` in the project directory (or any location accessible to the tool).
  - Step 3: Execute the `sagemaker-image-builder build` command, providing the malicious configuration file and a target patch version (e.g., 0.0.1):
    ```bash
    VERSION=0.0.1
    IMAGE_CONFIG_FILE=malicious_config.json
    sagemaker-image-builder build --target-patch-version $VERSION --image-config-file $IMAGE_CONFIG_FILE
    ```
  - Step 4: After the command executes, check if the file `/tmp/pwned` exists on the system where the `sagemaker-image-builder build` command was run.
    ```bash
    ls /tmp/pwned
    ```
  - If the file `/tmp/pwned` exists, it confirms that the injected command `touch /tmp/pwned` was successfully executed during the Docker build process, demonstrating the command injection vulnerability.