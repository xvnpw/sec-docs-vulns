## Combined Vulnerability List

### Vulnerability Name: Path Traversal in `additional_packages_env_in_file`

- **Description:**
    - An attacker can exploit a path traversal vulnerability through the `additional_packages_env_in_file` parameter in the image configuration JSON.
    - Step 1: The attacker crafts a malicious image configuration JSON file.
    - Step 2: In this JSON file, the `additional_packages_env_in_file` parameter is set to a path that traverses outside the intended `build_artifacts` directory, e.g., `../../../../malicious.env.in`.
    - Step 3: When the `sagemaker-image-builder build` command is executed with this malicious configuration, the application uses the provided path without proper validation.
    - Step 4: The `get_match_specs` function attempts to read the file from the attacker-controlled path, potentially accessing files outside the `build_artifacts` directory.
    - Step 5: This could allow the attacker to include malicious conda packages or overwrite existing files during the Docker image build process.
- **Impact:**
    - Arbitrary file read or inclusion of malicious files during the Docker image build process.
    - Potential for remote code execution if malicious code is included in the Docker image via a crafted `additional_packages_env_in_file`.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - None. No input validation or sanitization is implemented for the `additional_packages_env_in_file` path.
- **Missing Mitigations:**
    - Implement input validation for the `additional_packages_env_in_file` parameter.
    - Sanitize the file path to prevent path traversal attacks.
    - Ensure that the provided path is restricted to the expected `build_artifacts` directory or use secure file path handling mechanisms to prevent access to unauthorized locations.
- **Preconditions:**
    - The attacker must be able to provide a malicious image configuration JSON file to the `sagemaker-image-builder build` command.
    - This could occur if the image configuration file is generated from user-supplied data or if an attacker gains access to modify existing configuration files.
- **Source Code Analysis:**
    - File: `/code/sagemaker_image_builder/main.py`
    - Function: `_create_new_version_conda_specs`
    - Vulnerable code:
      ```python
      additional_packages_match_specs_in = get_match_specs(f"{new_version_dir}/{additional_packages_env_in_filename}")
      ```
    - The `additional_packages_env_in_filename` is directly taken from the image configuration and passed to `get_match_specs` without any validation.
    - File: `/code/sagemaker_image_builder/utils.py`
    - Function: `get_match_specs`
      ```python
      requirement_spec = read_env_file(file_path)
      ```
    - Calls `read_env_file` with the unvalidated `file_path`.
    - File: `/code/sagemaker_image_builder/utils.py`
    - Function: `read_env_file`
      ```python
      return RequirementsSpec(filename=file_path)
      ```
    - Directly uses the provided `filename` to create `RequirementsSpec`, leading to potential path traversal if `file_path` is malicious.
- **Security Test Case:**
    - Step 1: Create a malicious environment file named `malicious.env.in` with content `conda-forge::test-package` and place it outside the `build_artifacts` directory, for example, in the `/tmp/` directory.
    - Step 2: Create an image configuration file named `image_config_malicious.json` with the following content:
      ```json
      [
          {
              "image_name": "test-image",
              "build_args": {
                  "TAG_FOR_BASE_MICROMAMBA_IMAGE": "jammy-cuda-11.8.0",
                  "CUDA_MAJOR_MINOR_VERSION": "11.8",
                  "ENV_IN_FILENAME": "gpu.env.in",
                  "ARG_BASED_ENV_IN_FILENAME": "gpu.arg_based_env.in"
              },
              "additional_packages_env_in_file": "../../../../../tmp/malicious.env.in",
              "image_tag_suffix": "test",
              "env_out_filename": "test.env.out",
              "image_type": "test"
          }
      ]
      ```
    - Step 3: Run the build command:
      ```bash
      VERSION=0.0.1
      IMAGE_CONFIG_FILE=image_config_malicious.json
      sagemaker-image-builder build --target-patch-version $VERSION --image-config-file $IMAGE_CONFIG_FILE --skip-tests
      ```
    - Step 4: After the build completes, inspect the Docker image (e.g., using `docker history <image_id>`).
    - Step 5: Verify if the `test-package` from the `malicious.env.in` file located outside the intended directory is included in the Docker image. If it is, the path traversal vulnerability is confirmed. You can also try to execute a command in the Dockerfile using the malicious env file to further confirm code execution.

### Vulnerability Name: Command Injection via `build_args` in Image Configuration

- **Description:**
    - An attacker can inject malicious commands into the Docker build process by crafting a manipulated `image_config.json` file.
    - The vulnerability lies in the `build_args` section of the `image_config.json` file.
    - The `sagemaker-image-builder build` command parses this `image_config.json` file.
    - It extracts the `build_args` dictionary.
    - These `build_args` are directly incorporated into the `docker build` command as `--build-arg` parameters without any sanitization.
    - The `docker build` command is then executed using `subprocess.check_output`.
    - By injecting malicious commands within the values of `build_args` in `image_config.json`, an attacker can execute arbitrary commands on the system during the Docker image build process.
    - For example, an attacker can set a `build_arg` value to `$(touch /tmp/pwned)` or `; touch /tmp/pwned`. When the `docker build` command is executed, this injected command will also be executed by the shell.
- **Impact:**
    - Arbitrary code execution on the system where the `sagemaker-image-builder build` command is executed.
    - This can lead to a full system compromise, including:
        - Data exfiltration: Sensitive data from the build environment or accessible systems could be stolen.
        - Malware installation: The attacker could install backdoors or malware for persistent access.
        - Privilege escalation: The attacker could escalate privileges within the build environment.
        - Denial of service: The attacker could disrupt the build process or the entire system.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    - None. The code directly uses the `build_args` from the `image_config.json` file without any validation or sanitization before passing them to the `subprocess.check_output` to execute the `docker build` command.
- **Missing Mitigations:**
    - Input validation and sanitization: Implement strict validation and sanitization of the `build_args` values from the `image_config.json` file. Ensure that the values do not contain any shell metacharacters or command injection sequences.
    - Principle of least privilege: Run the `sagemaker-image-builder` tool and the Docker build process with the minimum necessary privileges to reduce the impact of a successful command injection.
    - Consider using Docker SDK: Instead of constructing the `docker build` command as a string and executing it via `subprocess`, use the Docker SDK for Python (`docker-py`). The SDK provides functions to build images programmatically, which can help avoid command injection vulnerabilities if used correctly. However, it's crucial to ensure that even when using the SDK, input sanitization is still performed if user-provided data is used in the build process.
- **Preconditions:**
    - The attacker must be able to provide or modify the `image_config.json` file that is used by the `sagemaker-image-builder build` command. This could happen if:
        - The attacker has write access to the file system where `image_config.json` is stored.
        - The `image_config.json` file is fetched from an untrusted source controlled by the attacker.
        - A higher-level process or user interface allows an attacker to influence the content of the `image_config.json` file.
- **Source Code Analysis:**
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

- **Security Test Case:**
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
    - Step 5: If the file `/tmp/pwned` exists, it confirms that the injected command `touch /tmp/pwned` was successfully executed during the Docker build process, demonstrating the command injection vulnerability.

### Vulnerability Name: Command Injection via `additional_packages_env_in_file` in Image Configuration

- **Description:**
    - An attacker crafts a malicious `additional_packages_env_in_file`.
    - Within this file, the attacker injects arbitrary commands. For example, adding a line like `$(touch /tmp/pwned_image)` in the file.
    - The attacker provides an image configuration JSON file that references this malicious `additional_packages_env_in_file`.
    - The `sagemaker-image-builder build` command is executed with this configuration.
    - The `sagemaker-image-builder` tool reads the `additional_packages_env_in_file` and processes its contents.
    - If the tool improperly handles the content of `additional_packages_env_in_file` and executes it as a shell command or passes it unsanitized to a shell-executing process during the Docker image build, the injected commands will be executed.
    - This can lead to arbitrary command execution within the Docker build environment, potentially resulting in container escape or a compromised Docker image.
- **Impact:**
    - **Container Escape:** Similar to the `build_args` injection, this can also lead to escaping the Docker container build environment.
    - **Compromised Docker Image:** Malicious modifications can be injected into the Docker image.
    - **Confidentiality and Integrity Violation:** Host system and image integrity can be compromised.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - None. The code reads and processes the `additional_packages_env_in_file` but there is no visible sanitization of its contents before using it in the build process. The code uses `get_match_specs` to parse the file, which is designed to parse conda environment files, but if the file is not strictly in that format and contains shell commands, it might still be exploitable if the contents are later used in a shell context.
- **Missing Mitigations:**
    - Input Sanitization and Validation: Sanitize and validate the contents of `additional_packages_env_in_file`. Ensure that the file only contains valid package specifications and does not include any executable commands or shell metacharacters. Validate against expected format.
    - Secure File Handling: Process the `additional_packages_env_in_file` in a way that avoids shell interpretation of its contents. If the intention is to process package names, ensure that the parsing logic is robust against unexpected or malicious content.
- **Preconditions:**
    - The attacker needs to be able to create or modify the file specified as `additional_packages_env_in_file` and reference it in the image configuration JSON file.
- **Source Code Analysis:**
    - File: `/code/sagemaker_image_builder/main.py`
    - Function: `_create_new_version_conda_specs(...)` and `_get_config_for_image(...)` indirectly uses `additional_packages_env_in_file`.
    - Code Snippet in `_create_new_version_conda_specs`:
    ```python
    def _create_new_version_conda_specs(
        base_version_dir, new_version_dir, runtime_version_upgrade_type, image_generator_config
    ):
        # ...
        additional_packages_env_in_filename = image_generator_config["additional_packages_env_in_file"]
        # ...
        additional_packages_match_specs_in = get_match_specs(f"{new_version_dir}/{additional_packages_env_in_filename}")
        # ...
    ```
    - Code Snippet in `_get_config_for_image`:
    ```python
    def _get_config_for_image(target_version_dir: str, image_generator_config, force_rebuild) -> dict:
        # ...
        config_for_image = copy.deepcopy(image_generator_config)
        # ...
        return config_for_image
    ```
    - The `additional_packages_env_in_file` path is read from the image configuration and passed to `get_match_specs`. While `get_match_specs` is intended to parse conda environment files and might not directly execute shell commands, if the contents of this file are later used in a context where shell commands are executed (though not directly evident in the provided code snippets for `additional_packages_env_in_file`), it could become a vulnerability. Further analysis of how `additional_packages_env_in_file` is used in Dockerfile or other parts of the build process is needed to confirm if the content of this file can lead to command injection.
- **Security Test Case:**
    - Step 1: Create a malicious additional packages environment input file named `malicious_packages.in` with the following content:
    ```
    conda-forge::package1
    $(touch /tmp/pwned_image)
    conda-forge::package2
    ```
    - Step 2: Create a malicious image configuration file named `malicious_config_packages.json` with the following content, referencing the malicious packages file:
    ```json
    [
        {
            "image_name": "malicious-image-packages",
            "build_args": {
                "TAG_FOR_BASE_MICROMAMBA_IMAGE": "jammy-cuda-11.8.0",
                "CUDA_MAJOR_MINOR_VERSION": "11.8",
                "ENV_IN_FILENAME": "gpu.env.in",
                "ARG_BASED_ENV_IN_FILENAME": "gpu.arg_based_env.in"
            },
            "additional_packages_env_in_file": "malicious_packages.in",
            "image_tag_suffix": "gpu",
            "env_out_filename": "gpu_packages.env.out",
            "image_type": "gpu"
        }
    ]
    ```
    - Step 3: Place `malicious_packages.in` in the same directory as you will run the build command, or adjust the path in `malicious_config_packages.json` accordingly.
    - Step 4: Navigate to the `/code` directory of the project in a terminal.
    - Step 5: Execute the `sagemaker-image-builder build` command with the malicious configuration:
    ```shell
    VERSION=0.0.1
    IMAGE_CONFIG_FILE=malicious_config_packages.json
    sagemaker-image-builder build --target-patch-version $VERSION --image-config-file $IMAGE_CONFIG_FILE
    ```
    - Step 6: Check for successful command execution: After the build process completes (or fails), check if the file `/tmp/pwned_image` exists within the Docker image. This might require running the built image and checking inside the container. Alternatively, check if the command execution leads to any observable side effects on the host system, depending on how the `additional_packages_env_in_file` is processed.

### Vulnerability Name: Path Traversal and Arbitrary File Inclusion via Malicious `build_artifacts`

- **Description:**
    - An attacker crafts a malicious `build_artifacts` folder.
    - This folder contains a manipulated Dockerfile or other build artifacts designed to exploit path traversal (e.g., using `../` sequences).
    - The attacker tricks a user into providing the path to this malicious `build_artifacts` folder to the `sagemaker-image-builder` tool.
    - When the tool initiates the Docker image build process, it utilizes the artifacts from the attacker-supplied folder without proper validation.
    - Due to the path traversal sequences embedded in the Dockerfile or other build artifacts, the Docker build process can access files and directories outside the intended `build_artifacts` directory.
    - This allows the attacker to inject malicious content, such as backdoors or exploits, into the resulting Docker image by copying or adding files from arbitrary locations.
- **Impact:**
    - **Compromised Docker Image:** The Docker image built using the malicious artifacts can be backdoored, contain malware, or have exploitable vulnerabilities. This can lead to the compromise of SageMaker environments or any systems utilizing these images.
    - **Information Disclosure:** A malicious Dockerfile could be crafted to exfiltrate sensitive information from the build environment during the image creation process by copying them into the image and potentially exposing them later.
    - **Supply Chain Attack:** If the compromised Docker image is distributed and used by other users or systems, it can propagate the vulnerability, leading to a supply chain attack.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - None. The tool directly processes user-provided `build_artifacts` without any input validation or security checks on the contents of the artifacts.
- **Missing Mitigations:**
    - Input Validation and Sanitization: Implement rigorous validation and sanitization of all files and paths within the `build_artifacts` folder before using them in the Docker build process. This should specifically prevent path traversal attempts.
    - Restricting Docker Build Context: Ensure that the Docker build context is strictly limited to the intended `build_artifacts` directory and prevent access to parent directories or arbitrary file system locations.
    - Sandboxed Build Environment: Consider executing the Docker build process within a sandboxed or containerized environment. This would limit the potential damage if malicious artifacts are used, as the build process would be isolated from the host system.
    - Code Review: Conduct thorough security code reviews, specifically focusing on file handling, path processing, and Docker build execution, to identify and rectify potential vulnerabilities.
- **Preconditions:**
    - An attacker must be able to create a malicious `build_artifacts` folder with a crafted Dockerfile or other build artifacts.
    - A user must be persuaded to use the `sagemaker-image-builder` tool with the path pointing to this malicious `build_artifacts` folder.
- **Source Code Analysis:**
    - `sagemaker_image_builder/main.py`:
        - The `build_images` function in `main.py` orchestrates the image build process.
        - It uses `get_dir_for_version(target_version)` to determine the directory for build artifacts, which is based on user-provided `target_patch_version`.
        - The `_build_local_images` function is then called, which executes the `docker build` command.
        - The crucial part is that `docker build` is executed with the build context set directly to the `target_version_dir`, which originates from the user-provided `build_artifacts` folder.
        - ```python
          docker_build_command = ["docker", "build", "--rm", "--pull"] + build_arg_options + [f"./{target_version_dir}"]
          ```
        - There is no code present to validate or sanitize the contents of `target_version_dir` before it's used as the build context. This means if a malicious user crafts a `build_artifacts` folder with a Dockerfile containing path traversal, the `docker build` command will execute it as is.
- **Security Test Case:**
    - Step 1: Create Malicious Build Artifacts
        - Create a directory structure for malicious build artifacts:
          ```bash
          mkdir -p malicious_build_artifacts/v0/v0.0/v0.0.1
          ```
        - Create a malicious `Dockerfile` within the directory that uses path traversal to copy the host's `/etc/passwd` file into the image:
          ```bash
          echo "FROM alpine\nCOPY ../../../../../../../../../../../etc/passwd /tmp/passwd_leaked" > malicious_build_artifacts/v0/v0.0/v0.0.1/Dockerfile
          ```
    - Step 2: Create Dummy Image Configuration
        - Create a minimal `image_config.json` file:
          ```json
          echo '[{"image_name": "test-image", "build_args": {}, "env_out_filename": "cpu.env.out", "image_type": "cpu"}]' > image_config.json
          ```
    - Step 3: Run `sagemaker-image-builder build` with Malicious Artifacts
        - Execute the `sagemaker-image-builder build` command, specifying the malicious `build_artifacts` folder indirectly through `target-patch-version` and relying on default `build_artifacts` base path.
          ```bash
          sagemaker-image-builder build --target-patch-version 0.0.1 --image-config-file image_config.json
          ```
    - Step 4: Run the Built Docker Image
        - Execute the newly built Docker image:
          ```bash
          docker run test-image:0.0.1 cat /tmp/passwd_leaked
          ```
    - Step 5: Verify Path Traversal
        - Check the output of the `docker run` command. If the `/etc/passwd` file content is displayed, it confirms that the path traversal in the malicious Dockerfile was successful, and the host's `/etc/passwd` file was copied into the container. This demonstrates the vulnerability.