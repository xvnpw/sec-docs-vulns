- Vulnerability Name: Path Traversal in `additional_packages_env_in_file`
- Description:
    - An attacker can exploit a path traversal vulnerability through the `additional_packages_env_in_file` parameter in the image configuration JSON.
    - Step 1: The attacker crafts a malicious image configuration JSON file.
    - Step 2: In this JSON file, the `additional_packages_env_in_file` parameter is set to a path that traverses outside the intended `build_artifacts` directory, e.g., `../../../../malicious.env.in`.
    - Step 3: When the `sagemaker-image-builder build` command is executed with this malicious configuration, the application uses the provided path without proper validation.
    - Step 4: The `get_match_specs` function attempts to read the file from the attacker-controlled path, potentially accessing files outside the `build_artifacts` directory.
    - Step 5: This could allow the attacker to include malicious conda packages or overwrite existing files during the Docker image build process.
- Impact:
    - Arbitrary file read or inclusion of malicious files during the Docker image build process.
    - Potential for remote code execution if malicious code is included in the Docker image via a crafted `additional_packages_env_in_file`.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. No input validation or sanitization is implemented for the `additional_packages_env_in_file` path.
- Missing Mitigations:
    - Implement input validation for the `additional_packages_env_in_file` parameter.
    - Sanitize the file path to prevent path traversal attacks.
    - Ensure that the provided path is restricted to the expected `build_artifacts` directory or use secure file path handling mechanisms to prevent access to unauthorized locations.
- Preconditions:
    - The attacker must be able to provide a malicious image configuration JSON file to the `sagemaker-image-builder build` command.
    - This could occur if the image configuration file is generated from user-supplied data or if an attacker gains access to modify existing configuration files.
- Source Code Analysis:
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
- Security Test Case:
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