- Vulnerability name: Path Traversal and Arbitrary File Inclusion via Malicious `build_artifacts`
- Description:
    - An attacker crafts a malicious `build_artifacts` folder.
    - This folder contains a manipulated Dockerfile or other build artifacts designed to exploit path traversal (e.g., using `../` sequences).
    - The attacker tricks a user into providing the path to this malicious `build_artifacts` folder to the `sagemaker-image-builder` tool.
    - When the tool initiates the Docker image build process, it utilizes the artifacts from the attacker-supplied folder without proper validation.
    - Due to the path traversal sequences embedded in the Dockerfile or other build artifacts, the Docker build process can access files and directories outside the intended `build_artifacts` directory.
    - This allows the attacker to inject malicious content, such as backdoors or exploits, into the resulting Docker image by copying or adding files from arbitrary locations.
- Impact:
    - **Compromised Docker Image:** The Docker image built using the malicious artifacts can be backdoored, contain malware, or have exploitable vulnerabilities. This can lead to the compromise of SageMaker environments or any systems utilizing these images.
    - **Information Disclosure:** A malicious Dockerfile could be crafted to exfiltrate sensitive information from the build environment during the image creation process by copying them into the image and potentially exposing them later.
    - **Supply Chain Attack:** If the compromised Docker image is distributed and used by other users or systems, it can propagate the vulnerability, leading to a supply chain attack.
- Vulnerability rank: High
- Currently implemented mitigations:
    - None. The tool directly processes user-provided `build_artifacts` without any input validation or security checks on the contents of the artifacts.
- Missing mitigations:
    - **Input Validation and Sanitization:** Implement rigorous validation and sanitization of all files and paths within the `build_artifacts` folder before using them in the Docker build process. This should specifically prevent path traversal attempts.
    - **Restricting Docker Build Context:** Ensure that the Docker build context is strictly limited to the intended `build_artifacts` directory and prevent access to parent directories or arbitrary file system locations.
    - **Sandboxed Build Environment:** Consider executing the Docker build process within a sandboxed or containerized environment. This would limit the potential damage if malicious artifacts are used, as the build process would be isolated from the host system.
    - **Code Review:** Conduct thorough security code reviews, specifically focusing on file handling, path processing, and Docker build execution, to identify and rectify potential vulnerabilities.
- Preconditions:
    - An attacker must be able to create a malicious `build_artifacts` folder with a crafted Dockerfile or other build artifacts.
    - A user must be persuaded to use the `sagemaker-image-builder` tool with the path pointing to this malicious `build_artifacts` folder.
- Source code analysis:
    - `sagemaker_image_builder/main.py`:
        - The `build_images` function in `main.py` orchestrates the image build process.
        - It uses `get_dir_for_version(target_version)` to determine the directory for build artifacts, which is based on user-provided `target_patch_version`.
        - The `_build_local_images` function is then called, which executes the `docker build` command.
        - The crucial part is that `docker build` is executed with the build context set directly to the `target_version_dir`, which originates from the user-provided `build_artifacts` folder.
        - ```python
          docker_build_command = ["docker", "build", "--rm", "--pull"] + build_arg_options + [f"./{target_version_dir}"]
          ```
        - There is no code present to validate or sanitize the contents of `target_version_dir` before it's used as the build context. This means if a malicious user crafts a `build_artifacts` folder with a Dockerfile containing path traversal, the `docker build` command will execute it as is.
    - Visualization:
        ```
        User Input (Malicious build_artifacts) --> sagemaker-image-builder (build_images, _build_local_images) --> docker build (Vulnerable to Path Traversal in Dockerfile) --> Compromised Docker Image
        ```
- Security test case:
    - **Step 1: Create Malicious Build Artifacts**
        - Create a directory structure for malicious build artifacts:
          ```bash
          mkdir -p malicious_build_artifacts/v0/v0.0/v0.0.1
          ```
        - Create a malicious `Dockerfile` within the directory that uses path traversal to copy the host's `/etc/passwd` file into the image:
          ```bash
          echo "FROM alpine\nCOPY ../../../../../../../../../../../etc/passwd /tmp/passwd_leaked" > malicious_build_artifacts/v0/v0.0/v0.0.1/Dockerfile
          ```
    - **Step 2: Create Dummy Image Configuration**
        - Create a minimal `image_config.json` file:
          ```json
          echo '[{"image_name": "test-image", "build_args": {}, "env_out_filename": "cpu.env.out", "image_type": "cpu"}]' > image_config.json
          ```
    - **Step 3: Run `sagemaker-image-builder build` with Malicious Artifacts**
        - Execute the `sagemaker-image-builder build` command, specifying the malicious `build_artifacts` folder indirectly through `target-patch-version` and relying on default `build_artifacts` base path.
          ```bash
          sagemaker-image-builder build --target-patch-version 0.0.1 --image-config-file image_config.json
          ```
    - **Step 4: Run the Built Docker Image**
        - Execute the newly built Docker image:
          ```bash
          docker run test-image:0.0.1 cat /tmp/passwd_leaked
          ```
    - **Step 5: Verify Path Traversal**
        - Check the output of the `docker run` command. If the `/etc/passwd` file content is displayed, it confirms that the path traversal in the malicious Dockerfile was successful, and the host's `/etc/passwd` file was copied into the container. This demonstrates the vulnerability.