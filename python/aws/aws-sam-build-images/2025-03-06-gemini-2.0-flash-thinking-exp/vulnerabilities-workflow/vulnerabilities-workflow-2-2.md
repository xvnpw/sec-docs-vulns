### Vulnerability List

- Vulnerability Name: Docker Content Trust Disabled

- Description:
    - The `build_all_images.sh` script explicitly disables Docker Content Trust by setting `export DOCKER_CONTENT_TRUST=0`.
    - Docker Content Trust is a security feature that uses digital signatures to ensure the integrity and publisher authenticity of container images. When enabled, Docker verifies the signature of an image before pulling and running it, ensuring that the image has not been tampered with and comes from a trusted publisher.
    - By disabling Docker Content Trust, the script allows Docker to pull images from public registries without signature verification.
    - If a public registry is compromised or an attacker performs a man-in-the-middle attack, malicious images could be pulled and used as base images for building the AWS SAM CLI build images.
    - This can lead to the injection of malicious code into the AWS SAM CLI build images, which are then used by developers to build serverless applications.

- Impact:
    - **Supply Chain Attack:** If a malicious base image is used due to disabled content trust, all AWS SAM CLI build images built using this compromised base image will also be compromised.
    - **Code Injection:** Developers using these compromised build images will unknowingly incorporate malicious code into their serverless applications during the build process.
    - **Data Breach and System Compromise:** The injected malicious code in serverless applications could lead to various security breaches, including data exfiltration, credential theft, unauthorized access to AWS resources, and complete compromise of the deployed serverless application and potentially the underlying infrastructure.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None. The project explicitly disables Docker Content Trust in the `build_all_images.sh` script.

- Missing Mitigations:
    - **Enable Docker Content Trust by Default:** The `build_all_images.sh` script should not disable Docker Content Trust. It should be either enabled by default or the script should be modified to respect the user's Docker Content Trust settings.
    - **Documentation and User Awareness:**  The project documentation should clearly explain the security implications of disabling Docker Content Trust and strongly advise users against disabling it, especially when building and using container images.  It should also explain how to enable and use Docker Content Trust.
    - **Base Image Verification:** While Content Trust is the primary mitigation, additional measures could include:
        - Using base images from official and verified publishers.
        - Regularly scanning base images for known vulnerabilities.
        - Potentially mirroring base images in a private registry with Content Trust enabled for internal use, adding another layer of control.

- Preconditions:
    - An attacker compromises a public Docker registry or performs a man-in-the-middle attack to replace legitimate base images with malicious ones.
    - The `build_all_images.sh` script is executed, or developers manually build images using Dockerfiles from this project while Docker Content Trust is disabled (as suggested by the script).
    - Developers use the resulting compromised build images to build their serverless applications.

- Source Code Analysis:
    - File: `/code/build-image-src/build_all_images.sh`
    - Line:
        ```sh
        export DOCKER_CONTENT_TRUST=0
        ```
    - This line sets the environment variable `DOCKER_CONTENT_TRUST` to `0`.
    - When `DOCKER_CONTENT_TRUST` is set to `0`, Docker client disables content trust verification for image pull and push operations.
    - Consequently, when the script executes `docker build` commands to build various AWS SAM CLI build images, the base images specified in the Dockerfiles (e.g., `amazonlinux:2023`, `public.ecr.aws/docker/library/amazonlinux:2023`, `ubuntu:20.04`, etc. within the various `Dockerfile-*`) are pulled without any cryptographic signature verification.
    - This opens the door for using potentially compromised base images if an attacker manages to inject malicious images into the public registries under the same image names and tags.

- Security Test Case:
    1. **Setup:**
        - Set up a local Docker environment where you have control over image pulling.
        - Obtain the `build_all_images.sh` script and relevant Dockerfile (e.g., `Dockerfile-python3.9`) from the repository.
        - Identify the base image used in the Dockerfile (e.g., `amazonlinux:2023`).
        - **Simulate a Malicious Base Image:** Create a simple Dockerfile for a malicious base image based on `amazonlinux:2023`. This malicious image should include a benign indicator of compromise, such as echoing a warning message to the console during the build process and creating a file in `/tmp/INJECTED`. For example:
            ```dockerfile
            FROM amazonlinux:2023
            RUN echo "[VULNERABILITY-TEST] Malicious base image is being used!"
            RUN touch /tmp/INJECTED
            ```
        - Build this malicious base image and tag it as `amazonlinux:2023` in your local Docker registry.  Make sure this local registry is consulted *before* the public Docker Hub or ECR. This can be achieved by manipulating your Docker daemon configuration or simply by having a local image already present.
    2. **Trigger Vulnerability:**
        - Ensure Docker Content Trust is effectively disabled for your testing environment (though the script already does this).
        - Run the `build_all_images.sh` script, making sure `SAM_CLI_VERSION` is set. You can modify the script temporarily to only build the `python3.9` image to speed up testing.
        - Observe the output of the `docker build` process for the `amazon/aws-sam-cli-build-image-python3.9:x86_64` image.
    3. **Verify Impact:**
        - Check the Docker build logs. You should see the warning message `[VULNERABILITY-TEST] Malicious base image is being used!` in the output, confirming that your malicious base image was used during the build process.
        - Run a container based on the newly built `amazon/aws-sam-cli-build-image-python3.9:x86_64` image:
          ```bash
          docker run --rm amazon/aws-sam-cli-build-image-python3.9:x86_64 /bin/sh -c "test -f /tmp/INJECTED && echo 'Image is compromised'"
          ```
        - If the output is `Image is compromised`, it further confirms that the malicious content from the base image persists in the final build image.
        - This demonstrates that disabling Docker Content Trust in `build_all_images.sh` allows for the incorporation of potentially malicious code from compromised base images into the AWS SAM CLI build images.