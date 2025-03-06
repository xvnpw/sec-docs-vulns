- Vulnerability Name: Docker Content Trust Disabled during image build
- Description: The `build-image-src/build_all_images.sh` script explicitly disables Docker Content Trust by setting `export DOCKER_CONTENT_TRUST=0`. This setting affects all subsequent Docker commands within the script, including the `docker build` commands used to create the SAM CLI build images. During the Docker image build process, the Dockerfiles might pull base images or other components from public registries. With Docker Content Trust disabled, these pulled images are not cryptographically verified.

  Step-by-step to trigger:
  1. An attacker compromises a public Docker registry (or performs a man-in-the-middle attack).
  2. The project's Dockerfiles (e.g., Dockerfile-python3.12) are configured to pull base images from this compromised public registry.
  3. A developer executes the `build-image-src/build_all_images.sh` script to build the SAM CLI build images.
  4. Due to `export DOCKER_CONTENT_TRUST=0`, the `docker build` commands pull base images without content verification.
  5. The compromised base image, containing malicious code, is included in the resulting SAM CLI build image.
  6. A developer uses this compromised SAM CLI build image to build their serverless application using `sam build --use-container`.
  7. During the build process, malicious code from the compromised base image is executed on the developer's machine.

- Impact: Arbitrary code execution on the developer's machine. If a compromised build image is used, malicious code embedded in the base image or pulled dependencies can be executed during the `sam build` process. This can lead to:
    - Data theft: Sensitive information from the developer's machine or build environment could be exfiltrated.
    - System compromise: The attacker could gain control of the developer's machine, install backdoors, or perform further malicious activities.
    - Supply chain contamination: Applications built using compromised build images could inadvertently include malicious components, propagating the vulnerability to deployment environments.

- Vulnerability Rank: High

- Currently Implemented Mitigations: None. The script explicitly disables Docker Content Trust.

- Missing Mitigations:
    - Enable Docker Content Trust: Remove `export DOCKER_CONTENT_TRUST=0` from the `build-image-src/build_all_images.sh` script or set it to `export DOCKER_CONTENT_TRUST=1`. This will ensure that Docker verifies the content and publisher of images pulled from registries that support content trust.
    - Use specific image digests instead of tags in Dockerfiles: Modify Dockerfiles to use image digests (e.g., `FROM public.ecr.aws/amazonlinux/amazonlinux:2@sha256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`) instead of tags. This ensures that the pulled base images are always the intended versions and are immutable, preventing tag mutation attacks.
    - Regularly scan build images for vulnerabilities: Implement a process to regularly scan the generated build images for known vulnerabilities using container image scanning tools. This helps identify and remediate vulnerabilities introduced through base images or dependencies.

- Preconditions:
    - An attacker must be able to compromise a public Docker registry or perform a man-in-the-middle attack to intercept image pulls.
    - The project's Dockerfiles must rely on pulling base images or components from public registries.
    - A developer must use the build images produced by the vulnerable build script to build their serverless applications.

- Source Code Analysis:
    1. File: `/code/build-image-src/build_all_images.sh`
    2. Line: `export DOCKER_CONTENT_TRUST=0`
    3. This line explicitly disables Docker Content Trust for all subsequent `docker` commands executed within the script.
    4. The script proceeds to build Docker images using commands like:
       ```sh
       docker build -f Dockerfile-python312 -t amazon/aws-sam-cli-build-image-python3.12:x86_64 --platform linux/amd64 --build-arg SAM_CLI_VERSION=$SAM_CLI_VERSION --build-arg AWS_CLI_ARCH=x86_64 --build-arg IMAGE_ARCH=x86_64 .
       ```
    5. The Dockerfiles (e.g., `Dockerfile-python312`) are not provided in the PROJECT FILES, but typically, such Dockerfiles start with a `FROM` instruction that pulls a base image from a registry. For example, a Python Dockerfile might start with `FROM public.ecr.aws/amazonlinux/amazonlinux:2`.
    6. With `DOCKER_CONTENT_TRUST=0`, when `docker build` executes, it will pull the base image specified in the `FROM` instruction without verifying its cryptographic signature.
    7. If an attacker compromises the public registry `public.ecr.aws` and replaces the `amazonlinux:2` image with a malicious one, or performs a MITM attack, the `docker build` command will unknowingly pull and use the malicious base image.
    8. The resulting `amazon/aws-sam-cli-build-image-python3.12:x86_64` image will be based on the compromised base image, potentially containing malicious code.
    9. When a developer uses this compromised build image with `sam build --use-container`, the malicious code from the base image can be executed within the container during the build process, and potentially escape to the host machine depending on the nature of the malicious code and container configurations.

- Security Test Case:
    1. Prerequisites:
        - Docker environment setup.
        - Access to modify and execute `build-image-src/build_all_images.sh`.
        - Ability to simulate a compromised Docker registry (e.g., using a local registry and DNS manipulation or a proxy).
    2. Setup a Malicious Registry (Simulated Compromise):
        - Configure a local Docker registry (e.g., using `docker run -d -p 5000:5000 registry:2`).
        - Identify a base image used in one of the Dockerfiles (e.g., `public.ecr.aws/amazonlinux/amazonlinux:2`).
        - Create a malicious Dockerfile that starts `FROM public.ecr.aws/amazonlinux/amazonlinux:2` and adds a malicious command, for example: `RUN touch /tmp/pwned`. Build this malicious image and tag it as `localhost:5000/amazonlinux:2`.
        - Push the malicious image to your local registry: `docker push localhost:5000/amazonlinux:2`.
        - Configure your system's DNS or `/etc/hosts` to resolve `public.ecr.aws` to `localhost:5000` to redirect image pull requests to your local malicious registry.
    3. Build a Build Image with the Vulnerable Script:
        - Modify `/code/build-image-src/build_all_images.sh` to only build the `amazon/aws-sam-cli-build-image-python3.12:x86_64` image to expedite testing. Comment out or remove other `docker build` commands.
        - Execute `build-image-src/build_all_images.sh` with `SAM_CLI_VERSION` set. This will build the Python 3.12 build image, which will now pull the malicious base image from your local registry instead of the intended public registry because of DNS redirection and Docker Content Trust being disabled.
    4. Use the Compromised Build Image:
        - Run a container using the newly built `amazon/aws-sam-cli-build-image-python3.12:x86_64` image:
          ```bash
          docker run -it --rm --name sam-build-test amazon/aws-sam-cli-build-image-python3.12:x86_64 /bin/bash
          ```
        - Inside the container, navigate to `/tmp` and check if the file `pwned` exists: `ls /tmp/pwned`. If the file `pwned` exists, it indicates that the malicious command from the compromised base image was executed during the build process of the build image itself.
        - To further test the impact during `sam build`, exit the container and mount a local SAM app directory:
          ```bash
          docker run -it --rm -v $(pwd)/tests/apps/python3.12/sam-test-app:/app --name sam-build-test amazon/aws-sam-cli-build-image-python3.12:x86_64 /bin/bash
          cd /app
          sam build --use-container
          ```
        - After `sam build` completes, check again on your host machine if the file `/tmp/pwned` was created within the container's filesystem or potentially escaped to the host if the malicious payload was designed to do so (depending on the payload, you might need to check within the container's filesystem).
    5. Verify Vulnerability:
        - If the file `/tmp/pwned` (or any other indicator of malicious activity defined in your malicious base image) is found after building the image or using it for `sam build`, it confirms that disabling Docker Content Trust allows execution of code from potentially compromised base images during the build process.
    6. Cleanup:
        - Remove the DNS redirection or `/etc/hosts` entry.
        - Stop and remove the local Docker registry container.
        - Remove the malicious Docker image from your local registry.
        - Remove the `amazon/aws-sam-cli-build-image-python3.12:x86_64` image built during the test if you want to restore your environment.

This test case demonstrates how disabling Docker Content Trust can lead to the execution of malicious code from a compromised base image within the build environment, highlighting the vulnerability.