### Vulnerabilities Report

#### Unpinned SAM CLI Version in Docker Images
- **Description:**
  - The `build_all_images.sh` script uses the `SAM_CLI_VERSION` environment variable to determine the version of the AWS SAM CLI installed in the Docker build images.
  - An attacker who can control this environment variable during the image build process can inject a malicious version of the SAM CLI into the Docker images.
  - Developers using these compromised Docker images will unknowingly use the malicious SAM CLI to build their serverless applications.
  - This could lead to the deployment of backdoored serverless applications.
- **Impact:**
  - Supply chain attack.
  - Developers using the compromised Docker images will unknowingly build and deploy serverless applications with a backdoored SAM CLI.
  - This could allow the attacker to gain unauthorized access to AWS accounts and resources, steal sensitive data, or disrupt application functionality.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
  - None. The script relies on the environment variable `SAM_CLI_VERSION` without any validation or pinning.
- **Missing Mitigations:**
  - Pinning SAM CLI version: Hardcode or retrieve the SAM CLI version from a trusted, internal source instead of relying solely on an environment variable.
  - Input validation: Validate the `SAM_CLI_VERSION` environment variable to ensure it conforms to expected version format and potentially check against a list of allowed versions.
  - Image signing and verification: Sign the Docker images after building them and encourage users to verify the signature before using the images.
  - Secure build environment: Ensure the environment where the build script is executed is secured and access is restricted to authorized personnel.
- **Preconditions:**
  - Attacker needs to gain control over the environment where `build_all_images.sh` is executed or influence the value of the `SAM_CLI_VERSION` environment variable. This could be achieved by compromising the CI/CD pipeline or a developer's local machine if they are building images locally.
- **Source Code Analysis:**
  - File: `/code/build-image-src/build_all_images.sh`
    - The script starts by checking if `SAM_CLI_VERSION` is set:
      ```sh
      if [ -z ${SAM_CLI_VERSION+x} ];
      then
          echo "Must set SAM_CLI_VERSION to run this script."
          exit 1;
      else
          echo "SAM CLI VERSION: $SAM_CLI_VERSION";
      fi
      ```
    - The script then uses this `$SAM_CLI_VERSION` in multiple `docker build` commands as a build argument:
      ```sh
      docker build -f Dockerfile-dotnet6 -t amazon/aws-sam-cli-build-image-dotnet6:x86_64 --platform linux/amd64 --build-arg SAM_CLI_VERSION=$SAM_CLI_VERSION ... .
      ```
  - Dockerfiles (e.g., `Dockerfile-dotnet6`, not provided in PROJECT FILES, but assumed to be present and used by `build_all_images.sh`):
    - Inside the Dockerfiles, the `SAM_CLI_VERSION` build argument is used to install the SAM CLI using `pip install aws-sam-cli==$SAM_CLI_VERSION`. Example Dockerfile instruction:
      ```dockerfile
      RUN pip install --no-cache-dir --upgrade "aws-sam-cli==${SAM_CLI_VERSION}"
      ```
    - This mechanism allows the version of SAM CLI to be dictated by the `SAM_CLI_VERSION` environment variable at build time.
- **Security Test Case:**
  - Step 1: Setup - Access a machine where you can run the `build_all_images.sh` script and have Docker installed.
  - Step 2: Modify Environment - Before executing the script, set the `SAM_CLI_VERSION` environment variable to a malicious or controlled version. For example, to test control, set it to a specific older version of SAM CLI or a non-existent version: `export SAM_CLI_VERSION="99.99.99"`.
  - Step 3: Run Build Script - Execute the `build_all_images.sh` script.
  - Step 4: Verify Image - After the script completes (or fails with an error if using a non-existent version), inspect the Docker image. For example, if you targeted `Dockerfile-python3.9`, run a container from `amazon/aws-sam-cli-build-image-python3.9:x86_64`.
  - Step 5: Check SAM CLI Version - Inside the running container, check the installed SAM CLI version using `sam --version`.
  - Expected Result:
    - If you used a valid older version, `sam --version` should report that older version.
    - If you used `99.99.99` (or a non-existent version), the `docker build` command in `build_all_images.sh` should fail during the `pip install` step, indicating your control over the version. In a real attack with a malicious package, the installation would succeed, and `sam --version` would report the version of the malicious SAM CLI (although this is harder to demonstrate without creating a real malicious package).
  - This test case demonstrates that an attacker who can control the `SAM_CLI_VERSION` environment variable can influence the version of SAM CLI installed in the Docker images, confirming the vulnerability.

#### Docker Content Trust Disabled
- **Description:**
    - The `build_all_images.sh` script explicitly disables Docker Content Trust by setting `export DOCKER_CONTENT_TRUST=0`.
    - Docker Content Trust is a security feature that uses digital signatures to ensure the integrity and publisher authenticity of container images. When enabled, Docker verifies the signature of an image before pulling and running it, ensuring that the image has not been tampered with and comes from a trusted publisher.
    - By disabling Docker Content Trust, the script allows Docker to pull images from public registries without signature verification.
    - If a public registry is compromised or an attacker performs a man-in-the-middle attack, malicious images could be pulled and used as base images for building the AWS SAM CLI build images.
    - This can lead to the injection of malicious code into the AWS SAM CLI build images, which are then used by developers to build serverless applications.

  - Step-by-step to trigger:
  1. An attacker compromises a public Docker registry (or performs a man-in-the-middle attack).
  2. The project's Dockerfiles (e.g., Dockerfile-python3.12) are configured to pull base images from this compromised public registry.
  3. A developer executes the `build-image-src/build_all_images.sh` script to build the SAM CLI build images.
  4. Due to `export DOCKER_CONTENT_TRUST=0`, the `docker build` commands pull base images without content verification.
  5. The compromised base image, containing malicious code, is included in the resulting SAM CLI build image.
  6. A developer uses this compromised SAM CLI build image to build their serverless application using `sam build --use-container`.
  7. During the build process, malicious code from the compromised base image is executed on the developer's machine.
- **Impact:**
    - **Supply Chain Attack:** If a malicious base image is used due to disabled content trust, all AWS SAM CLI build images built using this compromised base image will also be compromised.
    - **Code Injection:** Developers using these compromised build images will unknowingly incorporate malicious code into their serverless applications during the build process.
    - **Data Breach and System Compromise:** The injected malicious code in serverless applications could lead to various security breaches, including data exfiltration, credential theft, unauthorized access to AWS resources, and complete compromise of the deployed serverless application and potentially the underlying infrastructure.
    - Arbitrary code execution on the developer's machine. If a compromised build image is used, malicious code embedded in the base image or pulled dependencies can be executed during the `sam build` process. This can lead to:
        - Data theft: Sensitive information from the developer's machine or build environment could be exfiltrated.
        - System compromise: The attacker could gain control of the developer's machine, install backdoors, or perform further malicious activities.
        - Supply chain contamination: Applications built using compromised build images could inadvertently include malicious components, propagating the vulnerability to deployment environments.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - None. The project explicitly disables Docker Content Trust in the `build_all_images.sh` script.
- **Missing Mitigations:**
    - Enable Docker Content Trust by Default: The `build_all_images.sh` script should not disable Docker Content Trust. It should be either enabled by default or the script should be modified to respect the user's Docker Content Trust settings.
    - Documentation and User Awareness:**  The project documentation should clearly explain the security implications of disabling Docker Content Trust and strongly advise users against disabling it, especially when building and using container images.  It should also explain how to enable and use Docker Content Trust.
    - Base Image Verification: While Content Trust is the primary mitigation, additional measures could include:
        - Using base images from official and verified publishers.
        - Regularly scanning base images for known vulnerabilities.
        - Potentially mirroring base images in a private registry with Content Trust enabled for internal use, adding another layer of control.
    - Use specific image digests instead of tags in Dockerfiles: Modify Dockerfiles to use image digests (e.g., `FROM public.ecr.aws/amazonlinux/amazonlinux:2@sha256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`) instead of tags. This ensures that the pulled base images are always the intended versions and are immutable, preventing tag mutation attacks.
    - Regularly scan build images for vulnerabilities: Implement a process to regularly scan the generated build images for known vulnerabilities using container image scanning tools. This helps identify and remediate vulnerabilities introduced through base images or dependencies.
- **Preconditions:**
    - An attacker compromises a public Docker registry or performs a man-in-the-middle attack to replace legitimate base images with malicious ones.
    - The `build_all_images.sh` script is executed, or developers manually build images using Dockerfiles from this project while Docker Content Trust is disabled (as suggested by the script).
    - Developers use the resulting compromised build images to build their serverless applications.
    - An attacker must be able to compromise a public Docker registry or perform a man-in-the-middle attack to intercept image pulls.
    - The project's Dockerfiles must rely on pulling base images or components from public registries.
    - A developer must use the build images produced by the vulnerable build script to build their serverless applications.
- **Source Code Analysis:**
    - File: `/code/build-image-src/build_all_images.sh`
    - Line:
        ```sh
        export DOCKER_CONTENT_TRUST=0
        ```
    - This line sets the environment variable `DOCKER_CONTENT_TRUST` to `0`.
    - When `DOCKER_CONTENT_TRUST` is set to `0`, Docker client disables content trust verification for image pull and push operations.
    - Consequently, when the script executes `docker build` commands to build various AWS SAM CLI build images, the base images specified in the Dockerfiles (e.g., `amazonlinux:2023`, `public.ecr.aws/docker/library/amazonlinux:2023`, `ubuntu:20.04`, etc. within the various `Dockerfile-*`) are pulled without any cryptographic signature verification.
    - This opens the door for using potentially compromised base images if an attacker manages to inject malicious images into the public registries under the same image names and tags.
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
- **Security Test Case:**
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