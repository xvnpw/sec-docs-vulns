- Vulnerability Name: Unpinned SAM CLI Version in Docker Images
- Description:
  - The `build_all_images.sh` script uses the `SAM_CLI_VERSION` environment variable to determine the version of the AWS SAM CLI installed in the Docker build images.
  - An attacker who can control this environment variable during the image build process can inject a malicious version of the SAM CLI into the Docker images.
  - Developers using these compromised Docker images will unknowingly use the malicious SAM CLI to build their serverless applications.
  - This could lead to the deployment of backdoored serverless applications.
- Impact:
  - Supply chain attack.
  - Developers using the compromised Docker images will unknowingly build and deploy serverless applications with a backdoored SAM CLI.
  - This could allow the attacker to gain unauthorized access to AWS accounts and resources, steal sensitive data, or disrupt application functionality.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
  - None. The script relies on the environment variable `SAM_CLI_VERSION` without any validation or pinning.
- Missing Mitigations:
  - Pinning SAM CLI version: Hardcode or retrieve the SAM CLI version from a trusted, internal source instead of relying solely on an environment variable.
  - Input validation: Validate the `SAM_CLI_VERSION` environment variable to ensure it conforms to expected version format and potentially check against a list of allowed versions.
  - Image signing and verification: Sign the Docker images after building them and encourage users to verify the signature before using the images.
  - Secure build environment: Ensure the environment where the build script is executed is secured and access is restricted to authorized personnel.
- Preconditions:
  - Attacker needs to gain control over the environment where `build_all_images.sh` is executed or influence the value of the `SAM_CLI_VERSION` environment variable. This could be achieved by compromising the CI/CD pipeline or a developer's local machine if they are building images locally.
- Source Code Analysis:
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
- Security Test Case:
  - Step 1: Setup - Access a machine where you can run the `build_all_images.sh` script and have Docker installed.
  - Step 2: Modify Environment - Before executing the script, set the `SAM_CLI_VERSION` environment variable to a malicious or controlled version. For example, to test control, set it to a specific older version of SAM CLI or a non-existent version: `export SAM_CLI_VERSION="99.99.99"`.
  - Step 3: Run Build Script - Execute the `build_all_images.sh` script.
  - Step 4: Verify Image - After the script completes (or fails with an error if using a non-existent version), inspect the Docker image. For example, if you targeted `Dockerfile-python3.9`, run a container from `amazon/aws-sam-cli-build-image-python3.9:x86_64`.
  - Step 5: Check SAM CLI Version - Inside the running container, check the installed SAM CLI version using `sam --version`.
  - Expected Result:
    - If you used a valid older version, `sam --version` should report that older version.
    - If you used `99.99.99` (or a non-existent version), the `docker build` command in `build_all_images.sh` should fail during the `pip install` step, indicating your control over the version. In a real attack with a malicious package, the installation would succeed, and `sam --version` would report the version of the malicious SAM CLI (although this is harder to demonstrate without creating a real malicious package).
  - This test case demonstrates that an attacker who can control the `SAM_CLI_VERSION` environment variable can influence the version of SAM CLI installed in the Docker images, confirming the vulnerability.