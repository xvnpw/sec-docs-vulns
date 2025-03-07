- Vulnerability Name: Command Injection in Docker Build and Push Scripts via Image Name and Version
- Description:
    - The `build-docker.sh` and `push-docker.sh` scripts use environment variables like `IMAGE_NAME` and `VERSION` to construct Docker commands.
    - An attacker can potentially inject malicious commands by manipulating these environment variables.
    - For example, by setting `IMAGE_NAME` to a value like `"image; malicious_command"` or `VERSION` to `"version; malicious_command"`, the injected command could be executed during the build or push process.
    - This is because the script directly uses these variables in shell commands without proper sanitization or escaping.
- Impact:
    - Arbitrary command execution on the developer's machine.
    - An attacker could gain complete control over the developer's environment, steal credentials, or plant malware.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None. The scripts directly use environment variables in command execution without sanitization.
- Missing Mitigations:
    - Input sanitization and validation: Sanitize and validate the `IMAGE_NAME` and `VERSION` environment variables before using them in shell commands.
    - Use safe command construction methods: Instead of directly embedding variables in shell commands, use safer methods like parameterization or shell escaping to prevent command injection.
- Preconditions:
    - The attacker needs to be able to control the environment variables used by the `iotedgedev` tool. This could be achieved if the tool is used in an automated CI/CD pipeline where environment variables are dynamically set, or if a developer is tricked into running the tool with malicious environment variables set.
- Source Code Analysis:
    - File: `/code/docker/tool/build-docker.sh`
        ```sh
        export VERSION=$(cat ../../iotedgedev/__init__.py | grep '__version__' | awk '{print $3}' | sed "s;';;g")
        IMAGE_NAME="$1"
        PLATFORM="$2"
        ...
        docker build \
            -f Dockerfile \
            --build-arg IOTEDGEDEV_VERSION=$VERSION \
            -t $IMAGE_NAME:$VERSION-amd64 \
            ...
        ```
        - The `IMAGE_NAME` variable is directly taken from the first argument `$1` passed to the script. If this argument is influenced by an environment variable controlled by the attacker, it can lead to command injection.
        - The `VERSION` variable, while derived from `__init__.py`, is still used in command construction and could be indirectly influenced if the attacker can modify `__init__.py` or control the script execution environment.
    - File: `/code/docker/tool/push-docker.sh`
        ```sh
        IMAGE_NAME="iotedgedev"
        VERSION="$1"
        ...
        docker push $ACR_LOGIN_SERVER/public/iotedge/$IMAGE_NAME:$VERSION-amd64
        ```
        - Similar to `build-docker.sh`, the `VERSION` variable taken from the first argument `$1` and `IMAGE_NAME` are directly used in `docker push` command, making it vulnerable to command injection if these values are attacker-controlled.
- Security Test Case:
    - Precondition:
        - Attacker has ability to set environment variables before running `iotedgedev` commands.
    - Steps:
        1. Set the environment variable `IMAGE_NAME` to `"; touch vulnerable_build_docker_command_injection"`
        2. Navigate to the `/code/docker/tool/` directory in the project.
        3. Run the script: `build-docker.sh injected_image_name linux`
        4. Check if a file named `vulnerable_build_docker_command_injection` is created in the `/code/docker/tool/` directory. If the file is created, it indicates successful command injection.
        5. Set the environment variable `VERSION` to `"; touch vulnerable_push_docker_command_injection"`
        6. Navigate to the `/code/docker/tool/` directory in the project.
        7. Run the script: `push-docker.sh injected_version`
        8. Check if a file named `vulnerable_push_docker_command_injection` is created in the `/code/docker/tool/` directory. If the file is created, it indicates successful command injection.