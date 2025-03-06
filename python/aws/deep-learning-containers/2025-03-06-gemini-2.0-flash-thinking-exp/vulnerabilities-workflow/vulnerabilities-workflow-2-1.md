- Vulnerability Name: **Unpinned Octopush Package in Dockerfile**
- Description:
    1. An attacker identifies that the `octopush` Python package in `mxnet/training/docker/1.6.0/py3/Dockerfile.gpu` Dockerfile is not version pinned.
    2. The attacker then compromises the PyPI repository or performs a dependency confusion attack to introduce a malicious version of the `octopush` package.
    3. When a user builds the Docker image using this Dockerfile, `pip install` fetches the latest version of `octopush`, which now includes the attacker's malicious code.
    4. The Docker image is built with the compromised `octopush` package.
    5. Users deploying containers from this image unknowingly deploy a container with the backdoor.
- Impact:
    - **High**: Successful exploitation allows arbitrary code execution within the Docker container. This could lead to data exfiltration, credential compromise, or complete control over the containerized environment.
- Vulnerability Rank: **High**
- Currently Implemented Mitigations:
    - None.
- Missing Mitigations:
    - **Pinning package versions**: Specify exact versions for all Python packages in `requirements.txt` files and Dockerfiles to ensure consistent and secure builds.
- Preconditions:
    - Public availability of the Dockerfile `mxnet/training/docker/1.6.0/py3/Dockerfile.gpu`.
    - Attacker's ability to compromise the PyPI repository or perform a dependency confusion attack for the `octopush` package.
- Source Code Analysis:
    - File: `/code/mxnet/training/docker/1.6.0/py3/Dockerfile.gpu`
    ```dockerfile
    # mxnet/training/docker/1.6.0/py3/Dockerfile.gpu
    139 RUN ${PIP} install --no-cache --upgrade \
    140     keras-mxnet==2.2.4.2 \
    ...........................
    159     ${MX_URL} \
    160     awscli \
    161     octopush # <----- Unpinned package
    ```
    - Line 161 in `mxnet/training/docker/1.6.0/py3/Dockerfile.gpu` adds the `octopush` package without specifying a version. This makes the build vulnerable to malicious packages if they become available under the same name on PyPI.
- Security Test Case:
    1. **Setup**:
        - Create a mock PyPI server hosting a malicious `octopush` package.
        - Modify the build environment to point to this mock PyPI server (e.g., using `--index-url` for `pip`).
        - Ensure the environment mimics a typical user building a Docker image from the provided Dockerfile.
    2. **Execution**:
        - Build the Docker image using the modified `mxnet/training/docker/1.6.0/py3/Dockerfile.gpu` and the mock PyPI server.
        ```bash
        docker build -t vulnerable-mxnet-gpu -f mxnet/training/docker/1.6.0/py3/Dockerfile.gpu --build-arg PIP_INDEX_URL="<mock_pypi_url>" .
        ```
        - Run the built Docker image.
        ```bash
        docker run -it vulnerable-mxnet-gpu bash
        ```
        - Inside the container, attempt to import the `octopush` package and execute a function from the malicious package that demonstrates code execution (e.g., writing to a file in `/tmp`).
        ```python
        python -c "import octopush; octopush.trigger_malicious_action()"
        ```
    3. **Verification**:
        - Verify that the malicious action defined in the mock `octopush` package is executed within the container, confirming code injection. For example, check if the file in `/tmp` was created.

- Vulnerability Name: **Command Injection via Build Arguments in Dockerfile**
- Description:
    1. An attacker identifies that the `MX_URL` build argument in Dockerfiles like `mxnet/training/docker/1.6.0/py3/Dockerfile.gpu` is used in a `RUN` command with shell expansion.
    2. The attacker submits a pull request modifying `mxnet/training/buildspec.yml` to inject a malicious payload into the `MX_URL` build argument. For example:
        ```yaml
        images:
          BuildEC2MXNetGPUTrainPy3DockerImage:
            build: &MXNET_GPU_TRAINING_PY3 false
            ...
            build_args:
              MX_URL: "https://example.com/mxnet-1.6.0.tar.gz; malicious_command"
        ```
    3. When the build process executes `RUN ${MX_URL} \`, the malicious command after `;` gets executed due to shell expansion.
    4. The attacker's malicious command is executed on the build server.
- Impact:
    - **High**: Successful command injection allows arbitrary code execution on the build server. This could lead to compromising build infrastructure, leaking secrets, or modifying build artifacts.
- Vulnerability Rank: **High**
- Currently Implemented Mitigations:
    - None.
- Missing Mitigations:
    - **Avoid shell expansion for URLs**: Use `COPY --from=...` or `ADD --from=...` with URLs instead of `RUN wget ... && RUN ...`. If `RUN` is necessary, use `curl` with `--url` and `--output` options and avoid shell expansion directly with variables containing URLs.
    - **Input validation**: Validate and sanitize build arguments in build scripts to prevent injection of malicious commands.
- Preconditions:
    - Ability to submit pull requests to the repository.
    - Build process uses shell expansion on build arguments within Dockerfiles.
- Source Code Analysis:
    - File: `/code/mxnet/training/docker/1.6.0/py3/Dockerfile.gpu`
    ```dockerfile
    # mxnet/training/docker/1.6.0/py3/Dockerfile.gpu
    139 RUN ${PIP} install --no-cache --upgrade \
    140     keras-mxnet==2.2.4.2 \
    ...........................
    159     ${MX_URL} \ # <----- Vulnerable line
    160     awscli \
    161     octopush
    ```
    - Line 159 uses `${MX_URL}` directly within a `RUN` command, allowing for command injection if `MX_URL` is maliciously crafted.
    - File: `/code/mxnet/training/buildspec.yml`
    ```yaml
    # mxnet/training/buildspec.yml
    41   images:
    42     BuildMXNetCPUTrainPy3DockerImage:
    43       <<: *TRAINING_REPOSITORY
             ...................
    47       build_args:
    48         MX_URL: &MX_URL https://dist.mxnet.io/python/wheel/cu112/mxnet_cu112-1.9.1-py3-none-manylinux2014_x86_64.whl # <----- MX_URL defined here
    ```
    - `MX_URL` is defined in `buildspec.yml`, and could be modified via a pull request.
- Security Test Case:
    1. **Setup**:
        - No special setup is needed beyond having the project repository cloned and Docker installed.
    2. **Execution**:
        - Modify the `mxnet/training/buildspec.yml` file to inject a malicious command into `MX_URL`:
        ```yaml
        # mxnet/training/buildspec.yml
        47       build_args:
        48         MX_URL: &MX_URL "https://example.com/mxnet-1.6.0.tar.gz; touch /tmp/vulnerable"
        ```
        - Build the Docker image using the modified `buildspec.yml`:
        ```bash
        python src/main.py --buildspec mxnet/training/buildspec.yml --framework mxnet --image_types training --device_types cpu --py_versions py3
        ```
    3. **Verification**:
        - After the build process completes, run a container based on the built image and check if the `/tmp/vulnerable` file exists inside the container.
        ```bash
        docker run --rm beta-mxnet-training:1.9.0-cpu-py3-ubuntu20.04-ec2 sh -c "ls /tmp/vulnerable"
        ```
        - If the file `/tmp/vulnerable` exists, it confirms that the command injection was successful during the Docker image build.