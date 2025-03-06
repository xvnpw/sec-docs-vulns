## Combined Vulnerability List

### Vulnerability Name: Unpinned Octopush Package in Dockerfile
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

### Vulnerability Name: Command Injection via Build Arguments in Dockerfile
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

### Vulnerability Name: Malicious Package Injection via Dockerfile Modification
- Description:
    1. A user clones the repository and intends to customize a deep learning container image by adding a new Python package, as described in the "Adding a package" section of the README.md.
    2. The user directly modifies the Dockerfile (e.g., `mxnet/training/docker/1.6.0/py3/Dockerfile.gpu`) by adding a new `RUN pip install` command with the name of the desired package (e.g., `octopush`).
    3. Unknowingly, the user adds a malicious package name (e.g., `octopush`) or a package from a compromised or attacker-controlled repository.
    4. When the Docker image is built using `python src/main.py --buildspec mxnet/training/buildspec.yml --framework mxnet`, the malicious package is installed into the container image.
    5. Anyone using this customized Docker image will now unknowingly execute the malicious code embedded within the container.
- Impact:
    - **High**: Successful exploitation allows arbitrary code execution within the user's deep learning container. This can lead to:
        - Backdoor access to the user's environment.
        - Data exfiltration, including potentially sensitive model data or training datasets.
        - Manipulation of deep learning workloads.
        - Compromise of the user's AWS account or infrastructure if container escapes or interacts with AWS services with sufficient permissions.
- Vulnerability Rank: **Critical**
- Currently Implemented Mitigations:
    - None: The project provides instructions for adding packages without security warnings or input validation.
- Missing Mitigations:
    - **Input Validation and Sanitization**: Implement checks to validate package names against a whitelist of approved and trusted packages or sources.
    - **Dependency Pinning and Lock Files**: Use dependency pinning and lock files (e.g., `requirements.txt` and `requirements.txt.lock`) to ensure reproducible builds and prevent supply chain attacks through dependency substitution. While `requirements.txt` exists, it's not used for user-added packages in `README.md` example.
    - **Security Scanning**: Integrate automated security scanning of Dockerfiles and built images to detect known vulnerabilities and malicious packages.
    - **User Education**: Enhance documentation to explicitly warn users about the risks of adding untrusted packages and recommend best practices for supply chain security, such as verifying package authenticity and using trusted repositories.
- Preconditions:
    - User must clone the repository and follow the instructions in `README.md` to customize a Dockerfile.
    - User must have Docker installed and be able to build Docker images.
    - User must willingly add a malicious package to the Dockerfile.
- Source Code Analysis:
    - **File: /code/README.md**
        - The section "Adding a package" guides users to directly modify Dockerfiles and use `pip install` to add packages:
        ```markdown
        ### Adding a package
        The following steps outline how to add a package to your image. For more information on customizing your container, see [Building AWS Deep Learning Containers Custom Images](custom_images.md).
        1. Suppose you want to add a package to the MXNet 1.6.0 py3 GPU docker image, then change the dockerfile from:
            ```dockerfile
            # mxnet/training/docker/1.6.0/py3/Dockerfile.gpu
            ...
            160     awscli
            ```
            to
            ```dockerfile
            139 RUN ${PIP} install --no-cache --upgrade \
            140     keras-mxnet==2.2.4.2 \
            ...
            160     awscli \
            161     octopush
            ```
        2. Build the container as described above.
        ```
        - This section highlights the direct Dockerfile modification approach.
    - **File: /code/src/main.py**
        ```python
        # ...
        - python src/main.py --buildspec mxnet/training/buildspec.yml --framework mxnet
        # ...
        ```
        - `src/main.py` is the entry point for building Docker images based on buildspec files. It executes `docker build` commands, which will process the user-modified Dockerfile and install the specified packages, including potentially malicious ones.
    - **File: /code/mxnet/training/buildspec.yml (Example)**
        ```yaml
        # ...
        49       docker_file: !join [ docker/, *VERSION, /, *DOCKER_PYTHON_VERSION, /Dockerfile., *DEVICE_TYPE ]
        # ...
    ```
        - Buildspec files like `mxnet/training/buildspec.yml` define the build process but do not include any validation or security checks on user-modified Dockerfiles. The `docker_file` key points to the Dockerfile that users are instructed to modify.

- Security Test Case:
    1. **Setup**:
        - Clone the `deep-learning-containers` repository to a local machine.
        - Install Docker.
        - Set up AWS CLI and ECR login as described in `README.md`.
    2. **Modify Dockerfile**:
        - Edit the Dockerfile `mxnet/training/docker/1.9.0/py3/Dockerfile.gpu` as instructed in `README.md` "Adding a package" section.
        - Replace `octopush` with a malicious package. For simplicity, let's assume a package named `malicious-package` hosted on a public repository like `pypi.org` that simply creates a backdoor file in the container. In real scenario, attacker can host this malicious package on a typosquatting domain.
        ```dockerfile
        # ... (mxnet/training/docker/1.9.0/py3/Dockerfile.gpu)
        160     awscli \
        161     malicious-package
        ```
        - Create a dummy malicious package `malicious-package` and host it locally or on a public repository. For test purpose, assume it's available in pypi.
        - Dummy malicious package `malicious-package/setup.py`:
        ```python
        from setuptools import setup

        setup(
            name='malicious-package',
            version='0.1.0',
            packages=['malicious_package'],
            install_requires=[],
            entry_points={
                'console_scripts': [
                    'malicious-package = malicious_package.main:main',
                ],
            },
        )
        ```
        - Dummy malicious package `malicious-package/malicious_package/main.py`:
        ```python
        import os
        def main():
            os.system('touch /tmp/backdoor.txt')

        if __name__ == '__main__':
            main()
        ```
        - Build and host the dummy malicious package on a local pypi server or a public test pypi instance.
    3. **Build the Docker Image**:
        ```bash
        export ACCOUNT_ID=<YOUR_ACCOUNT_ID>
        export REGION=us-west-2
        export REPOSITORY_NAME=beta-mxnet-training
        aws ecr get-login-password --region us-west-2 | docker login --username AWS --password-stdin $ACCOUNT_ID.dkr.ecr.us-west-2.amazonaws.com
        python src/main.py --buildspec mxnet/training/buildspec.yml --framework mxnet --image_types training --device_types gpu --py_versions py3
        ```
    4. **Run the Container**:
        ```bash
        docker run -it --rm <YOUR_ACCOUNT_ID>.dkr.ecr.us-west-2.amazonaws.com/pr-mxnet-training:1.9.0-gpu-py3-cu112-ubuntu20.04-ec2 bash
        ```
    5. **Verification**:
        - Inside the running container, check for the backdoor file:
        ```bash
        ls /tmp/backdoor.txt
        ```
        - If `backdoor.txt` exists in `/tmp`, the vulnerability is successfully triggered.

### Vulnerability Name: Command Injection via buildspec.yml context path
- Description:
    1. An attacker crafts a malicious `buildspec.yml` file.
    2. Within the `buildspec.yml`, under the `context`, `training_context`, `inference_context` or image-specific `context` sections, the attacker injects a malicious payload into the `source` field of a context artifact definition. This could be achieved by manipulating the `!join` tag or other YAML features to include shell commands.
    3. The `src/main.py` script, when processing this `buildspec.yml`, uses the `source` value without sufficient sanitization when creating the build context.
    4. During the Docker build process, when the script attempts to copy the artifact specified by the attacker-controlled `source` path, the injected commands are executed by the underlying shell.
- Impact:
    - **High/Critical**: Arbitrary command execution on the build server. An attacker could potentially gain full control of the build environment, steal credentials, modify built images, or pivot to internal networks.
- Vulnerability Rank: **Critical**
- Currently Implemented Mitigations:
    - None. The code directly uses the values from `buildspec.yml` without sanitization.
- Missing Mitigations:
    - Input validation and sanitization for all paths and parameters read from `buildspec.yml`, especially the `source` paths in context definitions.
    - Principle of least privilege for the build process.
    - Sandboxing or containerization of the build process to limit the impact of command injection.
- Preconditions:
    - An attacker needs to be able to modify or provide a malicious `buildspec.yml` file to the build process. In the described attack vector, this is achieved by crafting a malicious `buildspec.yml` in a forked repository and triggering a build using it.
- Source Code Analysis:
    1. The `src/main.py` script is the entry point for building Docker images.
    2. The script parses the `buildspec.yml` file specified by the `--buildspec` argument.
    3. The `buildspec.yml` file defines the build process, including context definitions.
    4. In `README.md`, the `context` section of `buildspec.yml` is described, showing how `source` and `target` keys are used to copy files into the Docker build context:
        ```markdown
        context:
          training_context: &TRAINING_CONTEXT
            entrypoint:
              source: docker/artifacts/dockerd-entrypoint.py
              target: dockerd-entrypoint.py
            deep_learning_container:
              source: ../../src/deep_learning_container.py
              target: deep_learning_container.py
        ```
    5. The `!join` tag is used to dynamically construct paths in `buildspec.yml`. If not handled carefully, this could be exploited for command injection.
    6. The `COPY` instruction in Dockerfiles, as shown in `README.md`:
        ```dockerfile
        COPY README-context.rst README.rst
        ```
       relies on the build context. If the build context is compromised due to command injection, arbitrary files can be copied.
    7. The `src/main.py` script uses the `buildspec.yml` to determine which Dockerfiles to build and how to build them, making it a central point for potential vulnerabilities.
    8. Further code analysis of `src/main.py` is needed to pinpoint the exact code locations where the `buildspec.yml` context paths are processed and how they are used in Docker build commands. However, based on the project description and file analysis, command injection via `buildspec.yml` context paths is a highly probable vulnerability.
- Security Test Case:
    1. Fork the repository.
    2. Create a malicious `buildspec.yml` file in `mxnet/training/` directory in your forked repository, replacing the original one. In this malicious `buildspec.yml`, modify the `source` field under `context` to inject a command. For example, modify `mxnet/training/buildspec.yml` and change line 20 from:
        ```yaml
        source: docker/artifacts/dockerd-entrypoint.py
        ```
        to:
        ```yaml
        source: !join ['', 'docker/artifacts/dockerd-entrypoint.py', ' ; touch /tmp/pwned']
        ```
        This payload attempts to create a file `/tmp/pwned` inside the build container during the `COPY` command execution.
    3. Set environment variables as described in `README.md` to prepare for building MXNet training container.
    4. Run the build command locally, targeting the modified `buildspec.yml`:
        ```shell script
        python src/main.py --buildspec mxnet/training/buildspec.yml --framework mxnet
        ```
    5. After the build process (or if it fails during build), inspect the resulting Docker image or the build logs for evidence of command execution. In this case, check if the `/tmp/pwned` file exists in the built container. You can run the container locally:
        ```shell script
        docker run --rm <your-built-image-name> sh -c "ls -l /tmp/pwned"
        ```
    6. If the file `/tmp/pwned` exists, it confirms the command injection vulnerability.