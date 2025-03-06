## Vulnerability List

- Vulnerability Name: Malicious Package Injection via Dockerfile Modification

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

- Vulnerability Rank: Critical

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
    5. **Verify Vulnerability**:
        - Inside the running container, check for the backdoor file:
        ```bash
        ls /tmp/backdoor.txt
        ```
        - If `backdoor.txt` exists in `/tmp`, the vulnerability is successfully triggered.

This vulnerability allows an attacker to compromise the security of user-built deep learning containers by simply tricking them into adding a malicious package to their Dockerfile.