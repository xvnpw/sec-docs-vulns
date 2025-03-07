- Vulnerability name: Hardcoded Subscription ID in `images/images.yml`
- Description: The `images/images.yml` file contains a hardcoded Azure Subscription ID. If an attacker gains unauthorized read access to the repository, they can identify the target Azure subscription used for image builds. This information can be used in combination with compromised `AZURE_CREDENTIALS` to target specific Azure resources or plan further attacks.
- Impact: Information Disclosure. The hardcoded subscription ID reveals the target Azure subscription, potentially aiding attackers in reconnaissance and targeted attacks if `AZURE_CREDENTIALS` is compromised.
- Vulnerability rank: Medium
- Currently implemented mitigations: None.
- Missing mitigations: Avoid hardcoding sensitive information like subscription IDs in configuration files. Use environment variables or dynamically retrieve the subscription ID from the Azure context during runtime.
- Preconditions:
    - An attacker gains unauthorized read access to the GitHub repository. This could be due to compromised GitHub account, misconfigured repository permissions, or other access control vulnerabilities.
- Source code analysis:
    - File: `/code/images/images.yml`
    ```yaml
    subscription: 00000000-0000-0000-0000-000000000000
    ```
    The `subscription` property is hardcoded with a placeholder value in the `images.yml` file. This file is intended to store common configuration properties for images.
    - File: `/code/builder/image.py`
    ```python
    def get_common() -> dict:
        '''Get the common properties from the images.yaml file in the root of the images directory'''
        images_path = syaml.get_file(images_root, 'images', required=False)

        if images_path is None:
            return {}

        common = syaml.parse(images_path, allowed=COMMON_ALLOWED_PROPERTIES)
        # ...
        return common

    def get(image_name, gallery, common=None, suffix=None, ensure_azure=False) -> dict:
        '''Get the image properties from the image.yaml file optionally supplementing with info from azure'''
        image = _get(image_name, gallery, common)
        # ...
        if common:  # merge common properties into image properties
            temp = common.copy()
            temp.update(image)
            image = temp.copy()
        # ...
        return image
    ```
    The `get_common` function in `image.py` parses the `images.yml` file and the `get` function merges these common properties into individual image configurations. This means the hardcoded subscription ID from `images.yml` will be used unless overridden in individual `image.yml` files or dynamically set during runtime.
- Security test case:
    1. Fork the repository to gain read access to the files.
    2. Navigate to the `/code/images/images.yml` file in the forked repository.
    3. Inspect the content of the file and locate the `subscription` property.
    4. Observe the hardcoded Azure Subscription ID value. This confirms the information disclosure vulnerability.

- Vulnerability name: Potential Secret Exposure in Builder Logs
- Description: The `AZURE_CREDENTIALS` secret, used to authenticate with Azure, might be inadvertently exposed in the builder logs. This can occur if logging is overly verbose, debug mode is enabled, or if error messages include sensitive environment variables or configuration details. If an attacker gains access to these logs, they could potentially extract the `AZURE_CREDENTIALS` secret and gain unauthorized access to the Azure subscription.
- Impact: Credential Leakage. Exposure of `AZURE_CREDENTIALS` secret would grant an attacker full control over the Azure resources managed by the Service Principal, leading to significant security breaches, data exfiltration, resource manipulation, and potential financial impact.
- Vulnerability rank: High
- Currently implemented mitigations: None evident from the provided code. The logging is configured in `builder/loggers.py`, but there is no mechanism to redact or prevent logging of sensitive information.
- Missing mitigations: Implement secret redaction in the logging mechanism to automatically sanitize logs by masking or removing sensitive data like credentials before they are written to logs.  Review and harden all scripts, especially Packer templates and provisioner scripts (not provided in project files), to ensure they do not inadvertently log sensitive information. Implement secure handling of environment variables to prevent accidental logging of secrets.
- Preconditions:
    - Verbose or debug logging is enabled in the builder environment.
    - Errors occur during the image build process, potentially leading to the logging of debug information or environment variables.
    - An attacker gains unauthorized access to the builder logs. This could be through compromised CI/CD pipeline access, misconfigured log storage, or other log management vulnerabilities.
- Source code analysis:
    - File: `/code/builder/loggers.py`
    ```python
    import logging
    import os
    from datetime import datetime, timezone
    from pathlib import Path

    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')

    # indicates if the script is running in the docker container
    in_builder = os.environ.get('ACI_IMAGE_BUILDER', False)

    repo = Path('/mnt/repo') if in_builder else Path(__file__).resolve().parent.parent
    storage = Path('/mnt/storage') if in_builder else repo / '.local' / 'storage'

    log_file = storage / f'log_{timestamp}.txt'


    def getLogger(name, level=logging.DEBUG):
        logger = logging.getLogger(name)
        logger.setLevel(level=level)

        formatter = logging.Formatter('{asctime} [{name:^8}] {levelname:<8}: {message}', datefmt='%m/%d/%Y %I:%M:%S %p', style='{',)

        ch = logging.StreamHandler()
        ch.setLevel(level=level)
        ch.setFormatter(formatter)

        logger.addHandler(ch)

        if in_builder and os.path.isdir(storage):
            fh = logging.FileHandler(log_file)
            fh.setLevel(level=level)
            fh.setFormatter(formatter)

            logger.addHandler(fh)

        return logger
    ```
    The `loggers.py` file sets up basic logging using Python's `logging` module. It defines a formatter and handlers for both stream output and file output (when running in the builder container). However, it lacks any mechanism for secret redaction or filtering of sensitive information. If any part of the code or Packer configurations were to log the `AZURE_CREDENTIALS` or related environment variables, they would be captured in the logs without any protection.
    - Review of other scripts (`azure.py`, `builder.py`, `build.py`, `packer.py`): While the provided code doesn't explicitly log the secrets, the risk exists if these scripts or the Packer templates (not provided) were to inadvertently log environment variables or sensitive configuration data during error handling, debugging, or normal operation.
- Security test case:
    1. Modify the `/code/builder/azure.py` file to intentionally log the `AZURE_CREDENTIALS` secret. For example, add the following line within the `cli` function before the `subprocess.run` call:
    ```python
    log.debug(f"Environment variables: {os.environ}")
    ```
    This will log all environment variables, including potentially `AZURE_CREDENTIALS` if it's passed as an environment variable to the builder container.
    2. Trigger a build workflow by modifying a file in the `/images` or `/scripts` directory to initiate a new build.
    3. Access the logs of the GitHub Actions workflow run that performed the build.
    4. Examine the logs for the "Environment variables:" entry added in step 1.
    5. Verify if the `AZURE_CREDENTIALS` secret (or parts of it, depending on how it's structured) is present in the logged environment variables. If the secret is found in the logs, it confirms the vulnerability.