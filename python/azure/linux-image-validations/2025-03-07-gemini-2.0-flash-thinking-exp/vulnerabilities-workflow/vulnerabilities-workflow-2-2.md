### Vulnerability List

- Vulnerability Name: Arbitrary Code Execution via Malicious Archive
- Description:
    - The `validate_upload.sh` script is designed to be uploaded and executed on the Azure validation VM.
    - The script unpacks the `validator.tar.gz` archive, which is expected to be placed in the same directory as the script.
    - The script then executes `validate.py` script from the unpacked archive with root privileges using `sudo`.
    - If an attacker can replace the legitimate `validator.tar.gz` archive with a malicious one, they can inject arbitrary code.
    - The malicious archive can contain a modified `validate.py` or other malicious scripts.
    - When `validate_upload.sh` unpacks and executes the contents, the attacker's malicious code will run with root privileges, leading to full system compromise of the validation VM.
- Impact: Critical. Arbitrary code execution with root privileges on the validation VM. This allows a complete compromise of the validation environment, potentially leading to data exfiltration, further attacks on Azure infrastructure, or use of the compromised VM for malicious purposes.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations: None. The project does not implement any mechanisms to verify the integrity or authenticity of the `validator.tar.gz` archive before unpacking and executing its contents.
- Missing Mitigations:
    - **Archive Integrity Check**: Implement a robust mechanism to verify the integrity and authenticity of the `validator.tar.gz` archive before it is unpacked and executed. This can be achieved through:
        - **Digital Signatures**: Sign the `validator.tar.gz` archive using a strong cryptographic key. The `validate_upload.sh` script should then verify this signature before proceeding with unpacking and execution.
        - **Checksum Verification**: Generate a cryptographic hash (e.g., SHA256) of the legitimate `validator.tar.gz` archive. Securely store this checksum and include it in the validation process. The `validate_upload.sh` script should calculate the checksum of the downloaded `validator.tar.gz` and compare it against the stored checksum. If the checksums do not match, the script should halt execution and report an error.
    - **Secure Distribution Channel**: Ensure that the distribution channel for the `validator.tar.gz` archive is secure and protected from unauthorized modifications. If users are instructed to upload the archive to an Azure Storage Account, ensure that appropriate access controls and security measures are in place to prevent attackers from replacing the legitimate archive.
    - **Principle of Least Privilege**: While validation scripts may require elevated privileges, carefully review the necessity of running `tar` and `python` with `sudo`. If `sudo` is unavoidable, minimize the scope of operations performed with root privileges and ensure that any executed scripts are thoroughly vetted and trusted.
- Preconditions:
    - An attacker must be able to replace the legitimate `validator.tar.gz` archive with a malicious one. This could be achieved by compromising the storage location of the archive or through a Man-in-the-Middle attack during transfer if the archive is downloaded over an insecure channel (though the provided script assumes it's already present).
    - A user must download and execute the `validate_upload.sh` script within their Azure environment, as instructed in the project documentation.
- Source Code Analysis:
    - File: `/code/validate_upload.sh`
    - Vulnerable lines:
        ```bash
        sudo $(which tar) -xzf validator.tar.gz

        [[ -n "$(uname -a | grep -i $distro)" || -n "$(uname -a | grep -i debian)" ]] && sudo $(which python) validate.py
        [[ -n "$(uname -a | grep -i $redhat)" || -n "$(uname -a | grep -i centos)" ]] && sudo $(which platform_python) validate.py
        ```
    - **`sudo $(which tar) -xzf validator.tar.gz`**: This line unpacks the `validator.tar.gz` archive using `tar`. The `-z` option decompresses gzip archives, `-x` extracts files, and `-f` specifies the archive file. The use of `sudo` executes `tar` with root privileges. There are no checks performed on the archive before extraction. A malicious archive could contain files that overwrite system files, or scripts that execute malicious commands upon extraction.
    - **`sudo $(which python) validate.py` and `sudo $(which platform_python) validate.py`**: These lines conditionally execute `validate.py` with root privileges based on the detected Linux distribution. The script assumes that `validate.py` is a trusted script within the unpacked archive. If a malicious `validator.tar.gz` replaces the legitimate one, this will execute a potentially attacker-controlled `validate.py` with root privileges.
- Security Test Case:
    1. **Prepare Malicious Archive**:
        - Create a new directory, for example `malicious_validator`.
        - Inside `malicious_validator`, create a malicious `validate.py` file with the following content:
            ```python
            import os

            # Create a marker file to indicate successful malicious code execution
            os.system("touch /tmp/pwned_by_malicious_validator")

            # Optionally, execute more harmful commands like creating a backdoor user
            # os.system("useradd -M -s /bin/bash backdoor_user")
            # os.system("echo 'backdoor_password' | passwd --stdin backdoor_user")
            # os.system("echo 'backdoor_user ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers")

            print("Malicious validate.py executed!")
            ```
        - Create a `validator.tar.gz` archive from the `malicious_validator` directory:
            ```bash
            tar -cvzf validator.tar.gz malicious_validator
            ```
    2. **Set up Test Environment**:
        - Deploy an Azure Linux VM to act as the validation target.
        - Upload the `validate_upload.sh` script and the newly created `validator.tar.gz` to the home directory of the VM (or any directory accessible to the user).
    3. **Execute the Validation Script**:
        - Connect to the Azure VM via SSH.
        - Navigate to the directory where `validate_upload.sh` and `validator.tar.gz` are located.
        - Execute the `validate_upload.sh` script:
            ```bash
            bash validate_upload.sh test-vhd test-generation
            ```
    4. **Verify Exploitation**:
        - After the script completes, check for the marker file created by the malicious script.
        - Execute the following command on the validation VM:
            ```bash
            ls /tmp/pwned_by_malicious_validator
            ```
        - If the file `/tmp/pwned_by_malicious_validator` exists, it confirms that the malicious `validate.py` script within the crafted `validator.tar.gz` was executed successfully, demonstrating arbitrary code execution.
        - Optionally, if you included commands to create a backdoor user, attempt to log in using the backdoor credentials to further verify the impact.