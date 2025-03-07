- Vulnerability name: Malicious Archive Extraction
- Description: The `validate_upload.sh` script downloads a `validator.tar.gz` archive from a storage account and extracts it using `tar -xzf validator.tar.gz`. There are no checks to ensure the integrity or authenticity of this archive before extraction. A malicious actor could potentially replace the legitimate `validator.tar.gz` in the storage account with a crafted archive. Upon extraction, this malicious archive could contain executable files or scripts that would be executed within the validation virtual machine, leading to arbitrary code execution.
- Impact: Remote code execution on the validation virtual machine. An attacker could gain complete control over the validation VM, potentially exfiltrating sensitive information, disrupting operations, or using it as a pivot point to attack other Azure resources.
- Vulnerability rank: High
- Currently implemented mitigations: None. The script directly downloads and extracts the archive without any validation.
- Missing mitigations:
    - Implement integrity checks for `validator.tar.gz` before extraction. This could be achieved by using checksums (like SHA256) or digital signatures. The checksum or signature of the legitimate archive should be securely stored and verified before extraction.
    - Ensure the download of `validator.tar.gz` happens over HTTPS to prevent Man-in-the-Middle attacks during download.
    - Restrict access to the storage account where `validator.tar.gz` is stored to prevent unauthorized modification or replacement of the archive.
- Preconditions:
    - The attacker needs to be able to replace the legitimate `validator.tar.gz` in the storage account. This could be due to compromised storage account credentials, misconfigurations in access policies, or vulnerabilities in the storage service itself.
    - The validation pipeline must be triggered to execute the `validate_upload.sh` script and extract the malicious archive.
- Source code analysis:
    - File: `/code/validations/validate_upload.sh`
    - Line: `sudo $(which tar) -xzf validator.tar.gz`
    - The script uses `tar -xzf` to extract the downloaded archive `validator.tar.gz`.
    - There is no preceding step to validate the integrity or source of `validator.tar.gz`.
    - An attacker who can replace `validator.tar.gz` with a malicious archive can inject arbitrary files into the validation VM's filesystem during extraction.
    - If the malicious archive contains executable scripts or configuration files, these can be executed post-extraction, leading to code execution.
- Security test case:
    1.  Prepare a malicious `validator.tar.gz` archive. This archive should contain a simple malicious script (e.g., `evil.sh`) that, when extracted and executed, will create a file in `/tmp/evil_marker` to indicate successful execution.
        ```bash
        mkdir malicious_validator
        echo '#!/bin/bash' > malicious_validator/evil.sh
        echo 'touch /tmp/evil_marker' >> malicious_validator/evil.sh
        chmod +x malicious_validator/evil.sh
        tar -cvzf malicious_validator.tar.gz -C malicious_validator .
        rm -rf malicious_validator
        ```
    2.  Identify the storage account and container where `validator.tar.gz` is stored. (Assuming for testing purposes, you have control over this storage account or can simulate the environment).
    3.  Replace the legitimate `validator.tar.gz` in the storage account with the `malicious_validator.tar.gz` created in step 1.
    4.  Trigger the validation pipeline (e.g., by running the Azure pipeline or `validate_upload.sh` script in a test environment that mimics the Azure VM setup).
    5.  After the validation process completes, access the validation VM (if possible in your test setup, or check logs if the validation process provides external feedback).
    6.  Check if the file `/tmp/evil_marker` exists on the validation VM. If it exists, this confirms that the malicious script within the crafted archive was executed, proving the vulnerability.

- Vulnerability name: Insecure Driver Download
- Description: The `LoadDriver.sh` script downloads kernel modules (`involflt.ko`) from `https://rheldriverssa.blob.core.windows.net` using `wget` over HTTP. The script does not perform any integrity checks on the downloaded driver (e.g., checksum or signature verification). An attacker performing a Man-in-the-Middle (MITM) attack or who has compromised the `rheldriverssa.blob.core.windows.net` domain/storage could replace the legitimate kernel module with a malicious one. When the script loads the driver using `modprobe involflt`, the malicious kernel module would be loaded into the kernel, leading to kernel-level code execution.
- Impact: Kernel-level code execution on the validation virtual machine. This is a critical vulnerability as kernel-level access provides the highest level of control over the system, allowing for complete compromise.
- Vulnerability rank: Medium
- Currently implemented mitigations: None. The script downloads the driver over HTTP and loads it without any verification.
- Missing mitigations:
    - Switch to HTTPS for downloading the kernel module to prevent basic MITM attacks.
    - Implement integrity checks for the downloaded kernel module. This could involve:
        - Storing a checksum (like SHA256) of the legitimate kernel module and verifying it after download.
        - Using digitally signed kernel modules and verifying the signature before loading with `modprobe`. This is the most secure approach.
- Preconditions:
    - The attacker needs to be able to perform a Man-in-the-Middle (MITM) attack on the network connection between the validation VM and `rheldriverssa.blob.core.windows.net`, or compromise the `rheldriverssa.blob.core.windows.net` domain/storage.
    - The `LoadDriver.sh` script must be executed as part of the validation process. This script is invoked by `validate.py` which is executed by `validate_upload.sh`.
- Source code analysis:
    - File: `/code/validations/image_validator/ASR/scripts/LoadDriver.sh`
    - Line: `wget https://rheldriverssa.blob.core.windows.net/involflt-`tr [A-Z] [a-z] <<< $OS`/$drvName`
    - The script uses `wget` to download the kernel module over HTTP.
    - There is no step to verify the integrity or authenticity of the downloaded kernel module before loading it into the kernel using `modprobe involflt`.
    - An attacker capable of MITM or storage compromise can replace the legitimate `involflt.ko` with a malicious kernel module.
    - Loading a malicious kernel module allows for arbitrary kernel-level code execution.
- Security test case:
    1.  Set up a Man-in-the-Middle proxy (e.g., using `mitmproxy` or `Burp Suite`). Configure the validation VM to route its traffic through this proxy.
    2.  Prepare a malicious kernel module (`involflt.ko`). This module, for testing purposes, could simply create a file in `/tmp/evil_kernel_module_marker` upon loading to indicate successful malicious module injection. (Creating a real malicious kernel module with more harmful functionality is possible but more complex and potentially risky for testing in production-like environments).
    3.  Configure the MITM proxy to intercept requests to `https://rheldriverssa.blob.core.windows.net` for `involflt.ko` and replace the response with the malicious `involflt.ko` prepared in step 2.
    4.  Trigger the validation pipeline, ensuring that the `LoadDriver.sh` script is executed on the validation VM.
    5.  After the validation process completes, access the validation VM (if possible in your test setup).
    6.  Check if the file `/tmp/evil_kernel_module_marker` exists on the validation VM. If it exists, this confirms that the malicious kernel module was loaded, proving the vulnerability of insecure driver download.