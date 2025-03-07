## Combined Vulnerability List

### Malicious Code Injection in Scripts and Tools

- **Vulnerability Name:** Malicious Code Injection in Scripts and Tools
- **Description:**
    - A malicious actor can create a clone of this repository and inject arbitrary code into shell and Python scripts.
    - A security researcher, believing they are using the legitimate tools, clones the malicious repository.
    - When the researcher executes any script (e.g., `run.sh`, `download_release.sh`, `kpwn_db.py`, etc.) from the malicious clone, the injected code will be executed on their host system.
    - This injected code can perform any action the researcher's user account has permissions for, potentially leading to full system compromise.
    - For example, a compromised `run.sh` script could download and execute a rootkit, steal credentials, or exfiltrate sensitive data from the researcher's machine.
- **Impact:**
    - Arbitrary code execution on the security researcher's system.
    - Potential for complete compromise of the researcher's system, including:
        - Data theft (research data, credentials, personal files).
        - Installation of malware (rootkits, spyware, ransomware).
        - Denial of service or disruption of the researcher's work.
        - Lateral movement to other systems if the researcher's system is part of a network.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    - None. The project does not include any technical mitigations to prevent the use of a malicious clone or to verify the integrity of the scripts.
    - The "Disclaimer" in the `README.md` file mentions that it is "not an officially supported Google product," but this is not a security mitigation.
- **Missing Mitigations:**
    - **Code Signing:** Implement code signing for all scripts (shell and Python). This would allow researchers to cryptographically verify that the scripts they are using are from a trusted source and have not been tampered with.
    - **Checksum Verification:** Provide checksums (e.g., SHA256 hashes) for all scripts and tools in a separate, trusted location (e.g., project website, official documentation). Researchers could then verify the integrity of their cloned repository by comparing the checksums of their local files against the trusted checksums.
    - **Repository Authenticity Verification Guide:** Include clear instructions in the `README.md` on how to verify the authenticity of the Git repository itself. This could involve:
        - Verifying Git commit signatures using GPG keys from trusted project maintainers.
        - Checking the repository's URL to ensure it matches the official project URL.
- **Preconditions:**
    - An attacker successfully social engineers a security researcher into cloning a malicious clone of this repository.
    - The researcher, unaware of the malicious nature of the clone, executes any of the scripts or tools within the cloned repository on their system.
- **Source Code Analysis:**
    - **Attack Vector:** All executable scripts within the repository are potential injection points. Both shell scripts (`.sh`) and Python scripts (`.py`) can be modified to execute arbitrary commands.
    - **Example - `run.sh` script:**
        - File: `/code/kernel-image-runner/run.sh`
        - Vulnerable Code Location: Beginning of the script.
        - Step-by-step analysis:
            1. An attacker modifies `run.sh` by inserting a malicious command at the very beginning of the script, before any legitimate code execution:
            ```bash
            #!/bin/bash
            # Injected malicious code:
            bash -c 'echo "You have been PWNED!" && mkdir /tmp/pwned_by_malicious_clone' &

            set -e

            SCRIPT_DIR=$(dirname $(realpath "$0"))
            ... (rest of the original script)
            ```
            2. When a researcher executes `./run.sh ubuntu <release-name>`, the Bash interpreter first executes the injected command `bash -c 'echo "You have been PWNED!" && mkdir /tmp/pwned_by_malicious_clone' &`.
            3. This injected command will:
                - Print "You have been PWNED!" to the console.
                - Create a directory named `/tmp/pwned_by_malicious_clone` on the researcher's system. The `&` at the end ensures this command runs in the background, so it does not block the execution of the rest of the script.
            4. After the injected code is executed, the script continues to execute the intended functionality of `run.sh`, potentially masking the malicious activity if the injected code is designed to be subtle.
- **Security Test Case:**
    1. **Setup:**
        - Create a controlled test environment (e.g., a virtual machine) to avoid harming the host system.
        - Create a malicious clone of the repository in the test environment.
        - Modify the `code/kernel-image-runner/run.sh` script in the malicious clone by adding the line `bash -c 'touch /tmp/vulnerable_test_file' &` at the beginning of the script.
    2. **Preconditions:**
        - Researcher (in the test environment) is assumed to have cloned the malicious repository.
        - Researcher is in the `code/kernel-image-runner/` directory of the malicious clone.
    3. **Steps to trigger vulnerability:**
        - Execute the command: `./run.sh ubuntu 5.4.0-26.30`
    4. **Expected outcome:**
        - The `run.sh` script executes.
        - The injected malicious code `bash -c 'touch /tmp/vulnerable_test_file' &` is executed on the researcher's test system in the background.
        - A file named `/tmp/vulnerable_test_file` is created on the researcher's test system, indicating successful arbitrary code execution.
        - The kernel runner might start and execute as intended afterwards, depending on the attacker's modifications.
    5. **Verification:**
        - Check for the existence of the `/tmp/vulnerable_test_file` file on the test system using the command `ls /tmp/vulnerable_test_file`.
        - If the file exists, the vulnerability is confirmed.

### Intentional Vulnerability Injection via kpwn Module

- **Vulnerability Name:** Intentional Vulnerability Injection via kpwn Module
- **Description:**
    - The `kpwn` kernel module is designed to intentionally introduce kernel vulnerabilities for research and testing purposes.
    - A user with administrative privileges can load the `kpwn` kernel module into a running Linux kernel.
    - Once loaded, the `kpwn` module creates a device `/dev/kpwn` that exposes various `ioctl` commands.
    - These `ioctl` commands are designed to simulate kernel vulnerabilities for research and testing purposes, such as arbitrary kernel memory read/write (`ARB_READ`, `ARB_WRITE`), arbitrary kernel memory free (`KFREE`), kernel address leaks (`KASLR_LEAK`, `SYM_ADDR`), and RIP control (`RIP_CONTROL`).
    - If this module is mistakenly deployed in a non-research environment, or if an attacker gains access to a system where it is loaded, these intentional vulnerabilities can be exploited to gain full kernel control.
    - An attacker could socially engineer a user into loading the module, or exploit other vulnerabilities to gain access and then leverage `kpwn`.
- **Impact:**
    - Critical system compromise.
    - Full control of the affected Linux system by the attacker.
    - Potential data breach and exfiltration.
    - System instability and unpredictable behavior due to exploitation of kernel vulnerabilities.
    - Bypassing all kernel security mechanisms.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    - None. The `kpwn` module is designed to inject vulnerabilities for research purposes, so no mitigations are implemented within the module itself.
    - Project documentation includes disclaimers stating that the `kpwn` module is for research purposes only and should not be deployed in production environments. This is mentioned in the main README.md file and the `third_party/kernel-modules/kpwn/README.md` file.
    - The disclaimer in the main README.md file also warns that this is not an officially supported Google product.
- **Missing Mitigations:**
    - **Technical Prevention of Non-Research Deployment:** Implement technical controls to prevent the `kpwn` module from being loaded in non-research environments. For example, the module could include checks to prevent loading outside of a specifically configured research VM or container.
    - **Runtime Warnings:** The `kpwn` module itself could include a runtime check and issue a kernel log warning message upon loading if it detects it's not in a designated testing environment.  It could also print a prominent warning message to the system console upon loading, clearly stating its purpose and risks.
    - **Restricted Device Permissions:** By default, the `/dev/kpwn` device could have very restricted permissions (e.g., root-only access) to limit the attack surface.
    - **Input Validation in `kpwn` module:** The `kpwn` module lacks input validation for the `ARB_WRITE` ioctl. Specifically, it should validate the `kernel_addr` and `length` to prevent writing to arbitrary kernel memory locations. Ideally, remove or disable `ARB_WRITE` and other highly dangerous ioctls unless explicitly needed for a specific research task and protected by additional safeguards.
    - **Conditional Compilation/Loading:** The `kpwn` module should not be compiled or loaded by default. It should only be enabled through explicit user action (e.g., a specific build flag or command-line argument to `kernel-image-runner`).
    - **Runtime Disable Feature:** Implement a mechanism to disable the `kpwn` module at runtime, even if it is loaded. This could be a sysctl parameter or another `ioctl` command to disable the dangerous functionalities.
    - **Warning Banner:** When `kernel-image-runner` is used with `--custom-modules=kpwn`, display a prominent warning message indicating the security risks associated with loading this module, especially in network-accessible environments.
- **Preconditions:**
    - The attacker needs access to a system where a user has already loaded the `kpwn` kernel module, or can social engineer a user to load it.
    - Loading the `kpwn` kernel module requires root or administrator privileges.
    - The kernel must be running and the `/dev/kpwn` device must exist.
    - For exploitation of `ARB_WRITE` via `core_pattern` overwrite, attacker needs initial access to the guest VM.
- **Source Code Analysis:**
    - **`third_party/kernel-modules/kpwn/kpwn.c`**: This file contains the source code for the `kpwn` kernel module.
    - The module registers a character device `/dev/kpwn` and implements the `ioctl` interface.
    - **`kpwn_ioctl` function**: This function in `kpwn.c` handles the `ioctl` commands.
    - **`enum kpwn_cmd`**:  This enum defines various commands including `ARB_WRITE` and `RIP_CONTROL`, each designed to simulate a vulnerability.
    - **`ARB_WRITE` command (case `ARB_WRITE` in `kpwn_ioctl`)**: This command takes a user-provided kernel address (`msg->kernel_addr`), data (`msg->data`), and length (`msg->length`) and directly copies user data to the specified kernel address using `memcpy` without proper validation.
    ```c
    case ARB_WRITE:
        if (!msg || !msg->data)
            return INVALID_MSG;
        if (msg->length > MAX_MESSAGE_LENGTH)
            return INVALID_LENGTH;
        if (!msg->kernel_addr)
            return INVALID_ADDRESS;

        if (copy_from_user(ubuffer, msg->data, msg->length))
            return COPY_FROM_USER_FAILED;

        memcpy((void *)msg->kernel_addr, ubuffer, msg->length); // <--- Arbitrary kernel write here

        break;
    ```
    - **`RIP_CONTROL` command (case `RIP_CONTROL` in `kpwn_ioctl`)**: This command allows controlling the instruction pointer (RIP), enabling arbitrary code execution in the kernel.
- **Security Test Case:**
    1. **Prerequisites:** Set up a Linux kernel environment, compile `kpwn` module, and compile `test/kpwn_test.c` or create a similar exploit program. For `core_pattern` overwrite test, create a malicious script `run_as_root` in the `rootfs`.
    2. **Load the kpwn module:** As root, load the `kpwn` module: `sudo insmod kpwn.ko`.
    3. **Run test program (ARB_WRITE - core_pattern overwrite):** Execute a program that uses `SYM_ADDR` to find `core_pattern` address, then uses `ARB_WRITE` to overwrite `core_pattern` with `|/tmp/run_as_root`. Trigger a kernel crash (e.g., using `KFREE(1)` ioctl).
    4. **Verify Impact (ARB_WRITE):** Check if `/tmp/pwned` file is created (if using `run_as_root` script that creates it). Check `core_pattern` value after exploit.
    5. **Run test program (RIP_CONTROL):** Execute `kpwn_test rip_control` to trigger `RIP_CONTROL` ioctl and verify "!!! YOU WON !!!" message in kernel logs.
    6. **Unload the module:** `sudo rmmod kpwn`.

This test case demonstrates how an attacker can leverage the intentionally injected vulnerabilities in the `kpwn` module to perform arbitrary kernel memory write and gain RIP control, leading to full system compromise. It also shows how `ARB_WRITE` can be used to overwrite `core_pattern` and achieve root code execution upon kernel crash.