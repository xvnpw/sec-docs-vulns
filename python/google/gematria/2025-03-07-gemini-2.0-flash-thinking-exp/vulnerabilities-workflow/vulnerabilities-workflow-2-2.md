- Vulnerability name: Unverified Download and Execution of External Build Script
- Description:
    1. The `README.md` file provides instructions for building the project using CMake.
    2. These instructions include a command that downloads and executes an external shell script, `build_tflite.sh`, from the `google/ml-compiler-opt` repository using `curl | bash`.
    3. This download and execution process is performed without any integrity checks on the downloaded script.
    4. If an attacker compromises the `build_tflite.sh` script in the upstream repository, users who follow the build instructions will download and execute the malicious script.
    5. This allows the attacker to execute arbitrary code on the user's machine during the build process.
- Impact:
    - Arbitrary code execution on the user's machine.
    - Full system compromise, including potential data theft, malware installation, and unauthorized access.
- Vulnerability rank: Critical
- Currently implemented mitigations:
    - None. The `README.md` directly instructs users to use the insecure `curl | bash` pattern.
    - The `seclinter_this_is_fine: false` pragma comment in the `README.md` is a code review note and not a runtime mitigation.
- Missing mitigations:
    - Missing integrity verification for the downloaded `build_tflite.sh` script.
    - Missing secure download and execution instructions.
    - Missing dependency vendoring or verifiable build process for TFLite.
- Preconditions:
    - User follows the CMake build instructions in the `README.md` file.
    - The `build_tflite.sh` script on the `google/ml-compiler-opt` repository is compromised by an attacker.
- Source code analysis:
    - File: `/code/README.md`
    - The `README.md` file contains the CMake build instructions.
    - The following command is provided to download and execute the external script:

    ```markdown
    <!--* pragma: { seclinter_this_is_fine: true } *-->
    ```shell
    mkdir /tmp/tflite && cd /tmp/tflite
    curl https://raw.githubusercontent.com/google/ml-compiler-opt/main/buildbot/build_tflite.sh | bash
    ```
    <!--* pragma: { seclinter_this_is_fine: false } *-->

    - The `curl | bash` pattern is inherently insecure as it executes downloaded code without verification.
    - The pragma comments indicate an internal awareness of potential security concerns but do not provide user-facing mitigations.
- Security test case:
    1. Setup:
        - Create a controlled testing environment (VM or container).
        - Prepare a malicious `build_tflite.sh` script that performs an observable action (e.g., creates a file in `/tmp`).
        - Host the malicious script at a publicly accessible URL.
        - In a local clone of the Gematria repository, modify the `README.md` file to replace the original `build_tflite.sh` URL with the URL of the malicious script.
    2. Execution:
        - In the testing environment, follow the CMake build instructions from the modified `README.md`, specifically executing the `curl | bash` command.
    3. Verification:
        - Check for the observable action of the malicious script (e.g., presence of the file in `/tmp`).
        - If the malicious action is observed, the vulnerability is confirmed, demonstrating arbitrary code execution.