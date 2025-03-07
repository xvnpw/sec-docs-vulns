- Vulnerability Name: **MIME Type Spoofing leading to Incorrect Application Launch in `sd-viewer`**
- Description:
    - An attacker crafts a malicious document, for example, disguising an executable script as a seemingly benign document type (e.g., a PDF).
    - The journalist receives this document as a SecureDrop submission and attempts to open it using the SecureDrop Client in the `sd-app` VM.
    - Due to a vulnerability in MIME type detection or handling within the `sd-viewer` template, the malicious file is misidentified as a safe document type.
    - Instead of being opened by a safe document viewer (like Evince for PDF), the file is launched by a different application, such as a shell interpreter or a less secure application, within the disposable `sd-viewer` VM.
    - This unintended application execution bypasses the intended security measures of the `sd-viewer` disposable VM, potentially allowing the attacker to execute arbitrary code within the disposable VM.

- Impact:
    - **High**. Successful MIME type spoofing allows arbitrary code execution within the `sd-viewer` disposable VM. While the `sd-viewer` is disposable and networkless, code execution here is the first step towards escaping the disposable VM and compromising the `sd-app` VM, which is the primary goal of the attacker as stated in the project description.  Compromise of `sd-viewer` allows reading the decrypted submission directly. Further exploitation could lead to compromising the `sd-app` VM and gaining access to all decrypted submissions.

- Vulnerability Rank: **High**

- Currently Implemented Mitigations:
    - **Disposable VM for Document Viewing (`sd-viewer`):**  Documents are opened in a disposable VM (`sd-viewer`), which limits the persistence of any compromise.
    - **MIME Type Handling Service (`securedrop-mime-handling`):** The project implements a `securedrop-mime-handling` service, intended to enforce secure MIME type handling and application associations. This service is active in `sd-app`, `sd-proxy`, and `sd-viewer` VMs, as confirmed by tests (`test_app.py`, `test_proxy_vm.py`, `test_viewer.py`).
    - **`mimeapps.list` Configuration:**  The `mimeapps.list` files in `sd-app`, `sd-proxy`, and `sd-viewer` define default applications for various MIME types, aiming to ensure documents are opened with designated viewers within `sd-viewer` disposable VMs. Tests (`test_app.py`, `test_proxy_vm.py`, `test_viewer.py`) verify these configurations.
    - **AppArmor Profiles:** AppArmor profiles are enforced for document viewers like Evince and Totem in `sd-viewer` (`test_viewer.py`), limiting their capabilities even if exploited.

- Missing Mitigations:
    - **Robust MIME Type Detection:** Relying solely on file extensions or basic MIME type detection might be insufficient to prevent spoofing. More robust content-based MIME type detection mechanisms could be considered, potentially using tools like `file --mime-type` with additional validation.
    - **Strict Application Whitelisting/Blacklisting:** Instead of relying on default MIME type associations, a stricter approach could involve whitelisting only explicitly approved document viewer applications within `sd-viewer` and preventing execution of any other applications, regardless of the detected MIME type.
    - **Sandboxing within Disposable VM:** While the disposable VM provides isolation, further sandboxing technologies (like seccomp or more restrictive AppArmor profiles) within the `sd-viewer` disposable VM could further limit the impact of a compromised document viewer.

- Preconditions:
    - The attacker needs to successfully submit a malicious document to the SecureDrop instance.
    - The journalist must download and attempt to open this submission using the SecureDrop Client in the `sd-app` VM.
    - The `sd-viewer` disposable VM must be launched to open the document.

- Source Code Analysis:
    - **`tests/test_viewer.py` and `tests/test_app.py`, `tests/test_proxy_vm.py`:** These tests verify the presence of `mimeapps.list` and the correct default applications for MIME types using `xdg-mime query default`. They also check for the `securedrop-mime-handling` service.
    - **`tests/base.py`:** The `mailcap_hardened()` function in `base.py` is used in tests to ensure mailcap rules are disabled as a fallback for MIME type handling. This is a positive security measure.
    - **`securedrop_salt/sd-viewer.sls`, `securedrop_salt/sd-app.sls`, `securedrop_salt/sd-proxy.sls`:**  These Salt states likely configure the `mimeapps.list` and enable the `securedrop-mime-handling` service. However, the *implementation* of `securedrop-mime-handling` service and its robustness are not directly visible in these files.
    - **`files/sdw-admin.py`:** This script applies Salt states, including those related to MIME handling, but doesn't contain the MIME handling logic itself.
    - **No specific code in the provided files directly implements MIME type detection or robust application launching decisions based on MIME types.** The project relies on the underlying OS (Debian and Qubes OS) and standard tools like `xdg-mime` and `run-mailcap` (which is intentionally hardened against).

    - **Visualization:**
        ```
        [sd-app VM] --> (Open Document) --> [DispVM: sd-viewer] --> (MIME Type Detection & App Launch) --> [Application (Expected Viewer OR Spoofed App)]
        ```
        The vulnerability lies in the "(MIME Type Detection & App Launch)" step within the `sd-viewer` disposable VM. If this step is flawed, it can lead to launching the "Spoofed App" instead of the "Expected Viewer."

- Security Test Case:
    1. **Preparation (Attacker):**
        - Create a malicious executable script (e.g., `evil.sh`) that, when executed, attempts to communicate back to the attacker (e.g., by creating a file in `/tmp` visible from dom0 via Qubes shared folders or by attempting DNS exfiltration – though network access is supposed to be disabled, side channels might exist).
        - Create a seemingly benign document file, for example, a PDF (`benign.pdf`).
        - Embed or append the malicious script `evil.sh` to `benign.pdf` in a way that might trick MIME type detection into identifying it as a shell script or another executable type, or in a way that exploits a vulnerability in document viewers when processing such hybrid files. For instance, create a PDF that also contains an embedded shell script and rename it to have a `.pdf` extension, but craft it to be potentially misidentified.
        - Encrypt and submit this crafted file as a SecureDrop submission.
    2. **Action (Journalist):**
        - In the `sd-app` VM, use the SecureDrop Client to download the submission containing the crafted file.
        - Attempt to open the downloaded file within the `sd-app` VM. This will trigger the opening of the file in a disposable `sd-viewer` VM.
    3. **Verification (Attacker & Journalist):**
        - **If vulnerable:** Observe if the malicious script `evil.sh` executes within the `sd-viewer` disposable VM. Check for indicators of execution, such as:
            - Creation of the attacker-defined file in `/tmp` (journalist can check this in dom0 after the test).
            - Attempted DNS requests from the `sd-viewer` VM (attacker can monitor for these).
        - **If mitigated:** Verify that the crafted file is opened by the expected document viewer application (e.g., Evince for PDF) within `sd-viewer` and that the malicious script does not execute, and no indicators of compromise are observed.
    4. **Expected Result (Vulnerable Scenario):** The malicious script executes in the `sd-viewer` disposable VM, demonstrating successful MIME type spoofing and arbitrary code execution within the disposable environment.
    5. **Expected Result (Mitigated Scenario):** The crafted file is safely opened by the intended document viewer in `sd-viewer`, and no malicious code execution occurs.