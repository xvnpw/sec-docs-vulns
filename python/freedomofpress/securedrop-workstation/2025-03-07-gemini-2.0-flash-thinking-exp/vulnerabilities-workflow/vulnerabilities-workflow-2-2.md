### Vulnerability List

* Vulnerability Name: Insecure MIME Type Handling in `sd-viewer`

* Description:
    1. An attacker uploads a maliciously crafted document to SecureDrop.
    2. A journalist logs into the SecureDrop Journalist Interface via the SecureDrop Client in the `sd-app` VM.
    3. The journalist downloads and attempts to view the malicious document.
    4. The SecureDrop Client, configured to open documents in disposable VMs based on `sd-viewer`, uses `xdg-open` to open the document.
    5. Due to insecure MIME type configurations within `sd-viewer`, a potentially unsafe application (e.g., a web browser or a script interpreter) might be launched to handle the malicious document instead of a safe document viewer like Evince or LibreOffice.
    6. If an unsafe application is launched, it could execute embedded malicious code within the document, leading to code execution within the disposable `sd-viewer` VM.

* Impact:
    - Code execution within the disposable `sd-viewer` VM.
    - Potential data exfiltration from the isolated `sd-viewer` VM, although limited by its network isolation and disposable nature.
    - Compromise of the viewed submission.
    - While the `sd-viewer` VM is disposable, successful exploitation could lead to further attacks if vulnerabilities exist in the Qubes OS or Xen hypervisor that allow for VM escape.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - **Disposable VMs for Document Viewing:** Documents are opened in disposable VMs (`sd-viewer`), limiting the persistence of any compromise.
    - **Network Isolation of `sd-viewer`:** `sd-viewer` VMs are networkless, preventing direct external communication for data exfiltration.
    - **AppArmor Profiles:** AppArmor profiles are enforced for document viewers like Evince and Totem in `sd-viewer` (`tests/test_viewer.py`), restricting their capabilities.
    - **MIME Type Configuration:** The project configures MIME type associations in `sd-viewer` to default to `open-in-dvm.desktop` which is intended to use safe viewers (`tests/test_viewer.py`, `tests/test_app.py`, `tests/test_proxy_vm.py`, `tests/test_sd_devices.py`).
    - **Mailcap Hardening:** Mailcap is disabled in `sd-viewer`, preventing fallback to potentially unsafe mailcap handlers (`tests/test_viewer.py`, `tests/test_app.py`, `tests/test_proxy_vm.py`, `tests/test_sd_devices.py`).

* Missing Mitigations:
    - **Strict MIME Type Validation and Sanitization:** The project relies on configuration files to define safe MIME type handlers. There is no explicit validation or sanitization of MIME types to ensure that attacker-controlled MIME types cannot bypass these configurations.
    - **Enforced Application for Document Viewing:** Instead of relying on `xdg-open` and MIME type configurations, the SecureDrop Client could enforce the use of a specific, hardened document viewer application for all document types, regardless of MIME type.
    - **Further Sandboxing of Document Viewers:** Deeper sandboxing mechanisms, beyond AppArmor, could be considered for document viewers within `sd-viewer` to further limit the impact of potential exploits.

* Preconditions:
    - An attacker needs to be able to upload a malicious document to a SecureDrop instance.
    - A journalist must download and attempt to view this malicious document using the SecureDrop Workstation.
    - The MIME type of the malicious document must be such that it triggers the launch of an unsafe application in `sd-viewer` due to misconfiguration or bypass of MIME handling settings.

* Source Code Analysis:
    1. **MIME Type Configuration Files:** The files `tests/vars/sd-viewer.mimeapps`, `tests/vars/sd-devices.mimeapps` and the tests `tests/test_viewer.py`, `tests/test_app.py`, `tests/test_proxy_vm.py`, `tests/test_sd_devices.py` indicate that MIME type handling is configured via `mimeapps.list` files and tested.
    2. **`test_viewer.py` - `test_mime_types` function:** This test reads a `sd-viewer.mimeapps` file and asserts that `xdg-mime query default <mime_type>` returns the expected application. This confirms that MIME types are being configured.
    3. **`test_app.py`, `test_proxy_vm.py`, `test_sd_devices.py` - `test_mimeapps` function:** These tests also check `mimeapps.list` and use `xdg-mime query default` to verify the default application for different MIME types. They assert that the default application is `open-in-dvm.desktop`.
    4. **`test_app.py`, `test_proxy_vm.py`, `test_sd_devices.py` - `test_open_in_dvm_desktop` function:** These tests verify the content of `open-in-dvm.desktop`, ensuring it uses `qvm-open-in-vm --view-only @dispvm:sd-viewer %f` to open files in disposable `sd-viewer` VMs in view-only mode.
    5. **`test_viewer.py` - `test_mimetypes_symlink`:** This test checks for a symlink for `mimeapps.list`, indicating a custom configuration might be in place.
    6. **`test_viewer.py` - `test_mailcap_hardened` and `test_app.py`, `test_proxy_vm.py`, `test_sd_devices.py` - `test_mailcap_hardened`:** These tests ensure mailcap is hardened by checking for a rule that disables mailcap usage and logs a message if it's used.
    7. **`securedrop_salt/sd-viewer/mime.sls`:** This Salt state file is likely responsible for configuring MIME types in `sd-viewer` and potentially for creating the `mimeapps.list` and the symlink tested in `test_viewer.py`.

    **Visualization:**

    ```
    SecureDrop Client (sd-app) --> xdg-open --> MIME type config (mimeapps.list in sd-viewer) --> Application in sd-viewer (potentially unsafe) --> Malicious Document
    ```

    **Code Flow:**
    - Journalist clicks to view a document in SecureDrop Client (`sd-app`).
    - SecureDrop Client uses `xdg-open` to open the document.
    - `xdg-open` in `sd-app` (configured to use `open-in-dvm.desktop`) redirects the request to `qvm-open-in-vm`.
    - `qvm-open-in-vm` launches a disposable VM based on `sd-viewer` and executes `xdg-open` within it.
    - `xdg-open` in `sd-viewer` consults `mimeapps.list` to determine the default application based on the document's MIME type.
    - If the MIME type is maliciously crafted or misconfigured, `xdg-open` might launch an unsafe application (e.g., if an attacker crafts a document with a MIME type associated with a web browser or script interpreter).
    - The unsafe application executes the malicious document, leading to code execution.

* Security Test Case:
    1. **Setup:**
        - Set up a SecureDrop Workstation development environment.
        - Identify a MIME type that is associated with a potentially unsafe application in a standard Debian system (e.g., a MIME type that might trigger a web browser or a script interpreter if misconfigured). For example, you could try to exploit MIME types related to shell scripts or HTML files if they are not correctly handled by the intended document viewers.
        - Create a malicious document that exploits a vulnerability in the identified unsafe application or simply attempts to execute arbitrary commands (e.g., using shell script MIME type with embedded commands or a crafted HTML file with Javascript).
    2. **Upload:**
        - As an attacker, upload the malicious document to the SecureDrop source interface.
    3. **Journalist Action:**
        - As a journalist, log in to the SecureDrop Journalist Interface using the SecureDrop Client in `sd-app`.
        - Download the submission containing the malicious document.
        - Attempt to view the malicious document by clicking on it in the SecureDrop Client.
    4. **Verification:**
        - Observe the behavior within the disposable `sd-viewer` VM.
        - Check for signs of code execution, such as unexpected processes running, files being created, or network connections being attempted (though network is isolated, side-channels might be possible to detect).
        - Specifically, check if an application other than the intended document viewers (Evince, LibreOffice) is launched to handle the document.
        - Ideally, have the malicious document attempt to write a log message to `/tmp/vulnerability_confirmed` within the `sd-viewer` disposable VM. After attempting to view the document, check if this file exists within the disposable VM to confirm code execution. You can use `qvm-run --disp sd-viewer-disposable 'ls /tmp/vulnerability_confirmed'` from dom0 to check for the file after attempting to view the document.
    5. **Expected Result (Vulnerability Confirmation):**
        - If the test is successful, the file `/tmp/vulnerability_confirmed` should exist within the disposable `sd-viewer` VM, indicating code execution.
        - Additionally, observing an unexpected application being launched to handle the document would further confirm the vulnerability related to insecure MIME type handling.