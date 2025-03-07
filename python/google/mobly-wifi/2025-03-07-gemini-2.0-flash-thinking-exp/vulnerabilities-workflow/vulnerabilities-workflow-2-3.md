### Vulnerability List

- Vulnerability Name: Insecure SSH Private Key Permissions in Setup Instructions
- Description:
    1. The `README.md` file provides instructions for one-time setup, which includes downloading an SSH private key (`testing_rsa`) and placing it in the `~/.ssh/` directory.
    2. The instructions in `README.md` do not explicitly mention setting restrictive permissions (e.g., 600) on the downloaded SSH private key file.
    3. If a user follows these instructions and omits setting the correct file permissions, the SSH private key file might have overly permissive access rights (e.g., world-readable).
    4. An attacker who has access to the same host machine (but not necessarily the same user account) could potentially read the SSH private key file if permissions are not restrictive.
    5. With the stolen SSH private key, the attacker can then authenticate to any OpenWrt device configured to accept this key, gaining unauthorized SSH access.
- Impact:
    - Unauthorized access to OpenWrt devices.
    - An attacker can gain complete control over the vulnerable OpenWrt devices, potentially leading to:
        - Modification of device configurations.
        - Installation of malicious firmware.
        - Data exfiltration from networks connected to the OpenWrt device.
        - Use of the compromised device as a pivot point for further attacks on the network.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - The code in `mobly/controllers/wifi/openwrt_device.py` attempts to mitigate this issue by setting the permissions of the `testing_rsa` file located within the *package itself* to `0o600` during the `initialize` method of the `OpenWrtDevice` class.
    - Specifically, the line `os.chmod(_SSH_KEY_IDENTITY, 0o600)` is present in the `initialize` method.
    - However, this mitigation only affects the `testing_rsa` file within the installed Python package and *not* the downloaded `testing_rsa` file placed in `~/.ssh/` by the user, which is the actual file used for SSH authentication as per the setup instructions.
- Missing Mitigations:
    - Explicit instructions in the `README.md` file to set restrictive permissions (specifically `600`) on the downloaded SSH private key file (`~/.ssh/testing_rsa`).
    - The documentation should include a command like `chmod 600 ~/.ssh/testing_rsa` in the "One-Time Setup on Host" section after instructing the user to download the key.
- Preconditions:
    - A user follows the setup instructions in the `README.md` file to configure the Mobly WiFi Controller.
    - The user downloads the `testing_rsa` SSH private key as instructed and places it in `~/.ssh/testing_rsa`.
    - The user *does not* manually set restrictive permissions on the `~/.ssh/testing_rsa` file after downloading it.
    - The host machine where Mobly WiFi Controller is installed is a multi-user environment, or an attacker gains access to the host machine through other means.
- Source Code Analysis:
    1. **File:** `/code/mobly/controllers/wifi/openwrt_device.py`
    2. **Method:** `OpenWrtDevice.initialize`
    3. **Code Snippet:**
        ```python
        _SSH_KEY_IDENTITY = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 'data/testing_rsa'
        )
        ...
        def initialize(self):
            ...
            os.chmod(_SSH_KEY_IDENTITY, 0o600)
            ...
        ```
    4. **Analysis:**
        - The code defines `_SSH_KEY_IDENTITY` to point to `testing_rsa` within the `data` directory of the `mobly.controllers.wifi` package.
        - The `os.chmod(_SSH_KEY_IDENTITY, 0o600)` line sets the permissions of *this file* to `0600`.
        - This is a security measure to restrict access to the private key.
        - **However, this mitigation is ineffective against the vulnerability described because:**
            - The `README.md` instructs users to download a *separate* `testing_rsa` file from a URL and place it in `~/.ssh/testing_rsa`.
            - This downloaded file is *different* from the `testing_rsa` within the package.
            - The `os.chmod` command in the code does *not* affect the permissions of the downloaded `~/.ssh/testing_rsa` file.
            - The vulnerability lies in the setup instructions in `README.md` that fail to guide users to secure the *downloaded* private key file.

- Security Test Case:
    1. **Setup:**
        - Create two user accounts on a Linux host machine: `user1` (test user) and `user2` (attacker).
        - As `user1`, follow the "One-Time Setup on Host" instructions in `README.md`, specifically:
            - Download the `testing_rsa` file from the provided URL.
            - Place the downloaded file at `~/.ssh/testing_rsa` (under `user1`'s home directory).
            - **Crucially, DO NOT manually execute `chmod 600 ~/.ssh/testing_rsa`.** Let the file permissions be whatever default is set upon download (likely more permissive than 600).
        - As `user1`, install the `mobly-wifi` package using `pip install mobly-wifi`.
        - Configure a testbed with an OpenWrt device, as described in "Write Mobly Device Configs" in `README.md`, using the IP address of your OpenWrt device.
    2. **Exploit:**
        - Switch to `user2` account on the same host machine.
        - As `user2`, attempt to SSH into the OpenWrt device using the private key file created by `user1`. Use the following command, adjusting the IP address to your OpenWrt device's IP:
            ```bash
            ssh -i /home/user1/.ssh/testing_rsa root@<OpenWrt_Device_IP>
            ```
            (Note: `/home/user1/.ssh/testing_rsa` is the path to the private key file created by `user1`, accessible to `user2` if permissions are too open).
        - If the SSH connection is successful *without prompting for a password*, it means `user2` (the attacker) has successfully authenticated to the OpenWrt device using `user1`'s private key, due to insecure file permissions.
    3. **Expected Result:**
        - The SSH connection from `user2` to the OpenWrt device should be successfully established without requiring a password, demonstrating unauthorized access due to insecure permissions on the SSH private key file as a result of incomplete setup instructions in `README.md`.