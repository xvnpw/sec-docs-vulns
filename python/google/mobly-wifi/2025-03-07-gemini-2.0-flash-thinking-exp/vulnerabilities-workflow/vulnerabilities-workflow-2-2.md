- Vulnerability Name: Insecure Default SSH Key
- Description: The Mobly WiFi Controller library uses a publicly shared SSH private key (`testing_rsa`) for authentication to OpenWrt devices. This key is distributed with the library and also available in a public Chromium repository. Anyone who obtains this private key can gain unauthorized SSH access to any OpenWrt device that is configured to accept the corresponding public key, which is likely the default configuration for devices intended to be used with this library.
    To trigger this vulnerability:
    1.  An attacker obtains the `testing_rsa` private key. This key is publicly available at `https://chromium.googlesource.com/chromiumos/chromite/+/master/ssh_keys/testing_rsa?pli=1` and is also included in the `data/` directory of the `mobly-wifi` Python package.
    2.  The attacker identifies an OpenWrt device that is intended to be controlled by the `mobly-wifi` library. These devices are expected to be configured to accept SSH connections using the public key corresponding to `testing_rsa`.
    3.  The attacker uses an SSH client and the obtained `testing_rsa` private key to attempt to connect to the OpenWrt device via SSH, using the default username (e.g., `root`) or a username configured for the device.
    4.  If the OpenWrt device is configured with the corresponding public key, the attacker will successfully establish an SSH connection without needing a password.

- Impact: Critical. Successful exploitation of this vulnerability allows an attacker to gain full remote control of the OpenWrt device. This includes the ability to:
    -  Modify system configurations.
    -  Install or remove software.
    -  Install or remove software.
    -  Monitor network traffic.
    -  Use the device as a point of entry to the network.
    -  Potentially use the device in botnets or for other malicious purposes.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations: None. The project actively encourages the use of this shared key in the documentation and code. The `README.md` explicitly instructs users to download and use this key. The code in `mobly/controllers/wifi/openwrt_device.py` defaults to using this key for SSH authentication.

- Missing Mitigations:
    -  Remove the distribution of the `testing_rsa` private key from the project.
    -  Remove the hardcoded path to `testing_rsa` as the default SSH key in the codebase.
    -  **Strongly discourage** the use of shared SSH keys in the documentation.
    -  Provide clear documentation and instructions on how to:
        -  Generate unique SSH key pairs for each OpenWrt device and Mobly controller setup.
        -  Securely configure OpenWrt devices to accept only specific public keys.
        -  Manage and securely store private keys.
    -  Recommend password-based authentication only as a temporary fallback and strongly advise against its use in production or testing environments.

- Preconditions:
    -  An OpenWrt device is configured to accept SSH connections using the public key associated with the distributed `testing_rsa` private key. This is likely the default configuration for devices intended to be used with the `mobly-wifi` library, or devices configured according to the library's instructions.
    -  The attacker has obtained the `testing_rsa` private key. This key is easily accessible as it is publicly hosted and distributed with the `mobly-wifi` package.
    -  The attacker knows or can discover the IP address or hostname of the target OpenWrt device.

- Source Code Analysis:
    -  **/code/README.md**: The "One-Time Setup on Host" section instructs users to:
        > "Get the SSH identity key to OpenWrt devices [here](https://chromium.googlesource.com/chromiumos/chromite/+/master/ssh_keys/testing_rsa?pli=1), put it at `~/.ssh/testing_rsa`."
        This clearly directs users to download and use a shared private key.
    -  **/code/mobly/controllers/wifi/openwrt_device.py**:
        -  Defines `_SSH_KEY_IDENTITY = os.path.join( os.path.dirname(os.path.abspath(__file__)), 'data/testing_rsa' )`. This line hardcodes the path to the `testing_rsa` private key within the library.
        -  In the `_create_ssh_client` method, the code checks if a password is provided in the configuration. If no password is provided (`self._password is None`), it instantiates `ssh_lib.SSHProxy` using the `keyfile=_SSH_KEY_IDENTITY`. This means that by default, the library will attempt to connect to OpenWrt devices using the `testing_rsa` private key if no password is given in the configuration.
        ```python
        def _create_ssh_client(self) -> ssh_lib.SSHProxy:
            if self._password is None:
              return ssh_lib.SSHProxy(
                  hostname=self._hostname,
                  ssh_port=self._ssh_port,
                  username=self._username,
                  keyfile=_SSH_KEY_IDENTITY, # Using default insecure key
              )
            else:
              return ssh_lib.SSHProxy(
                  hostname=self._hostname,
                  ssh_port=self._ssh_port,
                  username=self._username,
                  password=self._password,
              )
        ```
    -  Example configuration files like `/code/examples/config_hello_world_test.yml` and `/code/examples/config_simple_connect_test.yml` do not include password or key configurations, reinforcing the default usage of the insecure `testing_rsa` key.

- Security Test Case:
    1.  **Setup:**
        -  Prepare an attacker machine with internet access and an SSH client installed.
        -  Identify a publicly accessible OpenWrt device that is intended to be controlled by `mobly-wifi` or configure a test OpenWrt device for this purpose, ensuring it is reachable from the attacker machine. Assume the OpenWrt device is configured to accept the public key corresponding to `testing_rsa` (default configuration or as per library instructions).
    2.  **Vulnerability Exploitation:**
        -  **Obtain the private key:** Download the `testing_rsa` private key from the URL provided in the `README.md` (`https://chromium.googlesource.com/chromiumos/chromite/+/master/ssh_keys/testing_rsa?pli=1`) or locate it within the installed `mobly-wifi` package in the `data/` directory.
        -  **Attempt SSH Connection:** Use the `ssh` command from the attacker machine to connect to the target OpenWrt device. The command should look like this (replace `OPENWRT_IP_ADDRESS` with the actual IP address of the OpenWrt device and adjust the username if necessary, default is often `root`):
            ```bash
            ssh -i testing_rsa root@OPENWRT_IP_ADDRESS
            ```
            Ensure the `testing_rsa` file has restricted permissions (e.g., `chmod 600 testing_rsa`).
        -  **Verify Unauthorized Access:** If the SSH connection is established successfully without prompting for a password, it confirms that the OpenWrt device is vulnerable due to the insecure default SSH key. The attacker will have a shell prompt on the OpenWrt device, indicating successful unauthorized access.
    3.  **Expected Result:** The attacker should gain shell access to the OpenWrt device without providing a password, demonstrating the vulnerability.