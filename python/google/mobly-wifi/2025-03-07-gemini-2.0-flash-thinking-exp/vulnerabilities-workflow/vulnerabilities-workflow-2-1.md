### Vulnerability List

* Vulnerability Name: Hardcoded SSH Key for OpenWrt Devices

* Description:
    1. The `mobly-wifi` library's documentation instructs users to download a specific, publicly available SSH private key (`testing_rsa`) for authenticating with OpenWrt devices.
    2. This key, intended for testing, is hosted on a public code repository, making it accessible to anyone.
    3. The `mobly-wifi` library, by default, is configured to use this `testing_rsa` key for SSH authentication when connecting to OpenWrt devices, unless a password is explicitly provided in the configuration.
    4. An attacker who obtains this publicly available `testing_rsa` private key can attempt to establish SSH connections to any OpenWrt device configured to accept the corresponding public key.
    5. If users expose their OpenWrt devices, while running tests with `mobly-wifi`, to a network without proper security configurations and leave SSH accessible with default key-based authentication using the publicly known `testing_rsa` key, external attackers can gain unauthorized access.

* Impact:
    - Unauthorized Access: Attackers can gain shell access to the OpenWrt devices being controlled by the `mobly-wifi` library.
    - Remote Command Execution: Upon successful SSH connection, attackers can execute arbitrary commands on the compromised OpenWrt devices.
    - Device Compromise: Full control over the OpenWrt device, potentially leading to malware installation, configuration changes, or use in further attacks.
    - Network Pivoting: If the compromised OpenWrt device is connected to internal networks, attackers could potentially pivot to other systems within the network.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - None. The library uses the provided key as per the documentation.

* Missing Mitigations:
    - Security Warning: The documentation should include a prominent warning about the severe security risks associated with using a publicly known SSH key in any environment exposed to untrusted networks.
    - Strong Recommendation for Custom Keys: Users should be strongly advised to generate and configure their own unique SSH key pairs for controlling OpenWrt devices, especially in non-isolated test environments or any production-like scenario.
    - Key Generation Guidance: Consider adding guidance or scripts to assist users in generating their own SSH key pairs and securely deploying the public key to their OpenWrt devices.
    - Input for SSH Key Path: Allow users to configure a custom path for the SSH private key within the Mobly configuration, instead of relying on a default hardcoded path and key.

* Preconditions:
    - OpenWrt device is configured to allow SSH key-based authentication.
    - The OpenWrt device's SSH service is running and network accessible.
    - The OpenWrt device is configured to accept the public part of the `testing_rsa` key for authentication (which might be the default configuration for testing OpenWrt images or needs to be manually configured).
    - The user followed the `mobly-wifi` documentation and either placed the publicly known `testing_rsa` private key at `~/.ssh/testing_rsa` on the machine running Mobly, or the `mobly-wifi` library is using the bundled `testing_rsa` key.
    - The OpenWrt device is exposed to a network segment where an attacker can establish network connectivity to the device's SSH port.

* Source Code Analysis:
    - File: `/code/mobly/controllers/wifi/openwrt_device.py`
    - Line defining SSH key path:
        ```python
        _SSH_KEY_IDENTITY = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 'data/testing_rsa'
        )
        ```
        This line hardcodes the path to the `testing_rsa` private key within the `mobly-wifi` library's directory structure. While `data/testing_rsa` itself might not be distributed within the pip package, the documentation explicitly points users to download a well-known public test key.
    - Function `_create_ssh_client`:
        ```python
        def _create_ssh_client(self) -> ssh_lib.SSHProxy:
            if self._password is None:
                return ssh_lib.SSHProxy(
                    hostname=self._hostname,
                    ssh_port=self._ssh_port,
                    username=self._username,
                    keyfile=_SSH_KEY_IDENTITY,
                )
            else:
                return ssh_lib.SSHProxy(
                    hostname=self._hostname,
                    ssh_port=self._ssh_port,
                    username=self._username,
                    password=self._password,
                )
        ```
        This function shows that if no password is provided in the device configuration, the `SSHProxy` is initialized using `keyfile=_SSH_KEY_IDENTITY`. This confirms that by default, the library attempts to authenticate using the hardcoded `testing_rsa` key.
    - File: `/code/README.md`
    - Section: "One-Time Setup on Host"
        ```markdown
        ### One-Time Setup on Host

        Get the SSH identity key to OpenWrt devices
        [here](https://chromium.googlesource.com/chromiumos/chromite/+/master/ssh_keys/testing_rsa?pli=1),
        put it at `~/.ssh/testing_rsa`.
        ```
        This documentation explicitly instructs users to download and use the publicly shared `testing_rsa` key, reinforcing the vulnerability.

* Security Test Case:
    1. **Set up OpenWrt Device:**
        - Deploy an OpenWrt firmware image to a physical or virtual device.
        - Enable SSH server on the OpenWrt device.
        - Configure the OpenWrt SSH server to accept key-based authentication (this is often the default, but ensure it is enabled). If necessary, configure it to specifically accept the public key corresponding to `testing_rsa`.
        - Connect the OpenWrt device to a network where it is reachable by the attacker machine. Note the IP address of the OpenWrt device.
    2. **Prepare Attacker Machine:**
        - Obtain the `testing_rsa` private key. This key is publicly available at the URL provided in the `README.md`: `https://chromium.googlesource.com/chromiumos/chromite/+/master/ssh_keys/testing_rsa?pli=1`. Save this key to a file on the attacker machine, for example, `attacker_key`.
        - Ensure the attacker machine has SSH client installed.
    3. **Run Mobly Test (Optional but for context):**
        - Install the `mobly-wifi` library on a test machine if not already done.
        - Create a Mobly test configuration YAML file (e.g., `test_config.yaml`) that includes the OpenWrt device's IP address under `OpenWrtDevice` controller, and do *not* specify a password. Example:
            ```yaml
            TestBeds:
            - Name: SampleOpenWrtTestbed
              Controllers:
                OpenWrtDevice:
                -  hostname: 'OPENWRT_DEVICE_IP_ADDRESS' # Replace with actual IP
            ```
        - Run a simple Mobly test (like `hello_world_test.py` from examples) using this configuration to confirm basic connectivity if desired. This step is not strictly necessary to demonstrate the vulnerability but helps to set the stage.
    4. **Attempt SSH Access from Attacker Machine:**
        - Open a terminal on the attacker machine.
        - Use the SSH command to connect to the OpenWrt device using the `testing_rsa` private key. Assuming the default username is 'root' (or identify the correct username for the OpenWrt device), and the OpenWrt device's IP is `OPENWRT_DEVICE_IP_ADDRESS`, execute the following command:
            ```bash
            ssh -i attacker_key root@OPENWRT_DEVICE_IP_ADDRESS
            ```
        - If prompted about host key verification, accept and add the host key.
    5. **Verify Unauthorized Access:**
        - If the SSH connection is successful, the attacker will gain a shell prompt on the OpenWrt device without needing a password. This confirms the vulnerability.
        - Execute some commands (e.g., `whoami`, `ifconfig`, `ls /`) on the OpenWrt device through the SSH session to further demonstrate unauthorized command execution.

This test case successfully demonstrates that an attacker with the publicly available `testing_rsa` private key can gain unauthorized SSH access to OpenWrt devices configured as per the `mobly-wifi` documentation, highlighting the high-severity vulnerability of using a shared, public key for device access.