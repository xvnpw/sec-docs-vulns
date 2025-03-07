- ### Vulnerability Name: Use of Publicly Available SSH Private Key for Authentication
- Description:
    - The Mobly WiFi Controller library is designed to control OpenWrt access points via SSH.
    - The setup instructions in the README.md explicitly direct users to download a publicly available SSH private key (`testing_rsa`) from a Chromium project repository and place it in `~/.ssh/`.
    - The `OpenWrtDevice` controller in the library is configured by default to use this `testing_rsa` private key for SSH authentication if no password is provided in the device configuration.
    - An attacker who is aware of this default configuration and has network access to an OpenWrt device configured using the Mobly WiFi Controller and accepting SSH key authentication with the public `testing_rsa` key, can gain unauthorized SSH access to the device.
    - This access can be achieved by simply attempting to SSH into the OpenWrt device's IP address on port 22 using the corresponding public key (since the private key is publicly known).
- Impact:
    - **Critical:** Unauthorized access to OpenWrt devices.
    - Full control over the compromised OpenWrt device, including:
        - Modifying device configurations.
        - Flashing malicious firmware.
        - Monitoring network traffic.
        - Pivoting to other devices on the network.
        - Disrupting network services.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None. The library, by default and through documentation, encourages the use of a publicly known private key.
- Missing Mitigations:
    - **Remove the default usage of the publicly available `testing_rsa` key.**
    - **Discourage users from using the public `testing_rsa` key in documentation.**
    - **Recommend secure key management practices:**
        - Generate unique SSH key pairs for each OpenWrt device.
        - Securely distribute public keys to OpenWrt devices.
        - Keep private keys secret and protected.
        - Use password-based authentication only as a fallback and enforce strong passwords.
    - **Implement a warning during device initialization if default/insecure key is being used.**
- Preconditions:
    - An OpenWrt device is configured to accept SSH key authentication.
    - The OpenWrt device is configured to use the publicly available `testing_rsa` public key (or the default configuration is used which implicitly accepts it).
    - The attacker has network connectivity to the OpenWrt device (no firewall blocking SSH port 22).
    - The attacker is aware of the publicly available `testing_rsa` private key and the default configuration of Mobly WiFi Controller.
- Source Code Analysis:
    - File: `/code/mobly/controllers/wifi/openwrt_device.py`
    - Line 41: `_SSH_KEY_IDENTITY = os.path.join( os.path.dirname(os.path.abspath(__file__)), 'data/testing_rsa' )`
        - This line defines the default path to the SSH private key as `data/testing_rsa` relative to the current file's directory.
        - This implies that the library intends to use or at least point to a private key file located within its distribution.
    - Line 152-163: `def _create_ssh_client(self) -> ssh_lib.SSHProxy: ...`
        - This method creates an `SSHProxy` object to manage the SSH connection.
        - Lines 153-163 check if a password is provided in the configuration (`self._password`).
        - **If no password is provided (which is the likely case for users following the quick start guide and not explicitly setting a password), it defaults to using the `_SSH_KEY_IDENTITY`**: `keyfile=_SSH_KEY_IDENTITY`.
        - This hardcodes the usage of `data/testing_rsa` as the default SSH key if no password is given.
    - File: `/code/README.md`
    - Section "One-Time Setup on Host":
        - `Get the SSH identity key to OpenWrt devices here, put it at ~/.ssh/testing_rsa.`
        - The link points to a publicly accessible `testing_rsa` file in the Chromium OS repository.
        - The documentation explicitly instructs users to download and use this public key, further reinforcing the vulnerability by guiding users to set up insecure authentication.

- Security Test Case:
    - Pre-test setup:
        1. Set up an OpenWrt device with SSH enabled on port 22. Ensure no firewall rules are blocking port 22.
        2. Configure the OpenWrt device to accept SSH key authentication. It's likely that default OpenWrt configurations already allow this, or users might enable it following typical setup guides for SSH key authentication.
        3. Install the `mobly-wifi` library on a host machine.
        4. Create a Mobly test configuration file (YAML) to target the OpenWrt device using its IP address, **without specifying a password in the configuration.** This will trigger the default key-based authentication. Example `config.yml`:
        ```yaml
        TestBeds:
          - Name: AttackerTestbed
            Controllers:
              OpenWrtDevice:
              - hostname: 'OPENWRT_DEVICE_IP' # Replace with the IP address of your OpenWrt device
        ```
        5. Download the public `testing_rsa` private key from the provided Chromium link and place it in `~/.ssh/testing_rsa` on the host machine.
        6. Create a simple Mobly test script (e.g., based on `hello_world_test.py`) that registers and initializes the `OpenWrtDevice` controller. Example `attack_test.py`:
        ```python
        from mobly import base_test
        from mobly import test_runner
        from mobly.controllers.wifi import openwrt_device

        class AttackTest(base_test.BaseTestClass):
          def setup_class(self):
            self.openwrt = self.register_controller(openwrt_device)[0]
          def test_connect_and_execute(self):
            # Attempt to execute a command on the OpenWrt device to verify access.
            result = self.openwrt.ssh.execute_command('uname -a')
            self.openwrt.log.info(f"Command output: {result}")
            assert "Linux" in result # Verify command execution
        if __name__ == '__main__':
          test_runner.main()
        ```

    - Test Execution:
        1. Run the Mobly test script using the created configuration file: `python attack_test.py -c config.yml`

    - Expected Result:
        - The Mobly test should successfully connect to the OpenWrt device via SSH using the `testing_rsa` private key without requiring a password.
        - The command `uname -a` should be successfully executed on the OpenWrt device, and the output should be logged, demonstrating unauthorized access.
        - The assertion `assert "Linux" in result` should pass, confirming successful command execution and hence successful, unauthorized login.

This test case demonstrates how an attacker, using the publicly available private key and the default configuration of the Mobly WiFi Controller, can gain unauthorized access to an OpenWrt device.