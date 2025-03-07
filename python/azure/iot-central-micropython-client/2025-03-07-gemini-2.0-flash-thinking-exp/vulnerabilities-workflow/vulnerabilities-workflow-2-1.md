### Vulnerability List

- Vulnerability Name: Hardcoded Shared Access Key
- Description:
    - The code examples and documentation provided in this repository demonstrate and encourage the practice of hardcoding Shared Access Keys (SAKs) directly within the device firmware.
    - An attacker who gains unauthorized access to the device's firmware, either through physical access or by exploiting a separate vulnerability allowing firmware extraction, can retrieve these hardcoded SAKs.
    - This vulnerability is triggered when a developer follows the provided examples and embeds the SAK directly into the device code.
- Impact:
    - Exfiltration of the hardcoded SAK allows an attacker to fully impersonate the compromised device within the Azure IoT Central application.
    - The attacker can then:
        - Send fabricated telemetry data, potentially disrupting data analysis and alarming systems.
        - Modify device properties, leading to misconfiguration or unauthorized control of the device.
        - Execute commands on the device if command handling is implemented, potentially causing unintended actions or system compromise.
        - If the compromised key is a group SAS key, the attacker could potentially impersonate other devices within the same group, broadening the attack surface.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The provided examples and documentation actively promote hardcoding the Shared Access Key. There are no warnings against this practice or alternative secure key management methods suggested within the provided files.
- Missing Mitigations:
    - **Secure Key Storage Guidance:** The library and documentation lack any guidance on secure storage of device credentials. Missing are recommendations for:
        - Avoiding hardcoding secrets directly in the firmware.
        - Utilizing secure elements or hardware security modules (HSMs) for key storage when available on the target platform.
        - Employing encrypted storage mechanisms for sensitive credentials within the device firmware.
    - **Secure Provisioning Methods:** The documentation primarily focuses on Shared Access Key authentication and lacks information or examples for more secure provisioning methods such as:
        - Device Provisioning Service (DPS) with X.509 certificates.
        - DPS with Trusted Platform Modules (TPMs).
    - **Key Rotation Best Practices:** There is no mention of key rotation practices to limit the lifespan and potential impact of compromised keys.
    - **Environment Variable/Configuration File Loading:**  The library does not offer or suggest mechanisms to load sensitive credentials from environment variables or external configuration files that are not embedded directly in the firmware image.
- Preconditions:
    - The developer must follow the provided code examples and hardcode the Shared Access Key directly into the device firmware (e.g., within the `main.py` or similar application code).
    - An attacker must gain access to the device firmware. This could be achieved through:
        - Physical access to the device, allowing for firmware dumping via debugging interfaces or memory extraction techniques.
        - Exploiting a software vulnerability that allows for remote firmware extraction or unauthorized file system access on the device.
- Source Code Analysis:
    - **`samples/main.py`**:
        ```python
        key='device or symmetric key'
        conn_type=IoTCConnectType.DEVICE_KEY
        client=IoTCClient(scope_id,device_id,conn_type,key)
        ```
        - This sample code directly assigns the device key as a string literal to the `key` variable. This string is then passed as the `credentials` parameter when instantiating the `IoTCClient`.
        - When this script is compiled and flashed onto a MicroPython device, the Shared Access Key becomes embedded directly within the firmware image.
    - **`README.md`**:
        ```python
        ### Init
        ```py
        from iotc import IoTCConnectType
        id_scope = 'scopeID'
        device_id = 'device_id'
        sasKey = 'masterKey' # or use device key directly
        conn_type=IoTCConnectType.SYMM_KEY # or use DEVICE_KEY if working with device keys
        client = IoTCClient(id_scope, device_id, conn_type, sasKey)
        ```
        - The README.md file further reinforces the insecure practice of hardcoding keys by using the variable name `sasKey = 'masterKey'` and the comment `# or use device key directly`.
        - This example in the official documentation guides developers to directly embed sensitive keys as string literals in their code.

- Security Test Case:
    1. **Setup Development Environment:**
        - Set up a MicroPython development environment suitable for your target device (e.g., Raspberry Pi Pico W).
        - Install the `micropython-iotc` library on your development machine as per the instructions in `README.md`.
    2. **Create Azure IoT Central Resources:**
        - Create an Azure IoT Central application if you don't already have one.
        - Within your IoT Central application, create a new device template.
        - Create a new device instance based on the device template, using "Shared access key" as the authentication type. Note down the Device ID, Scope ID, and Primary Key (which will be used as the Shared Access Key).
    3. **Modify `samples/main.py`:**
        - Open the `samples/main.py` file.
        - Replace the placeholder values for `scope_id`, `device_id`, and `key` with the actual Scope ID, Device ID, and Primary Key obtained from the Azure IoT Central device creation step. Ensure `conn_type` is set to `IoTCConnectType.DEVICE_KEY`.
        ```python
        scope_id='YOUR_SCOPE_ID'
        device_id='YOUR_DEVICE_ID'
        key='YOUR_DEVICE_PRIMARY_KEY'
        conn_type=IoTCConnectType.DEVICE_KEY
        ```
        - Save the modified `main.py`.
    4. **Flash Firmware to Device:**
        - Flash the modified `main.py` script and any necessary MicroPython firmware onto your target device (e.g., Raspberry Pi Pico W). The exact flashing procedure will depend on your device and development environment.
        - After flashing, the device should automatically execute `main.py` upon boot.
    5. **Verify Device Connection:**
        - Monitor the serial output of your MicroPython device (if available) or check the device status in your Azure IoT Central application. The device should connect to IoT Central and start sending telemetry data if the connection is successful.
    6. **Simulate Firmware Extraction (Manual Inspection):**
        - For the purpose of this test, we will simulate firmware extraction by directly accessing the `main.py` file on the device's filesystem. This step would be different in a real attack scenario, potentially involving firmware dumping and reverse engineering.
        - Using a method appropriate for your device (e.g., using `ampy`, `rshell`, or similar tools if your device supports a filesystem interface over USB), access the files on the MicroPython device and open `main.py`.
        - **Observe the hardcoded Shared Access Key:**  You will clearly see the Shared Access Key string literal assigned to the `key` variable within the `main.py` file. This confirms that the key is directly embedded in the code.
    7. **Device Impersonation (Using Extracted Key):**
        - On a separate machine (attacker's machine), install the `micropython-iotc` library if not already installed.
        - Create a new Python script (e.g., `impersonate.py`) on the attacker's machine.
        - In `impersonate.py`, use the *exfiltrated* Shared Access Key (copied from `main.py` in the previous step), along with the same `scope_id` and `device_id`, to instantiate a new `IoTCClient`.
        ```python
        from iotc import IoTCClient, IoTCConnectType

        scope_id = 'YOUR_SCOPE_ID' # Use the same Scope ID
        device_id = 'YOUR_DEVICE_ID' # Use the same Device ID
        key = 'YOUR_DEVICE_PRIMARY_KEY' # Use the EXFILTRATED KEY from main.py
        conn_type = IoTCConnectType.DEVICE_KEY

        impersonator_client = IoTCClient(scope_id, device_id, conn_type, key)
        impersonator_client.connect()

        # Send telemetry as the impersonated device
        impersonator_client.send_telemetry({"impersonation_test": True})
        print("Telemetry sent from impersonator")

        ```
        - Replace `YOUR_SCOPE_ID` and `YOUR_DEVICE_ID` with the same values used in `main.py`. **Crucially, use the *same* `key` that was hardcoded in `main.py`**.
        - Run `impersonate.py` on the attacker's machine.
    8. **Verification of Impersonation in IoT Central:**
        - Go to your Azure IoT Central application and navigate to the device instance you created.
        - Check the telemetry data for the device. You should see telemetry messages with the key `"impersonation_test": True` arriving, even though this telemetry is being sent from the *attacker's* machine using the `impersonate.py` script.
        - This demonstrates successful device impersonation using the exfiltrated hardcoded Shared Access Key. An attacker can now send arbitrary data and potentially control the device's digital twin in IoT Central.

This security test case clearly demonstrates that hardcoding the Shared Access Key, as encouraged by the provided examples, creates a significant vulnerability allowing for device impersonation if the firmware is compromised.