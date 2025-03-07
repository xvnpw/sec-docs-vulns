- Vulnerability Name: Hardcoded SAS keys in example code
- Description: The example code provided in `README.md` and `samples/main.py` demonstrates the initialization of the `IoTCClient` with a Shared Access Signature (SAS) key directly embedded as a string literal in the code. Specifically, lines like `sasKey = 'masterKey'` in `README.md` and `key='device or symmetric key'` in `samples/main.py` illustrate this practice. If developers directly copy and paste these code snippets into their projects without replacing these placeholder keys with secure key management practices, the SAS keys will be hardcoded into the device firmware.
- Impact: If an attacker gains unauthorized access to the device's firmware, they can easily extract the hardcoded SAS keys. These keys grant the attacker the ability to impersonate the device on the Azure IoT Central platform. By impersonating the device, the attacker can send fabricated telemetry data, manipulate device properties, and potentially execute commands, disrupting the IoT application's functionality and data integrity.
- Vulnerability Rank: High
- Currently Implemented Mitigations: None. The project does not currently implement any mitigations against hardcoding SAS keys in the example code or provide sufficient warnings about the risks. The documentation mentions that only SAS key connection is supported currently, but lacks security guidance on key management.
- Missing Mitigations:
    - **Documentation Enhancement:** The documentation should explicitly warn against hardcoding SAS keys and clearly articulate the associated security risks. It should strongly recommend secure key management practices, such as utilizing environment variables, secure storage mechanisms (like dedicated secure elements or encrypted storage partitions), or leveraging device provisioning methods that avoid embedding keys directly in the firmware (e.g., Device Provisioning Service (DPS) with TPM or certificates).
    - **Example Code Modification:** The example code in `README.md` and `samples/main.py` should be revised to avoid showcasing hardcoded keys directly. Instead of `sasKey = 'masterKey'`, the examples should use placeholders like `sasKey = '<YOUR_SAS_KEY>'` and include comments emphasizing the need to replace this placeholder with keys obtained from a secure source or configuration. Ideally, example code should demonstrate reading keys from environment variables or a configuration file to promote better security practices.
- Preconditions:
    - Developers utilize the provided example code as a template for their IoT device applications.
    - Developers fail to recognize the security implications of hardcoded SAS keys and do not implement secure key management practices.
    - An attacker successfully gains access to the device firmware. This could be achieved through various means, including physical access to the device, exploiting software vulnerabilities to gain unauthorized access, or supply chain attacks.
- Source Code Analysis:
    - `README.md`:
        ```markdown
        ### Init
        ```py
        from iotc import IoTCConnectType
        id_scope = 'scopeID'
        device_id = 'device_id'
        sasKey = 'masterKey' # or use device key directly
        conn_type=IoTCConnectType.SYMM_KEY # or use DEVICE_KEY if working with device keys
        client = IoTCClient(id_scope, device_id, conn_type, sasKey)
        ```
        - The line `sasKey = 'masterKey'` directly presents a hardcoded SAS key as an example, which is misleading and insecure.
    - `samples/main.py`:
        ```python
        key='device or symmetric key'
        conn_type=IoTCConnectType.DEVICE_KEY

        client=IoTCClient(scope_id,device_id,conn_type,key)
        ```
        - Similarly, `key='device or symmetric key'` in `samples/main.py` uses a string literal, encouraging insecure practices by example.
- Security Test Case:
    1. **Setup:**
        - Create an Azure IoT Central application instance.
        - Register a new device within the IoT Central application using SAS key authentication.
        - Obtain the primary or secondary SAS key for the registered device.
    2. **Vulnerable Code Implementation:**
        - Modify the `samples/main.py` file.
        - Replace the placeholder values for `scope_id` and `device_id` with the actual Scope ID of your IoT Central application and the Device ID of the registered device, respectively.
        - In the line `key='device or symmetric key'`, replace `'device or symmetric key'` with the actual SAS key obtained in step 1. Ensure the SAS key is directly embedded as a string literal.
        - Flash the modified `samples/main.py` code onto a MicroPython device (e.g., Raspberry Pi Pico W, ESP32).
    3. **Simulate Firmware Extraction:**
        - For the purpose of this test, we will simulate firmware extraction by directly accessing the modified `samples/main.py` file on the development machine or by retrieving the code from the flashed device if possible (depending on device capabilities and access). In a real attack scenario, an attacker would employ techniques to dump the firmware from the device's flash memory.
    4. **SAS Key Extraction:**
        - Open the `samples/main.py` file (or the extracted firmware).
        - Locate the line where the SAS key was hardcoded (`key='YOUR_SAS_KEY'`).
        - The SAS key is now readily visible and extracted, demonstrating the vulnerability.
    5. **Device Impersonation:**
        - Using a separate machine or script (this could even be another MicroPython device or a standard computer with Python and necessary libraries), create a new instance of `IoTCClient`.
        - Initialize this new client using the **extracted SAS key**, along with the same `scope_id` and `device_id` as the original device.
        - Connect the impersonating client to Azure IoT Central.
    6. **Malicious Telemetry Injection:**
        - From the impersonating client, send telemetry data to Azure IoT Central using `client.send_telemetry(...)`. This data can be arbitrary and malicious, demonstrating the attacker's ability to inject false information.
    7. **Verification in Azure IoT Central:**
        - Monitor the device in the Azure IoT Central application.
        - Observe that telemetry data sent from the impersonating client is being received and attributed to the original device identity. This confirms successful device impersonation and the impact of the hardcoded SAS key vulnerability.

This test case successfully demonstrates how hardcoding SAS keys, as shown in the example code, leads to a critical vulnerability where attackers can extract the keys and impersonate devices, compromising the security and integrity of the IoT system.