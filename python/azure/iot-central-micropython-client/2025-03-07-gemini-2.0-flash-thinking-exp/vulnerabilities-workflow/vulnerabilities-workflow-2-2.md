### Vulnerability List

- Vulnerability Name: Missing TLS/SSL Certificate Verification
- Description: The MicroPython library for Azure IoT Central establishes secure connections using TLS/SSL for both MQTT and HTTPS communications. However, it fails to implement certificate verification during the TLS/SSL handshake. This omission means the client does not validate the server's certificate against a trusted Certificate Authority (CA) store.

  Steps to trigger the vulnerability:
  1. An attacker sets up a Man-in-the-Middle (MitM) proxy to intercept network traffic between the MicroPython device and Azure services (Azure IoT Central and DPS endpoints).
  2. The attacker configures the MitM proxy to dynamically generate and present forged TLS/SSL certificates for the domains used by the IoT Central client (e.g., `global.azure-devices-provisioning.net` for DPS and the specific IoT Hub hostname).
  3. The MicroPython device, using this library, attempts to connect to Azure IoT Central through the attacker's network.
  4. The library establishes a TLS/SSL connection with the MitM proxy, accepting the forged certificate without performing proper verification against a trusted CA.
  5. The attacker can now intercept, decrypt, and manipulate all communication between the device and Azure services.

- Impact: High. Successful exploitation of this vulnerability allows a Man-in-the-Middle attacker to:
  - Intercept and read sensitive data transmitted between the device and Azure IoT Central, including telemetry data, property updates, commands, and device credentials.
  - Modify data in transit, allowing the attacker to inject false telemetry data, alter property values, or send unauthorized commands to the device or to Azure IoT Central.
  - Impersonate the legitimate Azure IoT Central server, potentially leading to further attacks such as device hijacking or denial of service.
  - Compromise the confidentiality, integrity, and availability of the IoT system.

- Vulnerability Rank: High

- Currently Implemented Mitigations: None. While the library uses `ssl=True` to enable TLS/SSL for MQTT and HTTPS connections, there is no implementation of certificate verification to validate the server's identity.

- Missing Mitigations:
  - Implement TLS/SSL certificate verification for MQTT connections. This requires configuring the `umqtt.robust.MQTTClient` to use a CA certificate bundle to validate the server certificate during the TLS/SSL handshake.
  - Implement TLS/SSL certificate verification for HTTPS connections used during device provisioning. This requires configuring the `urequests` library to use a CA certificate bundle to validate server certificates when making HTTPS requests to the Device Provisioning Service (DPS).

- Preconditions:
  - The attacker must be positioned to perform a Man-in-the-Middle attack, typically by being on the same network as the IoT device or by controlling a network element in the communication path between the device and the internet.
  - The IoT device must be configured to use this MicroPython library to connect to Azure IoT Central.

- Source Code Analysis:
  - `iotc/__init__.py`:
    ```python
    from umqtt.robust import MQTTClient
    ...
    self._mqtt_client = MQTTClient(self._device_id, creds.host, 8883, creds.user.encode(
        'utf-8'), creds.password.encode('utf-8'), ssl=True, keepalive=60)
    ```
    - The `MQTTClient` is initialized with `ssl=True`, which enables TLS/SSL. However, there are no parameters provided to configure certificate verification, such as specifying a CA certificate bundle. This means the default behavior of `umqtt.robust` is being used, which might not include certificate verification by default in MicroPython environments for resource optimization.

  - `iotc/provision.py`:
    ```python
    import urequests
    ...
    uri = "https://{}/{}/registrations/{}/register?api-version={}".format(
        self._endpoint, self._scope_id, self._registration_id, self._api_version)
    response = urequests.put(
        uri, data=json.dumps(body), headers=self._headers)
    ...
    uri = "https://{}/{}/registrations/{}/operations/{}?api-version={}".format(
        self._endpoint, self._scope_id, self._registration_id, operation_id, self._api_version)
    response = urequests.get(uri, headers=self._headers)
    ```
    - The `urequests` library is used to make HTTPS requests to the DPS endpoint. The URLs start with `https://`, indicating TLS/SSL is used. However, similar to the MQTT client, there is no explicit configuration for certificate verification when using `urequests`. This relies on the default behavior of `urequests`, which might also lack certificate verification by default in MicroPython.

- Security Test Case:
  1. **Environment Setup:**
     - Install `mitmproxy` or a similar MitM proxy tool on a computer.
     - Configure the computer running `mitmproxy` as a gateway or proxy for the network where the MicroPython device will operate.
     - Generate a forged TLS/SSL certificate for `global.azure-devices-provisioning.net` and the expected IoT Hub hostname using `mitmproxy` or `openssl`. Configure `mitmproxy` to use this forged certificate for these domains.
  2. **Device Configuration:**
     - Flash the MicroPython firmware onto a supported device (e.g., Raspberry Pi Pico W).
     - Configure the device to connect to the network where the MitM proxy is active.
     - Modify the `samples/main.py` script with valid device credentials (scope ID, device ID, key).
     - Ensure the `samples/main.py` is set to run on the MicroPython device.
  3. **Run MitM Proxy:**
     - Start `mitmproxy` on the computer, listening on the appropriate port and configured to intercept and forge certificates as described in step 1.
  4. **Execute Test:**
     - Run `samples/main.py` on the MicroPython device.
     - Observe the output of `mitmproxy`. Verify that the device successfully establishes both HTTPS connections to DPS during provisioning and MQTT connection to the assigned IoT Hub, even though `mitmproxy` is presenting forged certificates. There should be no certificate-related errors or warnings from the MicroPython client.
     - In `mitmproxy`, inspect the intercepted HTTPS and MQTT traffic. Confirm that you can see the unencrypted content of the communication, demonstrating successful MitM interception due to the lack of certificate verification on the client side.
  5. **Expected Result:**
     - The MicroPython client connects successfully to Azure IoT Central and DPS without any certificate verification errors, despite the MitM proxy presenting forged certificates.
     - `mitmproxy` successfully intercepts and decrypts the traffic, showing the vulnerability. This confirms that the library is susceptible to MitM attacks due to missing TLS/SSL certificate verification.