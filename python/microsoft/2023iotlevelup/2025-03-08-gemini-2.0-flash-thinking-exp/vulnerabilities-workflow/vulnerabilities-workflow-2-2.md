### Vulnerability List

- Vulnerability Name: Insecure Device Authentication using Hardcoded Connection String
- Description:
    - The example code in `lab1.py` demonstrates device authentication using connection strings retrieved from environment variables (`os.getenv("conn_str")`).
    - The README and comments in the code might inadvertently encourage users to directly use or hardcode connection strings for simplicity in testing or development.
    - If users follow this practice and hardcode connection strings in their applications or scripts, especially in production environments, it can lead to unauthorized access to the IoT Hub and potential data breaches.
    - An attacker who gains access to the source code or configuration files where the connection string is hardcoded can impersonate the device and send/receive data, control devices, or disrupt operations.
- Impact:
    - High. Unauthorized access to IoT devices and IoT Hub.
    - Potential data breaches, device manipulation, and disruption of IoT services.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None in the example code itself. The code uses environment variables, which is a better practice than hardcoding directly in the script.
- Missing Mitigations:
    - Explicit warning in README and code comments against hardcoding connection strings.
    - Best practices guidance on secure storage and management of connection strings, such as using secure vaults or configuration management systems.
    - Emphasize the importance of using more secure authentication methods like X.509 certificates or TPM in production.
- Preconditions:
    - User follows the example code and hardcodes the connection string instead of using environment variables or secure configuration management.
    - Attacker gains access to the hardcoded connection string (e.g., through source code repository, configuration file, or compromised system).
- Source Code Analysis:
    - File: `/code/MQTT/lab1.py`
    - Line 2: `conn_str = os.getenv("conn_str")` - This line retrieves the connection string from an environment variable. While this is better than hardcoding, the lack of explicit warnings around the example can lead to insecure practices.
    - Line 8-12: `if conn_str == None: ... quit()` - This check ensures the environment variable is set, but doesn't prevent users from hardcoding for testing, which is a risk if the code is not properly secured later.
    - Review of README files (`/code/README.md`, `/code/IoT Hub & DPS/README.md`, `/code/IoT Hub & DPS/Code/README.md`, `/code/IoTEdge & Microagent/README.md`, `/code/IoTEdge & Microagent/Hands on Lab.md`, `/code/IoTEdge & Microagent/Lab Prerequisites.md`) shows no explicit warnings against hardcoding connection strings in production environments.
- Security Test Case:
    1. Setup:
        - Create an IoT Hub and an IoT device.
        - Obtain the device connection string.
        - Modify `lab1.py` to hardcode the connection string directly in the script: `conn_str = "HostName=YOUR_IOT_HUB_HOSTNAME;DeviceId=YOUR_DEVICE_ID;SharedAccessKey=YOUR_DEVICE_PRIMARY_KEY"`.
        - Run the modified `lab1.py` script and verify successful connection and message sending to IoT Hub.
    2. Exploit:
        - Assume attacker gains access to the modified `lab1.py` and extracts the hardcoded connection string.
        - Attacker uses the extracted connection string with Azure CLI to send a message impersonating the device:
          ```bash
          az iot hub send-d2c-message --hub-name YOUR_IOT_HUB_HOSTNAME --device-id YOUR_DEVICE_ID --body "{\"message\": \"Attacker Message\"}" --connection-string "HostName=YOUR_IOT_HUB_HOSTNAME;DeviceId=YOUR_DEVICE_ID;SharedAccessKey=YOUR_DEVICE_PRIMARY_KEY"
          ```
    3. Verification:
        - Observe that the attacker successfully sends messages to the IoT Hub using the hardcoded connection string, demonstrating unauthorized device access.
        - Check IoT Hub logs to confirm receipt of messages from the device (or attacker impersonating it).