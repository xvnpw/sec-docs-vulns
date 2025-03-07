### Vulnerability List

- Vulnerability Name: Insecure Storage of Device Credentials in Samples

- Description:
    - Step 1: An attacker gains access to the project's GitHub repository, specifically the `samples` directory.
    - Step 2: The attacker reviews the sample code, such as `simple_send_message.py` or files in `async-hub-scenarios` and `sync-samples` directories.
    - Step 3: The attacker identifies that the samples instruct users to store the device connection string directly in environment variables (e.g., `IOTHUB_DEVICE_CONNECTION_STRING`).
    - Step 4: The attacker understands that developers following these samples might hardcode or store connection strings insecurely in real-world applications, making them vulnerable if these credentials are exposed.

- Impact:
    - If developers follow the sample code's insecure credential management practices, they may inadvertently expose device connection strings.
    - Attackers who gain access to these exposed credentials can impersonate the IoT device.
    - This can lead to unauthorized access to the IoT Hub, data manipulation, device control hijacking, and other malicious activities.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None in code. The README.md and samples/README.md contain documentation that guides users to manage connection strings, but it does not enforce secure practices in code, and examples encourage insecure practices.
    - README.md and samples/README.md refer to a wiki page about [**common pitfalls**](https://github.com/Azure/azure-iot-sdk-python/wiki/pitfalls) which mentions "Using Connection Strings Incorrectly".

- Missing Mitigations:
    - Secure credential management guidance and enforcement in sample code.
    - Code examples demonstrating secure credential handling using secure key vaults or configuration files instead of environment variables or hardcoding.
    - Security linter or static analysis tools to detect hardcoded credentials in code.
    - Emphasize in documentation and samples the security risks of using connection strings directly in code and environment variables in production.

- Preconditions:
    - Developers use the Azure IoT Device SDK for Python and follow the insecure credential management practices demonstrated in the provided samples.
    - Attackers gain access to systems or repositories where developers have stored these insecure credentials.

- Source Code Analysis:
    - File: `/code/samples/README.md` and `/code/samples/async-hub-scenarios/README.md` and `/code/samples/sync-samples/README.md`
    - Step 1: The README.md files in the `samples`, `async-hub-scenarios`, and `sync-samples` directories instruct users to set the `IOTHUB_DEVICE_CONNECTION_STRING` environment variable.
    - Step 2: The sample code, like `simple_send_message.py`, directly retrieves the connection string from the environment variable using `os.getenv("IOTHUB_DEVICE_CONNECTION_STRING")` and uses it to create the `IoTHubDeviceClient`.
    - Step 3: This practice is repeated across multiple samples in different directories, consistently showing insecure credential management as the primary method.

- Security Test Case:
    - Step 1: Deploy a sample application from the repository, for example `simple_send_message.py`, following the instructions in `/code/samples/README.md`.
    - Step 2: Set the `IOTHUB_DEVICE_CONNECTION_STRING` environment variable with a valid device connection string for testing purposes.
    - Step 3: Run the sample application to ensure it connects to the IoT Hub and sends messages.
    - Step 4: Examine the running environment of the sample application and confirm that the connection string is stored in plain text in the environment variables.
    - Step 5: As an attacker, simulate gaining access to the environment where the application is running (e.g., through a compromised system or repository access).
    - Step 6: Extract the `IOTHUB_DEVICE_CONNECTION_STRING` environment variable in plain text.
    - Step 7: Use the extracted connection string to create a new `IoTHubDeviceClient` instance outside of the original application's environment.
    - Step 8: Connect to the IoT Hub using the new `IoTHubDeviceClient` instance and perform unauthorized actions, such as sending telemetry or controlling the device twin, proving successful impersonation due to insecure credential exposure.