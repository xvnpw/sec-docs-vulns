- vulnerability name: Insecure Storage of Device Authentication Credentials in Environment Variables
- description: |
  The Azure IoT Device SDK for Python, by default, reads device authentication credentials, such as connection strings, symmetric keys, and x.509 certificate paths, from environment variables.
  This practice can lead to vulnerabilities if not handled carefully by the user application, as environment variables are often stored in plain text and can be unintentionally exposed or logged.

  An attacker who gains unauthorized access to the environment where the application is running can easily retrieve these credentials and use them to impersonate the IoT device.

  Steps to trigger vulnerability:
  1. A developer creates an IoT application using Azure IoT Device SDK for Python.
  2. The developer follows the documentation or samples, which instruct them to store device credentials (connection string, symmetric key, x.509 certificate paths) in environment variables (e.g. `IOTHUB_DEVICE_CONNECTION_STRING`, `X509_CERT_FILE`, `X509_KEY_FILE`, `PROVISIONING_SYMMETRIC_KEY`).
  3. The application is deployed to an environment (e.g. device, server, cloud instance).
  4. An attacker gains unauthorized access to this environment through some means (e.g. exploiting other vulnerabilities, social engineering, physical access).
  5. The attacker inspects the environment variables and retrieves the device authentication credentials stored in plain text.
  6. The attacker can now use these stolen credentials to impersonate the IoT device and perform malicious actions, such as sending fabricated telemetry data or controlling the device via direct methods or device twins.
- impact: |
  Compromise of device authentication credentials can lead to complete control over the IoT device.
  An attacker can:
  - Impersonate the device and send malicious data to Azure IoT Hub, potentially corrupting data or disrupting services relying on device telemetry.
  - Steal data from device-to-cloud messages.
  - Control the device by sending commands (direct methods) or modifying device configuration (device twins).
  - Potentially use the compromised device as a pivot point to attack other parts of the system.
- vulnerability rank: High
- currently implemented mitigations:
  - None in code, but documentation mentions environment variables as just one option, and users can choose other more secure methods.
  - Documentation contains a wiki page about pitfalls, but it does not specifically mention the risk of storing credentials in environment variables.
- missing mitigations: |
  - The SDK should strongly discourage storing credentials in environment variables in documentation and samples, and instead promote more secure alternatives.
  - The SDK documentation and samples should provide guidance on secure credential management, such as using secure storage mechanisms (e.g. hardware security modules, secure enclaves, key vaults, encrypted files) or credential injection techniques.
  - Consider adding security best practices directly in SDK documentation, and potentially in code, e.g. warnings during development if environment variables are used for credentials.
- preconditions:
  - Application using Azure IoT Device SDK for Python is deployed in an environment.
  - Device authentication credentials are stored in environment variables within that environment.
  - Attacker gains unauthorized access to the environment.
- source code analysis: |
  - The source code itself does not introduce this vulnerability, but the SDK's design and documentation promotes usage of environment variables for storing credentials.
  - Files like `/code/samples/README.md`, `/code/samples/async-hub-scenarios/README.md`, `/code/samples/sync-samples/README.md`, `/code/samples/pnp/README.md`, `/code/samples/how-to-guides/connect_retry_with_telemetry.md`, `/code/devbox_setup.md`, `/code/migration_guide.md`, `/code/sdklab/meantimerecovery/README.md` all either explicitly mention or imply using environment variables for storing credentials.
  - Code examples in `/code/samples` directory directly use `os.getenv()` to retrieve credentials from environment variables.
  - The `SymmetricKeyAuthenticationProvider` and `SharedAccessSignatureAuthenticationProvider` in `/code/doc` and source code are designed to parse credentials from strings, which can be easily read from environment variables.
- security test case: |
  1. Create a Python IoT device application using the Azure IoT Device SDK for Python, following the quickstart guide in `/code/samples/README.md`.
  2. In the application code, use `os.getenv("IOTHUB_DEVICE_CONNECTION_STRING")` to retrieve the device connection string from environment variables as shown in the quickstart guide.
  3. Set the `IOTHUB_DEVICE_CONNECTION_STRING` environment variable with a valid device connection string.
  4. Run the application and verify that it successfully connects to Azure IoT Hub and sends telemetry data.
  5. As an attacker, gain access to the environment where the application is running (this step depends on the specific deployment environment and is outside the scope of this test case, assume attacker has shell access to the environment).
  6. In the attacker's shell, inspect the environment variables (e.g., using `printenv` or `set` command in Linux/macOS or `Get-ChildItem Env:` in PowerShell on Windows).
  7. Verify that the `IOTHUB_DEVICE_CONNECTION_STRING` environment variable is present and contains the device connection string in plain text.
  8. Copy the value of `IOTHUB_DEVICE_CONNECTION_STRING`.
  9. As an attacker, use a separate tool (e.g., Azure IoT Explorer, `az iot hub send-d2c-message` CLI command) and configure it to connect to the Azure IoT Hub using the stolen connection string.
  10. Verify that the attacker can successfully connect to the IoT Hub using the stolen credentials and perform actions like sending messages as the compromised device or invoking direct methods.