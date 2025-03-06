- Vulnerability Name: Insecure Storage of AWS IAM Credentials
- Description:
    1. An attacker targets a user of the AWS IoT Arduino Yún SDK who is using IAM credentials for WebSocket authentication.
    2. The user, misunderstanding security best practices or for ease of setup, hardcodes their AWS Access Key ID and AWS Secret Access Key directly into the Arduino sketch code. This could be done in various ways, such as:
        - Directly embedding the credentials as string literals in the Arduino sketch file (e.g., in variables or directly passed as arguments if the API was misused in such a way).
        - Storing the credentials in a separate, easily accessible file on the Arduino Yún's file system and then reading them into the sketch.
    3. Alternatively, even if the user follows the documentation and uses the `AWSIoTArduinoYunWebsocketCredentialConfig.sh` script to set environment variables, the security of these credentials then relies entirely on the security of the Yun device itself. If the Yun device is compromised (e.g., through weak SSH passwords, exposed network services, or physical access), an attacker can access these environment variables.
    4. An attacker gains access to the Arduino sketch code (e.g., if the user publicly shares the sketch, if the attacker gains unauthorized access to the user's development environment, or if the Yun device itself is compromised and the sketch is accessible). Or, if environment variables are used, the attacker gains access to the Yun device's shell (e.g., via SSH brute-forcing, exploiting other vulnerabilities on the Yun, or physical access).
    5. If credentials are hardcoded in the sketch, the attacker can directly extract the AWS Access Key ID and AWS Secret Access Key by examining the sketch code. If credentials are in environment variables on a compromised Yun, the attacker can retrieve them from the system's environment.
    6. With the extracted AWS IAM credentials, the attacker can now authenticate to AWS IoT as if they were the legitimate user.
    7. The attacker can perform any actions within AWS IoT that the compromised IAM credentials permit, based on the attached IAM policy. This could include:
        - Publishing and subscribing to MQTT topics, potentially disrupting device communication or injecting malicious data into the IoT system.
        - Interacting with Thing Shadows, allowing them to control devices, steal or modify device state information.
        - Accessing other AWS services if the IAM role associated with the credentials has overly broad permissions.
- Impact:
    - Unauthorized access to the user's AWS IoT resources.
    - Potential data breaches if the attacker accesses sensitive data through MQTT or Thing Shadows.
    - Device hijacking if the attacker gains control over IoT devices through Thing Shadow updates or MQTT commands.
    - Financial implications due to unauthorized use of AWS resources and potential service disruption.
    - Reputational damage for the user or organization employing the vulnerable system.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None in the code itself.
    - The documentation (`README.md`) advises users to use environment variables for IAM credentials and to secure their Yun device, but this is advisory and not enforced by the SDK.
- Missing Mitigations:
    - **Code-level enforcement of secure credential handling:** The SDK does not provide any mechanisms to enforce secure storage or prevent hardcoding of credentials.
    - **Runtime warnings:** The SDK could potentially include checks (though complex and potentially with false positives) to detect if credentials appear to be hardcoded in the sketch and issue warnings during compilation or runtime.
    - **Enhanced documentation and examples:** While the documentation mentions security, it could be further emphasized with more prominent warnings and best practice examples directly within the code examples and configuration files provided with the SDK. For example, comments in `aws_iot_config.h` in example sketches could strongly discourage hardcoding and point to secure alternatives.
- Preconditions:
    - The user opts to use WebSocket authentication with IAM credentials.
    - The user insecurely stores their AWS IAM credentials, either by hardcoding them in the sketch or storing them insecurely on the Yun device.
    - An attacker gains access to the Arduino sketch code or unauthorized access to the Arduino Yun device's operating system.
- Source Code Analysis:
    - The provided source code is primarily documentation and installation scripts. The core Arduino library code that directly handles credentials is not provided in these files.
    - `README.md`:  The "Credentials" section describes both X.509 certificates and IAM credentials. For IAM credentials, it mentions using environment variables and provides the `AWSIoTArduinoYunWebsocketCredentialConfig.sh` script. This script itself, while automating the process, does not inherently enforce secure storage beyond system-level environment variables on the Yun, which are vulnerable if the Yun is compromised. The README warns: "An attacker could potentially gain unauthorized access to a user's AWS IoT resources if the user insecurely stores or exposes their AWS IAM credentials...". This acknowledges the vulnerability but does not provide code-level mitigation.
    - `AWSIoTArduinoYunWebsocketCredentialConfig.sh`: This script automates setting environment variables for AWS IAM credentials. While using environment variables is a step away from hardcoding directly in the sketch, it still leaves the credentials vulnerable if the Yun device's security is compromised. The script doesn't include any security measures like encryption or access control for these variables.
    - The Python runtime code (`AWS-IoT-Python-Runtime/runtime/runtimeHub.py`, `AWS-IoT-Python-Runtime/runtime/run.py`) is responsible for using the credentials to connect to AWS IoT. However, these files are focused on SDK functionality and command processing, not on credential *storage*. They would read the credentials from the environment variables (or potentially from files if configured for certificate-based auth), assuming they are available. The vulnerability exists *before* the SDK code is even executed, in how the user initially stores and protects these credentials.
- Security Test Case:
    1. **Setup:** Configure the AWS IoT Arduino Yún SDK to use WebSocket with IAM credentials. Follow the documentation to set up the Yun and install the SDK.
    2. **Insecure Credential Storage (Hardcoding in Sketch):**
        - Modify the example sketch (e.g., `BasicPubSub` or `ThingShadowEcho`).
        - Instead of relying on environment variables or certificate files, directly hardcode your AWS Access Key ID and AWS Secret Access Key as string literals within the Arduino sketch code. For example, you could modify the `configWss` function (even though it's designed for CA file path, for testing purposes, imagine if you could directly pass keys or simulate a scenario where a user misuses the API or a future version changes). Or, simply create string variables in the sketch and assign your keys to them.
        - Compile and upload this modified sketch to your Arduino Yún.
    3. **Access Sketch/Device:** Assume the role of an attacker who has gained access to the Arduino sketch code (e.g., you cloned a public repository where the user mistakenly committed their sketch with hardcoded credentials, or you gained access to the user's computer).
    4. **Extract Credentials:** Open the Arduino sketch code and easily locate and copy the hardcoded AWS Access Key ID and AWS Secret Access Key.
    5. **Unauthorized AWS Access:**
        - On a separate computer with AWS CLI configured, use the extracted AWS Access Key ID and AWS Secret Access Key to configure a new AWS CLI profile:
          ```bash
          aws configure --profile hacked-yun
          AWS Access Key ID [None]: <YOUR_EXTRACTED_ACCESS_KEY_ID>
          AWS Secret Access Key [None]: <YOUR_EXTRACTED_SECRET_ACCESS_KEY>
          Default region name [None]: <YOUR_AWS_REGION>  (e.g., us-west-2)
          Default output format [None]: json
          ```
        - Use this profile to interact with AWS IoT. For example, publish an MQTT message to a topic in your AWS IoT account:
          ```bash
          aws iot-data publish --topic 'test/hacked' --payload '{"message": "Hacked from Yun credentials"}' --profile hacked-yun
          ```
    6. **Verification:** Check the AWS IoT console or subscribe to the `test/hacked` topic using a legitimate client. You should see the message published using the hardcoded credentials, demonstrating successful unauthorized access.

This test case, while simplified to demonstrate the concept, clearly shows how insecure storage (hardcoding) of IAM credentials leads to a vulnerability allowing unauthorized access to AWS IoT resources. A similar test case could be devised for insecure file storage or compromised Yun device environment variables.