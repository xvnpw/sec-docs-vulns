## Combined Vulnerability List

This document outlines identified vulnerabilities by combining and deduplicating information from provided vulnerability lists. Each vulnerability is described in detail, including its potential impact, rank, and steps for mitigation and testing.

### 1. Insecure Storage of X.509 Certificates and Private Keys

- **Description:**
  - The AWS IoT Arduino Yún SDK installation process instructs users to manually place X.509 certificates, private keys, and root CA certificates in the `/root/AWS-IoT-Python-Runtime/certs` directory on the Arduino Yún's filesystem. These files are stored in plaintext. An attacker gaining unauthorized access to the Arduino Yún device (through physical access, network vulnerabilities, or compromised Wi-Fi) can read these files, extract the X.509 certificate and private key, and impersonate the Arduino Yún device. The attacker can connect to AWS IoT using the stolen credentials and perform actions as the legitimate device, subject to its AWS IoT policies.

- **Impact:**
  - **Device Impersonation:** An attacker can fully impersonate the compromised Arduino Yún device.
  - **Unauthorized Access to AWS IoT Resources:** The attacker gains unauthorized access to AWS IoT services and resources associated with the device.
  - **Data Breaches:** The attacker could access and potentially exfiltrate data streams intended for the legitimate device.
  - **Control of IoT Devices:** If the compromised device controls other IoT devices, the attacker could manipulate them, leading to physical consequences.
  - **Reputation Damage:** Device compromise and unauthorized AWS access can damage the reputation of the user or organization.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
  - None. The project provides no mitigations for insecure credential storage. The documentation only guides users on placing credentials on the device.

- **Missing Mitigations:**
  - **Secure Storage Mechanisms:** Implement secure storage for X.509 certificates and private keys, such as:
    - **Encrypted Filesystem Partition:** Storing credentials on an encrypted partition.
    - **Hardware Security Module (HSM) or Secure Element:** Using dedicated hardware for secure key storage (less feasible on standard Arduino Yún).
    - **Secure Enclaves/Trusted Execution Environments (TEEs):** Utilizing TEEs if supported by hardware (not natively supported by Arduino Yún).
  - **Documentation and Best Practices:** At minimum, documentation should:
    - **Clearly warn users** about the risks of plaintext credential storage.
    - **Recommend best practices** for securing the Arduino Yún (password changes, Wi-Fi security, physical access control).
    - **Explore and document limited software-based mitigations**, like restricting file system permissions (easily bypassed by root).

- **Preconditions:**
  - Successful installation of the SDK and placement of X.509 certificates and private keys in `/root/AWS-IoT-Python-Runtime/certs`.
  - Unauthorized access to the Arduino Yún device via:
    - Physical Access
    - Network Vulnerabilities
    - Compromised Wi-Fi
    - Default Credentials (e.g., default SSH password 'arduino')

- **Source Code Analysis:**
  - **`AWSIoTArduinoYunInstallAll.sh`**: Copies `AWS-IoT-Python-Runtime` directory, including `certs`, to `/root/` on Arduino Yún, placing certificate files in plaintext.
  - **`AWSIoTArduinoYunScp.sh`**: Uses `scp` for secure transfer, but the destination `/root/AWS-IoT-Python-Runtime/certs` is not a secure storage location.
  - **`AWS-IoT-Python-Runtime/runtime/runtimeHub.py`**: Python runtime expects credentials in plaintext at configured paths for TLS handshake.
  - **`README.md` (Credentials Section)**: Explicitly instructs users to store credentials in `AWS-IoT-Arduino-Yun-SDK/AWS-IoT-Python-Runtime/certs` in plaintext without security warnings.

- **Security Test Case:**
  1. **Setup:** Install SDK, configure X.509 authentication, place certificates in `AWS-IoT-Python-Runtime/certs`, and run `AWSIoTArduinoYunInstallAll.sh`.
  2. **Gain SSH Access:** SSH into Arduino Yún as `root` (default password 'arduino').
  3. **Navigate to Credentials Directory:** `cd /root/AWS-IoT-Python-Runtime/certs`.
  4. **Verify Plaintext Storage:** `ls -l` to list files; observe `cert.pem`, `privkey.pem`, `aws-iot-rootCA.crt`.
  5. **Read Credential Files:** `cat cert.pem`, `cat privkey.pem`, `cat aws-iot-rootCA.crt` to read plaintext credentials.
  6. **Impersonation (Optional):** Use stolen credentials to connect to AWS IoT from another environment as the compromised device.

---

### 2. Insecure Storage of AWS IAM Credentials

- **Description:**
  - When using Websocket connections with IAM authentication, the SDK documentation and scripts instruct users to store AWS Access Key ID and AWS Secret Access Key insecurely. This can occur in two primary ways:
    - **Environment Variables:** The `AWSIoTArduinoYunWebsocketCredentialConfig.sh` script guides users to store IAM credentials as environment variables in `/etc/profile`. Environment variables in system-wide configuration files are not secure storage and are accessible to users with sufficient privileges or through process introspection.
    - **Hardcoding in Sketch:** Users might mistakenly or intentionally hardcode their AWS Access Key ID and AWS Secret Access Key directly into the Arduino sketch code for simplicity. This could involve embedding credentials as string literals within the code.
  - An attacker who gains unauthorized access to the Arduino Yún can retrieve these IAM credentials. Access to `/etc/profile` or system environment variables allows extraction of credentials stored as environment variables. Access to the sketch code (through various means like public sharing or compromised development environment) allows extraction of hardcoded credentials. With these IAM credentials, the attacker can authenticate to AWS services as the associated IAM role and perform unauthorized actions on AWS IoT and other AWS services based on the IAM role's permissions.

- **Impact:**
  - **IAM Role Impersonation:** An attacker can impersonate the IAM role configured on the Arduino Yún.
  - **Unauthorized Access to AWS Services:** The attacker gains unauthorized access to AWS services (including AWS IoT) and resources associated with the IAM role.
  - **Data Breaches and Resource Manipulation:** Depending on IAM policy, the attacker can access, modify, or delete data in AWS, control IoT devices, and incur AWS costs.
  - **Lateral Movement in AWS:** Overly permissive IAM policies could allow lateral movement to compromise other AWS resources.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
  - None. The project lacks mitigations for insecure IAM credential storage. Documentation and scripts promote insecure environment variable storage. No measures prevent hardcoding in sketches.

- **Missing Mitigations:**
  - **Secure Credential Management:** Implement secure IAM credential management, ideally avoiding long-term keys on the device:
    - **AssumeRole with Web Identity:** If feasible for Arduino Yún, use AssumeRole with Web Identity to avoid direct credential storage.
    - **Temporary Credentials:** Implement fetching temporary IAM credentials from a secure service at runtime.
    - **Credential Rotation:** If long-term keys are necessary, implement robust credential rotation and minimize key lifespan.
  - **Documentation and Best Practices:** Documentation should:
    - **Clearly warn users** about significant risks of storing IAM credentials as environment variables, especially in `/etc/profile`, and hardcoding in sketches.
    - **Strongly discourage** these practices and recommend secure alternatives.
    - **If environment variable storage is unavoidable**: guide on restricting file permissions on `/etc/profile` (limited security), minimizing IAM permissions (least privilege), regular credential rotation, and robust device security.
    - **Explicitly warn against hardcoding** credentials in sketches and provide secure coding examples.

- **Preconditions:**
  - Websocket connection with IAM authentication is configured.
  - User executes `AWSIoTArduinoYunWebsocketCredentialConfig.sh` or hardcodes credentials in the sketch.
  - Unauthorized access to Arduino Yún device is gained.

- **Source Code Analysis:**
  - **`AWSIoTArduinoYunWebsocketCredentialConfig.sh`**: Modifies `/etc/profile` to add `export AWS_ACCESS_KEY_ID` and `export AWS_SECRET_ACCESS_KEY` lines, storing credentials in plaintext environment variables.
  - **`README.md` (Credentials Section and Installation Instructions)**: Guides users to use `AWSIoTArduinoYunWebsocketCredentialConfig.sh` or manually modify `/etc/profile` for IAM credentials, reinforcing insecure environment variable storage.
  - **`AWS-IoT-Python-Runtime/runtime/runtimeHub.py`**: Python runtime relies on AWS IoT Python SDK to retrieve IAM credentials from environment variables `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`.

- **Security Test Case:**
  1. **Setup (Environment Variables):** Configure Websocket/IAM, run `AWSIoTArduinoYunWebsocketCredentialConfig.sh`.
  2. **Gain SSH Access:** SSH into Arduino Yún as `root` (default password 'arduino').
  3. **Read `/etc/profile`:** `cat /etc/profile` to view contents.
  4. **Verify Plaintext IAM Credentials:** Check for `export AWS_ACCESS_KEY_ID` and `export AWS_SECRET_ACCESS_KEY` lines in `/etc/profile`.
  5. **Inspect Environment Variables (Alternative):** `env` command to verify environment variables.
  6. **Impersonation (Optional):** Use stolen IAM credentials to configure AWS CLI and perform actions on AWS IoT.

  **Security Test Case for Hardcoding in Sketch:**
  1. **Setup (Hardcoding):** Configure AWS IoT Arduino Yún SDK for WebSocket with IAM.
  2. **Insecure Credential Storage (Hardcoding in Sketch):** Modify example sketch to directly hardcode AWS Access Key ID and Secret Access Key as string literals.
  3. **Access Sketch/Device:** Assume attacker gains access to the Arduino sketch code.
  4. **Extract Credentials:** Open sketch code, locate and copy hardcoded AWS Access Key ID and Secret Access Key.
  5. **Unauthorized AWS Access:** Configure AWS CLI profile with extracted credentials. Use AWS CLI to interact with AWS IoT (e.g., publish MQTT message).
  6. **Verification:** Check AWS IoT console or subscribe to topic to see message published using hardcoded credentials.

---

### 3. User Callback Buffer Overflow in MQTT Message Handling

- **Description:**
  - An attacker sends a crafted MQTT message to a topic subscribed to by the Arduino Yun. The AWS IoT Arduino Yun SDK Python runtime forwards the payload to the Arduino via Serial1. The Arduino library invokes the user-defined callback function for that topic. If the user callback function lacks buffer size checks when handling the payload, a buffer overflow can occur. The attacker crafts the MQTT message payload to exceed the buffer size in the user callback, overwriting adjacent memory regions.

- **Impact:**
  - Memory corruption on the Arduino Yun device.
  - Potential for arbitrary code execution if the attacker controls the overflow to overwrite critical memory locations.
  - Device compromise, allowing attacker control, data exfiltration, or use as a bot.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
  - None apparent. Documentation mentions `MAX_BUF_SIZE` in `aws_iot_config_SDK.h`, but enforcement in user callbacks and prevention of overflows within user callback logic is unclear. `README.md` highlights user callbacks as a likely attack vector, implicitly acknowledging the risk.

- **Missing Mitigations:**
  - **Input Validation and Sanitization in User Callbacks:**  Strongly advise and provide examples to users on robust input validation and sanitization in message callbacks to prevent buffer overflows. This includes checking payload length against buffer size before processing.
  - **Buffer Size Enforcement in Arduino Library:** Arduino library could strictly enforce `MAX_BUF_SIZE`, potentially truncating messages exceeding the limit before user callbacks. Provide received length to user callbacks for graceful overflow handling.
  - **Secure Coding Guidelines for Users:** Documentation should include explicit secure coding guidelines for callback functions, emphasizing buffer overflow prevention, input validation, and safe string handling in C++.

- **Preconditions:**
  - Arduino Yun connected to AWS IoT and subscribed to an MQTT topic.
  - User-implemented callback function for the subscribed topic in Arduino sketch.
  - User callback function vulnerable to buffer overflows (lacking bounds checking).
  - Attacker can publish MQTT messages to the subscribed topic.

- **Source Code Analysis:**
  - **`README.md` Analysis:** Explicitly points out user callbacks as a potential attack vector for buffer overflows.
  - **`runtimeHub.py` Analysis:** Forwards MQTT message payload to Arduino via serial, but doesn't introduce buffer overflow itself. Vulnerability lies in Arduino C++ library and user callback handling of the payload after serial reception.
  - **Inferred Arduino C++ Library Behavior:** User `message_callback` receives `char* msg` and `unsigned int length`. Vulnerability arises if user's callback copies `msg` to a fixed-size buffer without checking `length`, potentially causing buffer overflow (e.g., using `strcpy` without length checks as shown in example).

- **Security Test Case:**
  1. **Pre-requisites:** Arduino Yun with SDK, AWS IoT connection, subscription to MQTT topic (e.g., "test/topic"), vulnerable callback in sketch (fixed-size buffer, `strcpy` without checks).
  2. **Steps:** Compile and upload vulnerable sketch, ensure device connects and subscribes. From attacker machine, publish MQTT message to "test/topic" with payload exceeding `USER_BUFFER_SIZE`.
  3. **Expected Outcome (Vulnerability Confirmation):** Arduino Yun may crash, reset, or exhibit corrupted serial monitor output due to buffer overflow.
  4. **Mitigation Test:** Modify callback to use `strncpy` with size limit and null termination. Recompile and upload. Repeat steps 2 and 3.
  5. **Expected Outcome (Mitigation Success):** Arduino Yun should not crash; serial monitor shows truncated message without memory corruption.