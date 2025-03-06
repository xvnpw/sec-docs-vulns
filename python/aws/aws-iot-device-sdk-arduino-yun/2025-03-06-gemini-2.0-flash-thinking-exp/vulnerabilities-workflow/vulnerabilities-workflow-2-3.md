### Vulnerability List

- Vulnerability Name: Insecure Storage of X.509 Certificates and Private Keys
- Description:
    - The AWS IoT Arduino Yún SDK stores X.509 certificates and private keys, used for device authentication, as files on the Arduino Yún's file system.
    - During the SDK installation process, the user is instructed to place these certificate files (root CA, device certificate, and private key) into the `AWS-IoT-Python-Runtime/certs` directory on their computer.
    - The installation scripts then upload the entire `AWS-IoT-Python-Runtime` directory, including the `certs` directory and its contents, to the `/root/` directory on the Arduino Yún board via SCP.
    - These certificate files are stored in plaintext within the `/root/AWS-IoT-Python-Runtime/certs` directory on the Arduino Yún's file system.
    - If an attacker gains unauthorized access to the Arduino Yún board, they can navigate to this directory and read the certificate and private key files.
    - Extracting these credentials allows the attacker to impersonate the legitimate Arduino Yún device when communicating with AWS IoT.
- Impact:
    - **Device Impersonation:** An attacker can use the extracted X.509 certificates and private keys to impersonate the compromised Arduino Yún device.
    - **Unauthorized Access to AWS IoT Resources:** By impersonating the device, the attacker gains unauthorized access to the AWS IoT resources associated with that device.
    - **Data Manipulation and Control:** The attacker can then publish malicious data to MQTT topics, subscribe to sensitive data from MQTT topics, and manipulate the device's Thing Shadow, potentially disrupting operations or controlling connected devices.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The SDK and installation process do not implement any measures to protect the stored certificates and private keys on the Arduino Yún board.
- Missing Mitigations:
    - **Encryption at Rest:** The certificate and private key files should be encrypted when stored on the Arduino Yún's file system. This would prevent unauthorized access even if an attacker gains access to the file system.
    - **Secure Storage Mechanisms:**  Consider utilizing secure storage mechanisms provided by the Arduino Yún hardware or software, if available, to store credentials more securely than plaintext files. This could involve using hardware security modules (HSMs) or secure elements, although feasibility on Arduino Yún might be limited.
    - **User Warnings and Best Practices:** The documentation and setup instructions should explicitly warn users about the security risks of storing credentials in plaintext on the device. Recommend best practices for securing the Arduino Yún, such as changing default SSH passwords and limiting network access.
- Preconditions:
    - The user must have installed the AWS IoT Arduino Yún SDK on an Arduino Yún board.
    - The user must have configured the SDK to use X.509 certificate-based authentication and uploaded the necessary certificate files as instructed.
    - An attacker must gain unauthorized access to the Arduino Yún board. This could be achieved through various means, such as:
        - Exploiting vulnerabilities in the Arduino Yún's firmware or operating system.
        - Using default SSH credentials ("root", "arduino") if the user has not changed them.
        - Gaining physical access to the device.
        - Exploiting other network vulnerabilities to access the device's file system.
- Source Code Analysis:
    - **README.md:** The "Credentials" section explicitly states: "You must upload these credentials along with the Python runtime code base to AR9331 on Yún board and specify the location of these files in a configuration file `aws_iot_config.h`." This indicates that the credentials are stored as files on the Yún's file system.
    - **AWSIoTArduinoYunInstallAll.sh & AWSIoTArduinoYunScp.sh:** These scripts are responsible for uploading the `AWS-IoT-Python-Runtime` directory, which includes the `certs` directory containing the certificate files, to the `/root/` directory on the Arduino Yún. The scripts use SCP for file transfer, but do not implement any encryption or secure storage for the credentials once they are on the device.
    - The code does not include any functionality for encrypting or securely managing the certificate files. The Python runtime and Arduino library rely on reading these files directly from the file system paths configured in `aws_iot_config.h`.
- Security Test Case:
    1. **Setup:**
        - Install the AWS IoT Arduino Yún SDK on an Arduino Yún board following the instructions in the README.
        - Configure the SDK to use X.509 certificate-based authentication. Ensure you have generated and placed valid X.509 certificates and a private key in the `AWS-IoT-Python-Runtime/certs` directory on your computer before running the installation script.
        - Connect the Arduino Yún to a network and obtain its IP address.
    2. **Gain Unauthorized Access:**
        - Assume the attacker gains unauthorized access to the Arduino Yún. A simple method for testing purposes is to use SSH with the default credentials (if not changed):
            ```bash
            ssh root@<Arduino_Yun_IP_Address>
            ```
            (Password: arduino)
        - In a real-world scenario, attackers might use more sophisticated methods to gain access.
    3. **Navigate to Credentials Directory:**
        - Once logged in via SSH, navigate to the directory where the certificates are stored:
            ```bash
            cd /root/AWS-IoT-Python-Runtime/certs
            ls -l
            ```
        - Observe the certificate files (e.g., `aws-iot-rootCA.crt`, `cert.pem`, `privkey.pem`).
    4. **Extract Credentials:**
        - Read the contents of the private key file (e.g., `privkey.pem`) to extract the private key:
            ```bash
            cat privkey.pem
            ```
        - Copy the output, which is the plaintext private key. You can do the same for the certificate file (`cert.pem`) if needed.
    5. **Impersonate Device:**
        - On a separate computer, use an MQTT client (like `mosquitto_pub` or a Python MQTT client) or the AWS CLI to attempt to connect to AWS IoT using the extracted X.509 certificate and private key.
        - For example, using `mosquitto_pub` (replace placeholders with your actual values):
            ```bash
            mosquitto_pub -h <Your_AWS_IoT_Endpoint> -p 8883 --qos 1 -t "test/topic" -m "Impersonated message" --cert cert.pem --key privkey.pem --cafile aws-iot-rootCA.crt --id "ImpersonatedClient"
            ```
            (You would need to transfer the `cert.pem`, `privkey.pem`, and `aws-iot-rootCA.crt` files to the machine running `mosquitto_pub` or configure the paths accordingly).
        - If successful, you will be able to publish messages to AWS IoT as if you were the compromised Arduino Yún device.
    6. **Verification:**
        - Check the AWS IoT console or subscribe to the "test/topic" to confirm that the message published from the impersonated client is received by AWS IoT, demonstrating successful device impersonation using the extracted credentials.

This vulnerability allows a threat actor with unauthorized access to the Arduino Yún to extract sensitive credentials and fully compromise the device's identity in AWS IoT.