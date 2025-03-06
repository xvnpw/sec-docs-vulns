### Vulnerability List

- Vulnerability Name: Insecure Storage of X.509 Certificates and Private Keys

- Description:
  - The AWS IoT Arduino Yún SDK installation process, as documented in `README.md` and implemented in scripts like `AWSIoTArduinoYunInstallAll.sh`, instructs users to manually place X.509 certificates, private keys, and root CA certificates in the `/root/AWS-IoT-Python-Runtime/certs` directory on the Arduino Yún's filesystem.
  - These files are stored in plaintext on the device's filesystem.
  - An attacker who gains unauthorized access to the Arduino Yún device (e.g., through physical access, network vulnerabilities, or compromised Wi-Fi) can read these files.
  - The attacker can then extract the X.509 certificate and private key.
  - With these credentials, the attacker can impersonate the Arduino Yún device.
  - The attacker can connect to AWS IoT using the stolen credentials.
  - The attacker can then perform actions on AWS IoT as if they were the legitimate Arduino Yún device, subject to the permissions granted to the device's certificate in AWS IoT policies.

- Impact:
  - **Device Impersonation:** An attacker can fully impersonate the compromised Arduino Yún device.
  - **Unauthorized Access to AWS IoT Resources:** The attacker gains unauthorized access to AWS IoT services and resources associated with the device.
  - **Data Breaches:** The attacker could access and potentially exfiltrate data streams intended for the legitimate device.
  - **Control of IoT Devices:** If the compromised device is used to control other IoT devices or actuators, the attacker could manipulate these devices, leading to potential physical consequences depending on the application.
  - **Reputation Damage:**  Compromise of devices and unauthorized access to AWS services can damage the reputation of the user or organization deploying these devices.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
  - None. The project provides no mitigations for insecure credential storage. The documentation only instructs users on how to place the credentials on the device.

- Missing Mitigations:
  - **Secure Storage Mechanisms:** Implement secure storage for X.509 certificates and private keys. This could involve:
    - **Encrypted Filesystem Partition:** Storing credentials on an encrypted partition. This adds complexity to setup and requires key management for the encrypted partition.
    - **Hardware Security Module (HSM) or Secure Element:** Using dedicated hardware for secure key storage. This is generally not feasible on standard Arduino Yún hardware without significant modifications.
    - **Secure Enclaves/Trusted Execution Environments (TEEs):** If the underlying hardware supported TEEs, these could be used to isolate and protect credentials. Arduino Yún does not natively support TEEs.
  - **Documentation and Best Practices:** At a minimum, the documentation should:
    - **Clearly warn users** about the risks of storing X.509 certificates and private keys in plaintext on the filesystem.
    - **Recommend best practices** for securing the Arduino Yún device itself, such as changing default passwords, securing Wi-Fi networks, and limiting physical access.
    - **Explore and document potential (though limited) software-based mitigations**, such as restricting file system permissions on the certificate files after installation (though this is easily bypassed by root access).

- Preconditions:
  - **Successful Installation of SDK:** The user must have successfully installed the AWS IoT Arduino Yún SDK and followed the instructions to place X.509 certificates and private keys in the `/root/AWS-IoT-Python-Runtime/certs` directory.
  - **Unauthorized Access to Arduino Yún:** An attacker must gain unauthorized access to the Arduino Yún device. This could be achieved through:
    - **Physical Access:** Directly accessing the device if it is not physically secured.
    - **Network Vulnerabilities:** Exploiting vulnerabilities in the Arduino Yún's operating system, network services, or open ports.
    - **Compromised Wi-Fi:** If the Arduino Yún is connected to a compromised Wi-Fi network, an attacker on the same network could potentially gain access to the device.
    - **Default Credentials:** If the default SSH password for the Arduino Yún ('arduino') is not changed, it becomes trivial for an attacker on the local network to gain root access.

- Source Code Analysis:
  - **`AWSIoTArduinoYunInstallAll.sh`**:
    - This script is used for automated installation.
    - It includes the line: `./AWSIoTArduinoYunScp.sh $yunBoardIP $yunBoardUserName $yunBoardPassword $pyLibDir /root/`
    - `AWSIoTArduinoYunScp.sh` then copies the entire `AWS-IoT-Python-Runtime` directory, including the `certs` directory, to `/root/` on the Arduino Yún.
    - This action places the certificate files directly into the `/root/AWS-IoT-Python-Runtime/certs` directory in plaintext.

  - **`AWSIoTArduinoYunScp.sh`**:
    - This script uses `scp` to securely copy files to the Arduino Yún. However, the destination directory `/root/AWS-IoT-Python-Runtime/certs` is not a secure storage location itself.
    - The script simply facilitates the file transfer to a location where files are stored in plaintext.

  - **`AWS-IoT-Python-Runtime/runtime/runtimeHub.py`**:
    - This Python script is the runtime component that uses the credentials.
    - It is not directly responsible for storing the credentials, but it expects them to be present in the filesystem at the paths configured in the Arduino sketch (and ultimately derived from `aws_iot_config.h`).
    - The Python SDK, used by `runtimeHub.py`, will load the certificate and private key files from the specified paths in plaintext during TLS handshake for secure MQTT connections.

  - **`README.md` (Credentials Section)**:
    - The "Credentials" section explicitly instructs users to "put your AWS IoT CA file, private key and certificate into `AWS-IoT-Arduino-Yun-SDK/AWS-IoT-Python-Runtime/certs`".
    - It further states, "You must upload these credentials along with the Python runtime code base to AR9331 on Yún board and specify the location of these files in a configuration file `aws_iot_config.h`."
    - This documentation reinforces the insecure practice of plaintext credential storage without any warnings about security implications or alternative methods.

- Security Test Case:
  1. **Setup:** Follow the "Installation" instructions in `README.md` to install the AWS IoT Arduino Yún SDK and configure it to use X.509 certificate-based authentication. Ensure you place your certificate, private key, and root CA certificate files into the `AWS-IoT-Arduino-Yun-SDK/AWS-IoT-Python-Runtime/certs` directory on your development machine. Run `AWSIoTArduinoYunInstallAll.sh` to upload the runtime and credentials to the Arduino Yún.
  2. **Gain SSH Access:** Establish an SSH connection to your Arduino Yún as the `root` user. If you haven't changed the default password, use 'arduino'.
  3. **Navigate to Credentials Directory:** In the SSH session, navigate to the directory where the credentials are stored: `cd /root/AWS-IoT-Python-Runtime/certs`.
  4. **Verify Plaintext Storage:** List the files in this directory using `ls -l`. You should see your certificate file (`cert.pem`), private key file (`privkey.pem`), and root CA certificate file (`aws-iot-rootCA.crt`).
  5. **Read Credential Files:** Use `cat cert.pem`, `cat privkey.pem`, and `cat aws-iot-rootCA.crt` to read the contents of each file. Observe that the X.509 certificate, private key, and root CA certificate are stored in plaintext and are directly readable by anyone with root access to the Arduino Yún.
  6. **Impersonation (Optional):**  To further demonstrate the impact, you could, in a separate environment (e.g., your development machine with AWS CLI configured), use the stolen certificate and private key to connect to AWS IoT as the compromised device and perform actions that the legitimate device is authorized to do (e.g., publish messages to MQTT topics, update shadow state). This step requires additional AWS IoT setup and is not strictly necessary to prove the vulnerability of insecure storage.

This test case confirms that X.509 certificates and private keys are stored in plaintext on the Arduino Yún filesystem after following the SDK's installation instructions, thus validating the vulnerability.

---

- Vulnerability Name: Insecure Storage of IAM Credentials in Environment Variables

- Description:
  - When using Websocket connections with IAM authentication, the SDK documentation (`README.md`) and the script `AWSIoTArduinoYunWebsocketCredentialConfig.sh` instruct users to store AWS Access Key ID and AWS Secret Access Key as environment variables in the `/etc/profile` file on the Arduino Yún.
  - Environment variables, especially when stored in a system-wide configuration file like `/etc/profile`, are not a secure method for storing sensitive credentials.
  - While environment variables might be slightly less directly exposed than files on the filesystem, they are still accessible to users with sufficient privileges on the Arduino Yún, and potentially through process introspection if other applications are compromised.
  - An attacker who gains unauthorized access to the Arduino Yún can read the `/etc/profile` file or inspect the environment variables of running processes to retrieve the AWS Access Key ID and AWS Secret Access Key.
  - With these IAM credentials, the attacker can authenticate to AWS services as the IAM role associated with these keys.
  - The attacker can then perform actions on AWS IoT and potentially other AWS services, depending on the permissions granted to the IAM role in AWS IAM policies.

- Impact:
  - **IAM Role Impersonation:** An attacker can impersonate the IAM role configured on the Arduino Yún.
  - **Unauthorized Access to AWS Services:** The attacker gains unauthorized access to AWS services (including AWS IoT) and resources associated with the IAM role.
  - **Data Breaches and Resource Manipulation:** Depending on the IAM policy, the attacker could access, modify, or delete data in AWS services, control AWS IoT devices, and potentially incur costs on the AWS account.
  - **Lateral Movement in AWS:** If the IAM role has overly permissive policies, the attacker could potentially use the compromised credentials to move laterally within the AWS environment and compromise other resources.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
  - None. The project provides no mitigations for insecure IAM credential storage. The documentation and scripts directly encourage storing credentials as environment variables.

- Missing Mitigations:
  - **Secure Credential Management:** Implement a more secure method for managing IAM credentials. Ideally, avoid storing long-term IAM credentials on the device altogether. Consider more secure alternatives if feasible for the use case:
    - **AssumeRole with Web Identity:**  If the Arduino Yún can authenticate with a web identity provider (though unlikely in typical Arduino Yún setups), using AssumeRole with Web Identity would be a more secure approach, avoiding direct credential storage.
    - **Temporary Credentials:** If possible, implement a mechanism to fetch temporary IAM credentials from a secure service at runtime, rather than storing long-term keys.
    - **Credential Rotation:** If long-term keys must be used, implement a robust credential rotation mechanism and minimize the lifespan of the keys.
  - **Documentation and Best Practices:** At a minimum, the documentation should:
    - **Clearly warn users** about the significant security risks of storing IAM credentials as environment variables, especially in `/etc/profile`.
    - **Strongly discourage** this practice and recommend exploring more secure alternatives.
    - **If environment variable storage is absolutely unavoidable**, provide guidance on:
      - **Restricting file permissions** on `/etc/profile` (though this offers limited security).
      - **Minimizing the scope of IAM permissions** granted to the compromised credentials (principle of least privilege).
      - **Regularly rotating IAM credentials**.
      - **Robust device security practices** to prevent unauthorized access to the Arduino Yún in the first place.

- Preconditions:
  - **Websocket Connection with IAM Authentication:** The user must choose to configure the SDK for Websocket connections and IAM-based authentication, as described in `README.md`.
  - **Execution of `AWSIoTArduinoYunWebsocketCredentialConfig.sh`:** The user must run the `AWSIoTArduinoYunWebsocketCredentialConfig.sh` script, providing their AWS Access Key ID and AWS Secret Access Key as command-line arguments.
  - **Unauthorized Access to Arduino Yún:** An attacker must gain unauthorized access to the Arduino Yún device, similar to the preconditions for X.509 certificate compromise.

- Source Code Analysis:
  - **`AWSIoTArduinoYunWebsocketCredentialConfig.sh`**:
    - This script is designed specifically to configure IAM credentials.
    - It modifies the `/etc/profile` file using `sed` and `echo` commands to add `export AWS_ACCESS_KEY_ID=<AWS_ACCESS_KEY_ID>` and `export AWS_SECRET_ACCESS_KEY=<AWS_SECRET_ACCESS_KEY>` lines to the end of the file.
    - `/etc/profile` is a system-wide configuration file that is typically sourced when a user logs in, making these environment variables available system-wide.
    - The script explicitly stores the IAM credentials in plaintext within `/etc/profile`.

  - **`README.md` (Credentials Section and Installation Instructions)**:
    - The "Credentials" section for IAM credentials states, "A tooling script `AWSIoTArduinoYunWebsocketCredentialConfig.sh` is provided... to update the IAM credentials as environment variables on AR9331, Yún board."
    - The "Installation on Windows/Linux" sections guide users to run this script and manually modify `/etc/profile` to include IAM credentials as environment variables, reinforcing this insecure storage method.

  - **`AWS-IoT-Python-Runtime/runtime/runtimeHub.py`**:
    - The Python runtime, when configured for Websocket and IAM, will rely on the AWS IoT Python SDK to retrieve IAM credentials from the environment variables `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`.
    - The SDK itself is designed to look for credentials in environment variables as one of its default credential providers.
    - `runtimeHub.py` indirectly depends on these environment variables being set for successful IAM authentication, thus making it vulnerable to insecure storage in environment variables if users follow the provided instructions.

- Security Test Case:
  1. **Setup:** Follow the "Installation" instructions in `README.md` for Websocket connections and IAM authentication. Run the `AWSIoTArduinoYunWebsocketCredentialConfig.sh` script, providing your AWS Access Key ID and AWS Secret Access Key.
  2. **Gain SSH Access:** Establish an SSH connection to your Arduino Yún as the `root` user (using 'arduino' password if not changed).
  3. **Read `/etc/profile`:** In the SSH session, use the command `cat /etc/profile` to view the contents of the `/etc/profile` file.
  4. **Verify Plaintext IAM Credentials:** Examine the output of `cat /etc/profile`. You should find lines like `export AWS_ACCESS_KEY_ID=<your_access_key_id>` and `export AWS_SECRET_ACCESS_KEY=<your_secret_access_key>` near the end of the file. Observe that your AWS Access Key ID and AWS Secret Access Key are stored in plaintext within this system configuration file.
  5. **Inspect Environment Variables (Alternative):** Alternatively, in the SSH session, run the command `env`. Examine the output and verify that `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` are present as environment variables and their values are your plaintext IAM credentials.
  6. **Impersonation (Optional):** To further demonstrate the impact, you could, in a separate environment (e.g., your development machine with AWS CLI configured), use the stolen AWS Access Key ID and AWS Secret Access Key to configure the AWS CLI with these credentials. Then, use the AWS CLI to perform actions on AWS IoT or other AWS services that the compromised IAM role is authorized to do (e.g., list IoT things, publish messages, etc.). This step requires AWS CLI setup and IAM policy knowledge and is not strictly needed to prove the vulnerability of insecure environment variable storage.

This test case confirms that IAM credentials are stored in plaintext environment variables in `/etc/profile` after using the provided configuration script, thus validating the vulnerability.