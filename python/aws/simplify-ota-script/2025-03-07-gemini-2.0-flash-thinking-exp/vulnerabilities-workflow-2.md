## Vulnerability Report

### Insecure Configuration File Handling

- **Vulnerability Name:** Insecure Configuration File Handling leading to AWS Account Takeover and Malicious OTA Update Deployment

- **Description:**
    - Step 1: The `setup_ota_update.py` script creates a `config.json` file in the current working directory to store configuration parameters for AWS IoT OTA updates. This file is created without setting restrictive file permissions.
    - Step 2: This `config.json` file contains sensitive information such as the OTA update ID, IAM role ARN, target device/group ARNs, S3 bucket details, signing profile names, and firmware file locations. These parameters are used to interact with AWS services and define the OTA update process.
    - Step 3: The application reads configuration directly from this local `config.json` file in `run_ota_update.py` without any integrity checks or input validation.
    - Step 4: The `config.json` file is stored in plaintext on the local file system without encryption.
    - Step 5: If an attacker gains local access to the system where the script is run, they can read and modify the `config.json` file. This could be due to default insecure file permissions, compromised user accounts, or other system vulnerabilities.
    - Step 6: An attacker can modify various parameters in `config.json` to inject malicious configurations. For example, they can:
        - Change the `roleArn` to an attacker-controlled IAM role, gaining elevated privileges in the victim's AWS account.
        - Modify the `targets` to include devices or groups the attacker wants to compromise.
        - Alter the `files` section to point to malicious update files in an S3 bucket controlled by the attacker.
        - Change the `otaUpdateId` to interfere with legitimate OTA updates.
    - Step 7: When the legitimate user executes `run_ota_update.py`, the script reads the configuration from the potentially compromised `config.json` file.
    - Step 8: The `run_ota_update.py` script then uses these attacker-injected configurations to call the `create_ota_update` API in AWS IoT Core, effectively performing actions in the user's AWS account under the attacker's control and potentially deploying malicious firmware to IoT devices.

- **Impact:**
    - An attacker can gain unauthorized control over the victim's AWS account and IoT devices by manipulating OTA updates. This can lead to:
        - **Data Breach:** Stealing sensitive data from IoT devices by deploying malicious firmware updates that exfiltrate data.
        - **Device Compromise:** Deploying malicious firmware to IoT devices, allowing arbitrary code execution, turning them into botnets, rendering them unusable, or causing device malfunction.
        - **Denial of Service:** Disrupting legitimate OTA updates, preventing devices from receiving critical security patches or functionality updates, or causing script failures by injecting invalid configuration.
        - **Privilege Escalation:** Potentially gaining higher privileges within the AWS account if the injected IAM role grants broader access than intended.
        - **Resource Hijacking:** Using the victim's AWS resources (S3, IoT Core, Signer, etc.) for malicious purposes, incurring costs for the victim.
        - **Redirection to Malicious Resources:** Causing devices to download firmware from attacker-controlled infrastructure.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - None. The script does not implement any specific mitigations to protect the `config.json` file, validate its contents, or secure its storage.

- **Missing Mitigations:**
    - **Restrict File Permissions:**  The `setup_ota_update.py` script should set restrictive file permissions on `config.json` immediately after creation (e.g., `chmod 600 config.json` on Linux/macOS) to ensure only the owner (user running the script) can read and write to it.
    - **Input Validation:** Implement robust input validation in `run_ota_update.py` to verify the integrity and expected format of the data read from `config.json`. This should include:
        - Schema validation to ensure the JSON structure is as expected.
        - Data type validation for each parameter (e.g., string, ARN, boolean).
        - Format validation for ARNs, bucket names, keys, and other parameters to conform to AWS standards and expected patterns.
        - Range validation and checks against whitelists or known good configurations where applicable.
    - **Configuration File Encryption:** For highly sensitive environments, consider encrypting the `config.json` file to protect the confidentiality of stored credentials and configuration data at rest.
    - **Integrity Checks:** Implement integrity checks for the `config.json` file, such as digital signatures or checksums, to detect unauthorized modifications.
    - **Secure Configuration Storage:** Consider using more secure storage mechanisms for sensitive configurations, such as dedicated secrets management services or OS-level credential storage, instead of plaintext local files.
    - **Principle of Least Privilege:**  Document and emphasize the importance of running the script with the least privileged AWS credentials necessary and granting only the required permissions to the IAM role used for OTA updates.
    - **Warning Message:** Display a clear warning message to the user during script execution, emphasizing the importance of securing the `config.json` file and protecting it from unauthorized access.

- **Preconditions:**
    - The user runs `setup_ota_update.py` to generate the `config.json` file.
    - An attacker has some level of local access to the system where the script is run and can modify files in the directory where `config.json` is created. This could be due to insecure default file permissions, shared hosting environments, compromised user accounts, or other system vulnerabilities.

- **Source Code Analysis:**
    - **`setup_ota_update.py`:**
        ```python
        with open('config.json', 'w', encoding="utf-8") as config_file:
            json.dump(data, config_file, indent=4)
        ```
        - This code block writes the configuration data to `config.json` in plaintext without setting restrictive file permissions.

    - **`run_ota_update.py`:**
        ```python
        with open('config.json', 'r', encoding="utf-8") as config_file:
            data = json.load(config_file)

        aws_iot_client = boto3.client('iot')

        response = aws_iot_client.create_ota_update(
            otaUpdateId=data['otaUpdateId'],
            targetSelection=data['targetSelection'],
            files=data['files'],
            targets=data['targets'],
            roleArn=data['roleArn'],
        )
        ```
        - This code block reads the configuration from `config.json` and directly uses the values without any validation to create the OTA update job. It blindly trusts the contents of the `config.json` file, making it vulnerable to manipulation if the file is compromised.

    - **Visualization:**
    ```mermaid
    graph LR
        A[setup_ota_update.py] --> B(config.json - plaintext write with insecure permissions);
        C[run_ota_update.py] --> D(config.json - plaintext read without validation);
        B --> E[Local File System - Insecure Storage];
        D --> E;
        E --> F[Attacker Local Access & Modification];
        F --> B;
        F --> D;
        D --> G[AWS IoT SDK create_ota_update - vulnerable to injected config];
    ```

- **Security Test Case:**
    - Step 1: Setup the environment:
        - Install the script and dependencies.
        - Run `python3 setup_ota_update.py` to create a `config.json` file with legitimate AWS configurations.
    - Step 2: Attacker Gains Local Access and Modifies `config.json`:
        - As an attacker with local access, open `config.json` in a text editor.
        - Modify sensitive parameters such as `roleArn` to an attacker-controlled IAM role ARN and `files[0].fileLocation.s3Location` to point to a malicious firmware file in an attacker-controlled S3 bucket.
    - Step 3: User Runs OTA Update:
        - As the legitimate user, run `python3 run_ota_update.py`.
    - Step 4: Verify Exploitation:
        - Check AWS CloudTrail logs to confirm the OTA update creation used the attacker-controlled IAM role (if modified).
        - Inspect the created OTA update job in the AWS IoT Core console and verify that it is configured to use the attacker's malicious firmware file location (if modified).
        - (Optional) In a safe test environment, deploy the OTA update to a test device and confirm the device attempts to download and install the malicious firmware.
        - Attempt to provide invalid data types or formats in `config.json` (e.g., invalid ARN, incorrect bucket name format) and observe if `run_ota_update.py` proceeds without error or validation.

---

### Command Injection Vulnerability in Certificate Generation

- **Vulnerability Name:** Command Injection in Certificate Generation

- **Description:**
    - Step 1: The `setup_ota_update.py` script, during the certificate creation process, prompts the user to "Enter an email to use for the certificate".
    - Step 2: The provided email address is incorporated into a certificate configuration file (`cert_config.txt`) using string substitution.
    - Step 3: The script then uses `os.system` to execute `openssl req` command, passing `cert_config.txt` as a configuration file.
    - Step 4: If a malicious user provides an email address containing shell command injection payloads (e.g., using semicolons or backticks), these commands will be embedded into `cert_config.txt`.
    - Step 5: When `os.system` executes the `openssl req` command, the shell interprets the injected commands and executes them, leading to arbitrary command execution on the system with the privileges of the script's user.

- **Impact:**
    - Successful command injection allows an attacker to execute arbitrary commands on the system running the script with the privileges of the script's user. This can lead to:
        - Unauthorized access to AWS credentials stored on the system.
        - Manipulation of AWS resources if the script is run with AWS credentials.
        - Data exfiltration from the system.
        - Installation of malware or backdoors.
        - Complete system compromise.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - None. The code directly uses user input in a system command without any input sanitization or validation.

- **Missing Mitigations:**
    - **Input Validation and Sanitization:** Implement input validation for the email address to ensure it conforms to expected email format and sanitize or reject any input containing shell metacharacters (e.g., `;`, `&`, `|`, `$`, `` ` ``, `\`, newline).
    - **Avoid `os.system`:** Replace `os.system` with safer alternatives like `subprocess.run` with proper argument handling to prevent shell injection. Use argument lists instead of shell strings, and sanitize or validate arguments passed to subprocesses.
    - **Use Python Libraries for Certificate Generation:** Ideally, use a Python library for certificate generation to avoid calling external commands altogether, eliminating the risk of command injection.

- **Preconditions:**
    - The attacker must be able to execute the `setup_ota_update.py` script.
    - The attacker must choose to create a new ACM Certificate when prompted by the script.

- **Source Code Analysis:**
    1. **`setup_ota_update.py` - `cert_gen` function:**
    ```python
    def cert_gen(aws_proxy, email_address="emailAddress"):
        email = {'email': email_address}
        with open("cert_template.txt", "r", encoding="utf-8") as cert_template:
            src = Template(cert_template.read())
            result = src.substitute(email)
        with open("cert_config.txt", "w", encoding="utf-8") as cert_config:
            cert_config.write(result)

        os.system("openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
                   -pkeyopt ec_param_enc:named_curve -outform PEM -out ecdsasigner-priv-key.pem")
        os.system("openssl req -new -x509 -config cert_config.txt -extensions my_exts \
                   -nodes -days 365 -key ecdsasigner-priv-key.pem -out ecdsasigner.crt")
        ...
    ```
    - The `email_address` input is directly substituted into `cert_template.txt` and written to `cert_config.txt`.
    - `os.system` is used to execute `openssl req` with `cert_config.txt`, making it vulnerable to command injection if `email_address` contains malicious shell commands.

    - **Visualization:**
    ```mermaid
    graph LR
        A[User Input - Email Address] --> B(cert_config.txt - Malicious Payload Injection);
        B --> C[os.system("openssl req -config cert_config.txt ...")];
        C --> D[Shell Command Execution];
    ```

- **Security Test Case:**
    1. Execute `setup_ota_update.py`: `python3 setup_ota_update.py`.
    2. When prompted to create a new ACM Certificate, select 'a'.
    3. When prompted for the email address, enter the payload: `"; touch /tmp/pwned"`.
    4. Complete the script execution with valid inputs for other prompts.
    5. After script completion, check if the file `/tmp/pwned` exists. If it does, command injection is successful.