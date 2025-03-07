### Vulnerability List

- Vulnerability Name: Local Configuration File Modification for Malicious OTA Update
- Description:
    - An attacker gains local access to the system where the `AWS-Simplify-OTA-Script` is installed and has been used.
    - The attacker navigates to the project directory where the `config.json` file is stored. This file is created after running `python3 setup-ota-update.py`.
    - The attacker modifies the `config.json` file using a text editor.
    - Specifically, the attacker changes the values within the `files[0].fileLocation.s3Location` section of the JSON structure.
        - The attacker replaces the original `bucket` name with the name of an S3 bucket they control.
        - The attacker replaces the original `key` (firmware file path) with the path to a malicious firmware file they have uploaded to their controlled S3 bucket.
    - The attacker saves the modified `config.json` file.
    - The legitimate user, intending to perform an OTA update, executes the script `python3 run-ota-update.py`.
    - The `run-ota-update.py` script reads the configuration from the locally stored `config.json` file, including the attacker-modified S3 bucket and firmware file path.
    - The script proceeds to create an OTA update job in AWS IoT Core, using the attacker's malicious firmware file location.
    - As a result, the OTA update job will distribute the attacker's malicious firmware to the targeted IoT devices.
- Impact:
    - IoT devices targeted by the OTA update will download and attempt to install the malicious firmware.
    - This can lead to complete compromise of the IoT devices, allowing the attacker to:
        - Execute arbitrary code on the devices.
        - Steal sensitive data from the devices or the network they are connected to.
        - Cause device malfunction or denial of service.
        - Use the devices as part of a botnet.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The application reads configuration directly from a local file without any integrity checks or access control mechanisms.
- Missing Mitigations:
    - **Input Validation:** The `run_ota_update.py` script should validate the data read from `config.json`, especially the S3 bucket and key, to ensure they conform to expected formats and potentially check against a whitelist or known good configurations.
    - **Integrity Checks:** Implement integrity checks for the `config.json` file. This could involve using digital signatures to ensure that the file has not been tampered with since it was initially created or last updated by a trusted process.
    - **File System Permissions:** Restrict file system permissions on the `config.json` file to limit write access only to the user running the `setup-ota-update.py` script and read access only to the user running the `run-ota-update.py` script. This would prevent unauthorized local users from modifying the configuration.
    - **Configuration File Location:** Consider storing the configuration in a more secure location, outside of the project directory, and with more restrictive access controls enforced by the operating system.
- Preconditions:
    - Local access to the file system where the `AWS-Simplify-OTA-Script` project is installed and where `config.json` is located.
    - The `setup-ota-update.py` script must have been executed at least once to generate the `config.json` file.
    - The legitimate user must subsequently execute the `run-ota-update.py` script after the attacker has modified the `config.json` file.
- Source Code Analysis:
    - File: `/code/source/run_ota_update.py`
    - The `create_ota_update` function in `run_ota_update.py` is responsible for creating the OTA update job.
    - It starts by reading the configuration from the `config.json` file:
    ```python
    with open('config.json', 'r', encoding="utf-8") as config_file:
        data = json.load(config_file)
    ```
    - The script then uses the `data` dictionary, which is directly loaded from the JSON file, to construct the parameters for the `create_ota_update` API call.
    - Critically, the `files` parameter, which includes the S3 location of the firmware, is taken directly from the `config.json` without any validation or sanitization:
    ```python
    response = aws_iot_client.create_ota_update(
        otaUpdateId=data['otaUpdateId'],
        targetSelection=data['targetSelection'],
        files=data['files'], # S3 location is read from config.json
        targets=data['targets'],
        roleArn=data['roleArn'],
    )
    ```
    - **Visualization:**
    ```
    [config.json (local file)] --> [run_ota_update.py] --> [boto3.client('iot').create_ota_update()] --> AWS IoT Core (OTA Job Creation)
    ^
    | Local Attacker Modification
    ```
    - This direct and unvalidated usage of the configuration data from `config.json` allows an attacker to inject malicious S3 locations by modifying the file locally. There are no checks in place to verify the integrity or trustworthiness of the data read from `config.json`.
- Security Test Case:
    1. **Setup:**
        - On a test system, set up the `AWS-Simplify-OTA-Script` project.
        - Run `python3 setup-ota-update.py` and complete the setup process using legitimate AWS credentials and resource names. Choose to create a new S3 bucket, IAM role, etc., or use existing ones. When prompted for the filepath to upload, provide a benign file (e.g., a dummy text file). Note the S3 bucket name and key that are configured in the generated `config.json`.
    2. **Attack (Local Access Required):**
        - As an attacker with local access to the test system, open the `config.json` file in a text editor.
        - Locate the `files` array in the JSON structure.
        - Modify the `bucket` and `key` values under `files[0].fileLocation.s3Location`.
            - Replace the original `bucket` name with the name of an S3 bucket controlled by the attacker.
            - Replace the original `key` with the path to a malicious firmware file that the attacker has uploaded to their controlled S3 bucket (e.g., `malicious-firmware.bin`).
        - Save the modified `config.json` file.
    3. **Execute OTA Update:**
        - As the legitimate user, execute the OTA update script: `python3 run-ota-update.py`.
        - The script will read the modified `config.json`.
    4. **Verify Vulnerability:**
        - Observe the output of `run_ota_update.py`. It should indicate that an OTA update job has been created successfully.
        - Go to the AWS IoT Core console in your AWS account.
        - Navigate to "Over-the-air (OTA) updates" -> "Job executions".
        - Find the OTA update job that was just created.
        - Inspect the job details. Verify that the "Update file location" in the job configuration points to the attacker-controlled S3 bucket and the malicious firmware file specified in the modified `config.json`.
        - (Optional, in a safe test environment with test IoT devices): If you have test IoT devices configured to receive OTA updates from this AWS IoT Core setup, you can further verify that the devices will attempt to download and install the malicious firmware from the attacker's S3 bucket when the OTA job starts executing.

This test case demonstrates that an attacker with local file system access can successfully manipulate the OTA update process by modifying the `config.json` file, leading to the distribution of malicious firmware to IoT devices.