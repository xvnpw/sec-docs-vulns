### Vulnerability List

- Vulnerability Name: Path Traversal in Azure Public Key File Loading
- Description:
    1. The `encrypted-sim-gen.py` script takes the Azure public key file path as a command-line argument using the `-A` or `--azure` parameter.
    2. The script uses the `ImportRsaPubKeyFromFile` function to read the public key from the specified file.
    3. The `ImportRsaPubKeyFromFile` function directly opens the file path provided without any validation or sanitization.
    4. An attacker can provide a malicious file path, such as `../../../../etc/passwd`, as the value for the `--azure` argument.
    5. The script will then attempt to open and read the file located at `../../../../etc/passwd` relative to the script's working directory.
    6. This allows an attacker to read arbitrary files from the system if the script is run with elevated privileges or if the attacker can access the script execution environment.
- Impact: High. An attacker can read sensitive files from the server's filesystem, potentially including configuration files, private keys, or other confidential data.
- Vulnerability Rank: High
- Currently Implemented Mitigations: None. The code directly uses the user-supplied file path without any validation.
- Missing Mitigations:
    - Implement path sanitization and validation in the `ImportRsaPubKeyFromFile` function.
    - Restrict file access to a predefined safe directory or use allowlisting for allowed file paths.
    - Consider using file path canonicalization to prevent traversal using symbolic links.
- Preconditions:
    - The attacker must be able to execute the `encrypted-sim-gen.py` script.
    - The attacker must be able to control the command-line arguments, specifically the `-A` or `--azure` parameter.
- Source Code Analysis:
    ```python
    def ImportRsaPubKeyFromFile(file):
        with open(file) as contents: # Vulnerable line: Directly opens user-provided 'file' path
            rsa = RSA.import_key(contents.read())
            return rsa.publickey().export_key(format="DER")

    args = argParser.parse_args()
    microsoftPublicKey = ImportRsaPubKeyFromFile(args.azure) # User-controlled path 'args.azure' passed directly to vulnerable function
    ```
    The `ImportRsaPubKeyFromFile` function in `/code/encrypted-sim-gen.py` takes the `file` argument directly from the command-line argument `args.azure` without any validation. The `open(file)` function then uses this unsanitized path to open the file. This allows path traversal if the user provides a path like `../../../../etc/passwd`.

- Security Test Case:
    1. Save the `encrypted-sim-gen.py` script to a local directory.
    2. Create a dummy private key file named `dummy_private_key.pem` in the same directory.
    3. Open a terminal and navigate to the directory containing `encrypted-sim-gen.py`.
    4. Execute the script with the following command:
    ```bash
    python encrypted-sim-gen.py -A "../../../../etc/passwd" -P dummy_private_key.pem
    ```
    5. Observe the output and error messages. If the script attempts to read and process the contents of `/etc/passwd` (or throws an error related to reading `/etc/passwd` as a key file), it confirms the path traversal vulnerability. For example, you might see errors from the RSA library trying to parse `/etc/passwd` as a PEM-encoded key.

- Vulnerability Name: Path Traversal in SIM Vendor Private Key File Loading
- Description:
    1. The `encrypted-sim-gen.py` script takes the SIM vendor private key file path as a command-line argument using the `-P` or `--private` parameter.
    2. The script uses the `ImportRsaKeysFromFile` function to read the private key from the specified file.
    3. Similar to the Azure public key file loading, the `ImportRsaKeysFromFile` function directly opens the provided file path without any validation.
    4. An attacker can provide a malicious file path, such as `../../../../etc/passwd`, as the value for the `--private` argument.
    5. The script will attempt to read the file at `../../../../etc/passwd`, allowing arbitrary file read.
- Impact: High. An attacker can read sensitive files from the server's filesystem.
- Vulnerability Rank: High
- Currently Implemented Mitigations: None.
- Missing Mitigations:
    - Implement path sanitization and validation in the `ImportRsaKeysFromFile` function, similar to the Azure public key file loading mitigation.
- Preconditions:
    - The attacker must be able to execute the `encrypted-sim-gen.py` script.
    - The attacker must be able to control the command-line arguments, specifically the `-P` or `--private` parameter.
- Source Code Analysis:
    ```python
    def ImportRsaKeysFromFile(file):
        with open(file) as contents: # Vulnerable line: Directly opens user-provided 'file' path
            rsa = RSA.import_key(contents.read())
            return rsa.export_key(format="DER"), rsa.publickey().export_key(format="DER")

    args = argParser.parse_args()
    simVendorPrivateKey,simVendorPublicKey = ImportRsaKeysFromFile(args.private) # User-controlled path 'args.private' passed directly to vulnerable function
    ```
    The `ImportRsaKeysFromFile` function in `/code/encrypted-sim-gen.py` takes the `file` argument directly from the command-line argument `args.private` without any validation. The `open(file)` function then uses this unsanitized path, leading to path traversal vulnerability.

- Security Test Case:
    1. Save the `encrypted-sim-gen.py` script to a local directory.
    2. Create a dummy public key file named `dummy_public_key.pem` in the same directory.
    3. Open a terminal and navigate to the directory containing `encrypted-sim-gen.py`.
    4. Execute the script with the following command:
    ```bash
    python encrypted-sim-gen.py -A dummy_public_key.pem -P "../../../../etc/passwd"
    ```
    5. Observe the output and error messages. Similar to the previous test case, if the script attempts to read and process `/etc/passwd` as a private key file, it confirms the vulnerability.

- Vulnerability Name: Path Traversal in SIM Data File Loading
- Description:
    1. The `encrypted-sim-gen.py` script takes the SIM data JSON file path as a command-line argument using the `-s` or `--sims` parameter.
    2. The script uses the `SimDefinitionFactory` to load SIM definitions from the specified file.
    3. The `SimDefinitionFactory` opens the file path provided as the `definition` argument without validation.
    4. An attacker can provide a malicious file path, such as `../../../../etc/passwd`, as the value for the `--sims` argument.
    5. The script will attempt to read the file at `../../../../etc/passwd`, leading to arbitrary file read.
- Impact: High. An attacker can read sensitive files from the server's filesystem.
- Vulnerability Rank: High
- Currently Implemented Mitigations: None.
- Missing Mitigations:
    - Implement path sanitization and validation when handling the file path for SIM data in `SimDefinitionFactory`.
- Preconditions:
    - The attacker must be able to execute the `encrypted-sim-gen.py` script.
    - The attacker must be able to control the command-line arguments, specifically the `-s` or `--sims` parameter.
- Source Code Analysis:
    ```python
    class SimDefinitionFactory:
        class DefinitionSource(Enum):
            BULKFILE = 1

        def __call__(self, source, definition):
            if (SimDefinitionFactory.DefinitionSource.BULKFILE == source):
                sims = []
                with open(definition) as bulkfile: # Vulnerable line: Directly opens user-provided 'definition' path
                    jsonSims = json.load(bulkfile)
                    for jsonSim in jsonSims:
                        sim = SimDefinition()
                        sim.fromJson(jsonSim)
                        sims.append(sim)
                return sims

    args = argParser.parse_args()
    simDefinitionFactory = SimDefinitionFactory()
    simDefinitions = simDefinitionFactory(DefinitionSource.BULKFILE, args.sims) # User-controlled path 'args.sims' passed directly to vulnerable function
    ```
    The `SimDefinitionFactory.__call__` method in `/code/encrypted-sim-gen.py` directly opens the file path provided by `args.sims` without validation, making it vulnerable to path traversal.

- Security Test Case:
    1. Save the `encrypted-sim-gen.py` script to a local directory.
    2. Create dummy key files `dummy_public_key.pem` and `dummy_private_key.pem` in the same directory.
    3. Open a terminal and navigate to the directory containing `encrypted-sim-gen.py`.
    4. Execute the script with the following command:
    ```bash
    python encrypted-sim-gen.py -A dummy_public_key.pem -P dummy_private_key.pem -s "../../../../etc/passwd"
    ```
    5. Observe the output and error messages. If the script attempts to read and parse `/etc/passwd` as a JSON file, or throws an error related to JSON parsing of `/etc/passwd`, it confirms the path traversal vulnerability.

- Vulnerability Name: Path Traversal in Decrypted Output File Writing
- Description:
    1. The `encrypted-sim-gen.py` script takes the decrypted SIM output file path as a command-line argument using the `-d` or `--decrypted` parameter.
    2. The script opens the file specified by `--decrypted` for writing the decrypted SIM data.
    3. The script directly uses the provided file path without any validation or sanitization.
    4. An attacker can provide a malicious file path, such as `/tmp/evil.json` or even more dangerous locations depending on permissions, as the value for the `--decrypted` argument.
    5. The script will attempt to write the decrypted SIM data to the specified path, potentially allowing an attacker to write files to arbitrary locations.
- Impact: High. An attacker can write files to arbitrary locations on the server, potentially overwriting critical system files or planting malicious files.
- Vulnerability Rank: High
- Currently Implemented Mitigations: None. The code directly uses the user-supplied file path for writing output.
- Missing Mitigations:
    - Implement path sanitization and validation for output file paths.
    - Restrict output file writing to a predefined safe directory.
- Preconditions:
    - The attacker must be able to execute the `encrypted-sim-gen.py` script.
    - The attacker must be able to control the command-line arguments, specifically the `-d` or `--decrypted` parameter.
- Source Code Analysis:
    ```python
    args = argParser.parse_args()
    # ...
    decryptedFile = open(args.decrypted, "w") # Vulnerable line: Directly opens user-provided 'args.decrypted' path for writing
    json.dump(listDecryptedSims, decryptedFile, indent=4, sort_keys=True)
    decryptedFile.close()
    ```
    The code in `/code/encrypted-sim-gen.py` directly uses `args.decrypted` to open a file for writing without any path validation, leading to a path traversal vulnerability in file writing.

- Security Test Case:
    1. Save the `encrypted-sim-gen.py` script to a local directory.
    2. Create dummy key files `dummy_public_key.pem` and `dummy_private_key.pem` in the same directory.
    3. Create a dummy SIM data file `dummy_sims.json` in the same directory with valid JSON content (e.g., `[{ "properties": { "integratedCircuitCardIdentifier": "iccid", "internationalMobileSubscriberIdentity": "imsi", "authenticationKey": "key", "operatorKeyCode": "opc" } }]`).
    4. Open a terminal and navigate to the directory containing `encrypted-sim-gen.py`.
    5. Execute the script with the following command:
    ```bash
    python encrypted-sim-gen.py -A dummy_public_key.pem -P dummy_private_key.pem -s dummy_sims.json -d "/tmp/evil_decrypted.json" -e dummy_encrypted.json
    ```
    6. Check if the file `/tmp/evil_decrypted.json` is created and contains the decrypted SIM data in JSON format. If the file is created in `/tmp`, it confirms the path traversal vulnerability in output file writing.

- Vulnerability Name: Path Traversal in Encrypted Output File Writing
- Description:
    1. The `encrypted-sim-gen.py` script takes the encrypted SIM output file path as a command-line argument using the `-e` or `--encrypted` parameter.
    2. The script opens the file specified by `--encrypted` for writing the encrypted SIM data.
    3. Similar to the decrypted output file, the script directly uses the provided file path without validation.
    4. An attacker can provide a malicious file path, such as `/tmp/evil.json`, as the value for the `--encrypted` argument, allowing arbitrary file write.
- Impact: High. An attacker can write files to arbitrary locations on the server.
- Vulnerability Rank: High
- Currently Implemented Mitigations: None.
- Missing Mitigations:
    - Implement path sanitization and validation for the encrypted output file path, similar to the decrypted output file mitigation.
- Preconditions:
    - The attacker must be able to execute the `encrypted-sim-gen.py` script.
    - The attacker must be able to control the command-line arguments, specifically the `-e` or `--encrypted` parameter.
- Source Code Analysis:
    ```python
    args = argParser.parse_args()
    # ...
    encryptedFile = open(args.encrypted, "w") # Vulnerable line: Directly opens user-provided 'args.encrypted' path for writing
    json.dump(jsonDefinition, encryptedFile, indent=4, sort_keys=False)
    encryptedFile.close()
    ```
    The code in `/code/encrypted-sim-gen.py` uses `args.encrypted` to open a file for writing without path validation, leading to a path traversal vulnerability in writing the encrypted output file.

- Security Test Case:
    1. Save the `encrypted-sim-gen.py` script to a local directory.
    2. Create dummy key files `dummy_public_key.pem` and `dummy_private_key.pem` in the same directory.
    3. Create a dummy SIM data file `dummy_sims.json` in the same directory.
    4. Open a terminal and navigate to the directory containing `encrypted-sim-gen.py`.
    5. Execute the script with the following command:
    ```bash
    python encrypted-sim-gen.py -A dummy_public_key.pem -P dummy_private_key.pem -s dummy_sims.json -e "/tmp/evil_encrypted.json" -d dummy_decrypted.json
    ```
    6. Check if the file `/tmp/evil_encrypted.json` is created and contains the encrypted SIM data in JSON format. If the file is created in `/tmp`, it confirms the path traversal vulnerability in output file writing.