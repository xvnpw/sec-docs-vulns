## Combined Vulnerability List

This document outlines the identified vulnerabilities, their descriptions, impacts, and recommended mitigations. Each vulnerability is detailed in its own section below.

### 1. Missing HMAC Verification in SIM Data Decryption

- **Description:**
    1. The `encrypted-sim-gen.py` script uses AES-CBC and HMAC-SHA512 to encrypt sensitive SIM data.
    2. The `SimDefinition.decrypt` function is designed for internal decryption of this data.
    3. The function extracts the HMAC from the encrypted data.
    4. **Crucially, the `decrypt` function fails to verify the extracted HMAC against a recalculated HMAC.**
    5. An attacker intercepting or manipulating the `encryptedCredentials` can modify the ciphertext.
    6. When `decrypt` is used on tampered data, it decrypts without HMAC validation.
    7. This lack of verification means data integrity is not checked during decryption in the provided `decrypt` function.
    8. If partners implement decryption logic without HMAC verification in their upload endpoints, they become vulnerable to accepting tampered SIM data.

- **Impact:**
    - High. Without HMAC verification in the upload endpoint, attackers can modify encrypted SIM data in transit.
    - By altering the ciphertext within `encryptedCredentials`, malicious or incorrect SIM data (ICCID, IMSI, KI, OPC) can be injected.
    - If the receiving system trusts decrypted data without validation, this can lead to unauthorized SIM provisioning, service disruption, or other security breaches based on backend system usage of SIM data.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - None. While HMAC is generated during encryption in the `encrypt` function, the `decrypt` function in `encrypted-sim-gen.py` lacks HMAC verification.

- **Missing Mitigations:**
    - **Implement HMAC Verification in Decryption:** The `decrypt` function and any real-world decryption processes at upload endpoints must be updated to include HMAC verification.
        - After extracting HMAC, IV, and ciphertext, recalculate the HMAC of the IV and ciphertext using the authentication transport key.
        - Compare the recalculated HMAC with the extracted HMAC.
        - If HMACs don't match, abort decryption and report an error, indicating data tampering.
        - Proceed with AES-CBC decryption and unpadding only upon successful HMAC verification.

- **Preconditions:**
    1. **Vulnerable Decryption Implementation:** The primary precondition is the absence of HMAC verification in the system decrypting `encryptedCredentials`, especially at the upload endpoint. A properly implemented upload endpoint with HMAC verification would mitigate this vulnerability.
    2. **Man-in-the-Middle or Data Modification:**  Attackers must be able to intercept and modify `encryptedCredentials` after generation and before decryption by the receiving system.

- **Source Code Analysis:**
    - The vulnerability is in the `SimDefinition.decrypt` function in `/code/encrypted-sim-gen.py`.

    ```python
    def decrypt(self, transportKey, vendorPublicKey):
        properties = self.jsonDefinition["properties"]
        encryptedSecret = bytes.fromhex(properties["encryptedCredentials"])

        del self.jsonDefinition["properties"]["encryptedCredentials"]

        cipherText = []
        try:
            if (len(encryptedSecret) < 33):
                raise ValueError()
            mac = encryptedSecret[:64] # HMAC is extracted here
            iv = encryptedSecret[64:80]
            cipherText = encryptedSecret[80:]

            cipherAes = AES.new(transportKey, AES.MODE_CBC, iv)
            cipherText= cipherAes.decrypt(cipherText) # Decryption proceeds without HMAC verification
        except ValueError:
            print("Bad tag or message")

        cipherText = unpad(cipherText, 16)
        secret = cipherText.decode('utf-8')
        version, iccid, imsi, ki, opc = secret.split(":")

        properties["version"] = version
        properties["integratedCircuitCardIdentifier"] = iccid
        properties["internationalMobileSubscriberIdentity"] = imsi
        properties["authenticationKey"] = ki
        properties["operatorKeyCode"] = opc
    ```
    - The code extracts `mac` (HMAC), but it is not used for verification.
    - Decryption happens directly after extraction without checking HMAC validity.
    - The `ValueError` handling is insufficient for HMAC verification failures.

- **Security Test Case:**
    1. **Generate Encrypted SIM Data:** Run `encrypted-sim-gen.py` to create `Output-SimEncryptedBulkUpload.json`.
        ```bash
        python encrypted-sim-gen.py -P <path_to_your_private_key.pem> -s SimBulkUpload.json -e Output-SimEncryptedBulkUpload.json -d Output-SimDecryptedBulkUpload.json
        ```
        *(Ensure valid private key file and `SimBulkUpload.json` file - example `SimBulkUpload.json`: `[{"properties": {"integratedCircuitCardIdentifier": "iccid1", "internationalMobileSubscriberIdentity": "imsi1", "authenticationKey": "key1", "operatorKeyCode": "opc1"}}]`)*
    2. **Modify `encrypted-sim-gen.py` for Decryption Test:** Add decryption test code to the `if __name__ == '__main__':` block in `encrypted-sim-gen.py`.

        ```python
        if __name__ == '__main__':
            # ... (rest of the __main__ block from original script) ...

            # --- Add this section for testing decryption ---
            import json

            with open(args.encrypted, "r") as encrypted_file_read:
                encrypted_json_data = json.load(encrypted_file_read)

            transportKey_bytes = bytes.fromhex(encrypted_json_data["encryptedTransportKey"]) # for test we need the original one
            signedTransportKey_bytes = bytes.fromhex(encrypted_json_data["signedTransportKey"]) # for test we need the original one

            combinedTransportKey_test = transportKey + authenticationTransportKey # Use original combined transport key

            print("\n--- Decrypting and printing SIM data from encrypted JSON ---")
            for encrypted_sim_json in encrypted_json_data["sims"]:
                sim_test = SimDefinition()
                sim_test.fromJson(encrypted_sim_json)
                sim_test.decrypt(transportKey, simVendorPublicKey) # Using transportKey to trigger vulnerability
                print("Decrypted SIM data:")
                print(sim_test)
            # --- End of added decryption test section ---
        ```
    3. **Run Modified Script for Baseline Output:** Run the modified script and note the decrypted output.
    4. **Tamper with Encrypted JSON:** Open `Output-SimEncryptedBulkUpload.json` and find `encryptedCredentials`.
    5. **Modify Ciphertext:** Alter a byte in the ciphertext part of `encryptedCredentials` (after the first 64 hex chars - HMAC).
    6. **Run Modified Script with Tampered JSON:** Run the modified script again, decrypting the tampered JSON.
    7. **Observe Vulnerable Behavior:** The script runs without errors and prints decrypted data, despite tampering. The data will be corrupted, but tampering is not detected due to missing HMAC verification.
    8. **Expected Correct Behavior (Mitigated):** With HMAC verification, step 6 should produce an error message indicating HMAC failure, and decryption should not proceed.

### 2. Path Traversal in Azure Public Key File Loading

- **Description:**
    1. The `encrypted-sim-gen.py` script accepts the Azure public key file path via the `-A` or `--azure` argument.
    2. `ImportRsaPubKeyFromFile` function reads the public key from the specified file.
    3. **The function directly opens the provided file path without any validation.**
    4. An attacker can provide a malicious path, e.g., `../../../../etc/passwd`, as the `--azure` argument.
    5. The script attempts to open and read `../../../../etc/passwd`.
    6. This allows reading arbitrary files if the script runs with sufficient privileges or if the attacker can access the execution environment.

- **Impact:** High. Attackers can read sensitive files from the server's filesystem, potentially including configuration files, private keys, or other confidential data.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:** None. User-supplied file paths are used directly without validation.

- **Missing Mitigations:**
    - Implement path sanitization and validation in `ImportRsaPubKeyFromFile`.
    - Restrict file access to a safe directory or use allowlisting for file paths.
    - Use file path canonicalization to prevent traversal via symbolic links.

- **Preconditions:**
    - Attacker can execute `encrypted-sim-gen.py`.
    - Attacker can control command-line arguments, specifically `-A` or `--azure`.

- **Source Code Analysis:**
    ```python
    def ImportRsaPubKeyFromFile(file):
        with open(file) as contents: # Vulnerable line: Directly opens user-provided 'file' path
            rsa = RSA.import_key(contents.read())
            return rsa.publickey().export_key(format="DER")

    args = argParser.parse_args()
    microsoftPublicKey = ImportRsaPubKeyFromFile(args.azure) # User-controlled path 'args.azure' passed directly to vulnerable function
    ```
    - `ImportRsaPubKeyFromFile` takes `file` directly from `args.azure` without validation.
    - `open(file)` uses this unsanitized path, leading to path traversal.

- **Security Test Case:**
    1. Save `encrypted-sim-gen.py` locally.
    2. Create a dummy private key file `dummy_private_key.pem`.
    3. Open terminal, navigate to the script's directory.
    4. Execute: `python encrypted-sim-gen.py -A "../../../../etc/passwd" -P dummy_private_key.pem`
    5. Observe output/errors. If the script tries to read `/etc/passwd` (or errors parsing it as a key), path traversal is confirmed.

### 3. Path Traversal in SIM Vendor Private Key File Loading

- **Description:**
    1. The `encrypted-sim-gen.py` script accepts the SIM vendor private key file path via `-P` or `--private`.
    2. `ImportRsaKeysFromFile` reads the private key from the specified file.
    3. **Similar to Azure key loading, the function directly opens the path without validation.**
    4. Attackers can provide a malicious path, e.g., `../../../../etc/passwd`, via `--private`.
    5. The script attempts to read `../../../../etc/passwd`, allowing arbitrary file read.

- **Impact:** High. Attackers can read sensitive files from the server's filesystem.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:** None.

- **Missing Mitigations:**
    - Implement path sanitization and validation in `ImportRsaKeysFromFile`, similar to Azure public key mitigation.

- **Preconditions:**
    - Attacker can execute `encrypted-sim-gen.py`.
    - Attacker can control command-line arguments, specifically `-P` or `--private`.

- **Source Code Analysis:**
    ```python
    def ImportRsaKeysFromFile(file):
        with open(file) as contents: # Vulnerable line: Directly opens user-provided 'file' path
            rsa = RSA.import_key(contents.read())
            return rsa.export_key(format="DER"), rsa.publickey().export_key(format="DER")

    args = argParser.parse_args()
    simVendorPrivateKey,simVendorPublicKey = ImportRsaKeysFromFile(args.private) # User-controlled path 'args.private' passed directly to vulnerable function
    ```
    - `ImportRsaKeysFromFile` takes `file` from `args.private` without validation.
    - `open(file)` uses this unsanitized path, leading to path traversal.

- **Security Test Case:**
    1. Save `encrypted-sim-gen.py` locally.
    2. Create a dummy public key file `dummy_public_key.pem`.
    3. Open terminal, navigate to the script's directory.
    4. Execute: `python encrypted-sim-gen.py -A dummy_public_key.pem -P "../../../../etc/passwd"`
    5. Observe output/errors. If the script tries to read `/etc/passwd` as a private key, path traversal is confirmed.

### 4. Path Traversal in SIM Data File Loading

- **Description:**
    1. The `encrypted-sim-gen.py` script accepts the SIM data JSON file path via `-s` or `--sims`.
    2. `SimDefinitionFactory` loads SIM definitions from the specified file.
    3. **`SimDefinitionFactory` directly opens the provided file path without validation.**
    4. Attackers can provide a malicious path, e.g., `../../../../etc/passwd`, via `--sims`.
    5. The script attempts to read `../../../../etc/passwd`, leading to arbitrary file read.

- **Impact:** High. Attackers can read sensitive files from the server's filesystem.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:** None.

- **Missing Mitigations:**
    - Implement path sanitization and validation for the SIM data file path in `SimDefinitionFactory`.

- **Preconditions:**
    - Attacker can execute `encrypted-sim-gen.py`.
    - Attacker can control command-line arguments, specifically `-s` or `--sims`.

- **Source Code Analysis:**
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
    - `SimDefinitionFactory.__call__` directly opens `args.sims` without validation.
    - `open(definition)` uses this unsanitized path, leading to path traversal.

- **Security Test Case:**
    1. Save `encrypted-sim-gen.py` locally.
    2. Create dummy key files `dummy_public_key.pem`, `dummy_private_key.pem`.
    3. Open terminal, navigate to the script's directory.
    4. Execute: `python encrypted-sim-gen.py -A dummy_public_key.pem -P dummy_private_key.pem -s "../../../../etc/passwd"`
    5. Observe output/errors. If the script tries to parse `/etc/passwd` as JSON or errors parsing JSON from `/etc/passwd`, path traversal is confirmed.

### 5. Path Traversal in Decrypted Output File Writing

- **Description:**
    1. The `encrypted-sim-gen.py` script accepts the decrypted SIM output file path via `-d` or `--decrypted`.
    2. The script opens the file specified by `--decrypted` for writing decrypted data.
    3. **The script directly uses the provided path without validation.**
    4. Attackers can provide a malicious path, e.g., `/tmp/evil.json`, via `--decrypted`.
    5. The script attempts to write to the specified path, potentially allowing arbitrary file write.

- **Impact:** High. Attackers can write files to arbitrary server locations, potentially overwriting critical system files or planting malicious files.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:** None. User-supplied output file paths are used directly.

- **Missing Mitigations:**
    - Implement path sanitization and validation for output file paths.
    - Restrict output file writing to a predefined safe directory.

- **Preconditions:**
    - Attacker can execute `encrypted-sim-gen.py`.
    - Attacker can control command-line arguments, specifically `-d` or `--decrypted`.

- **Source Code Analysis:**
    ```python
    args = argParser.parse_args()
    # ...
    decryptedFile = open(args.decrypted, "w") # Vulnerable line: Directly opens user-provided 'args.decrypted' path for writing
    json.dump(listDecryptedSims, decryptedFile, indent=4, sort_keys=True)
    decryptedFile.close()
    ```
    - The code directly uses `args.decrypted` to open a file for writing without validation, leading to path traversal in file writing.

- **Security Test Case:**
    1. Save `encrypted-sim-gen.py` locally.
    2. Create dummy key files `dummy_public_key.pem`, `dummy_private_key.pem`.
    3. Create dummy SIM data file `dummy_sims.json` (valid JSON content).
    4. Open terminal, navigate to the script's directory.
    5. Execute: `python encrypted-sim-gen.py -A dummy_public_key.pem -P dummy_private_key.pem -s dummy_sims.json -d "/tmp/evil_decrypted.json" -e dummy_encrypted.json`
    6. Check if `/tmp/evil_decrypted.json` is created with decrypted SIM data. If created in `/tmp`, path traversal is confirmed.

### 6. Path Traversal in Encrypted Output File Writing

- **Description:**
    1. The `encrypted-sim-gen.py` script accepts the encrypted SIM output file path via `-e` or `--encrypted`.
    2. The script opens the file specified by `--encrypted` for writing encrypted data.
    3. **Similar to decrypted output, the script directly uses the path without validation.**
    4. Attackers can provide a malicious path, e.g., `/tmp/evil.json`, via `--encrypted`, allowing arbitrary file write.

- **Impact:** High. Attackers can write files to arbitrary server locations.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:** None.

- **Missing Mitigations:**
    - Implement path sanitization and validation for the encrypted output file path, similar to decrypted output mitigation.

- **Preconditions:**
    - Attacker can execute `encrypted-sim-gen.py`.
    - Attacker can control command-line arguments, specifically `-e` or `--encrypted`.

- **Source Code Analysis:**
    ```python
    args = argParser.parse_args()
    # ...
    encryptedFile = open(args.encrypted, "w") # Vulnerable line: Directly opens user-provided 'args.encrypted' path for writing
    json.dump(jsonDefinition, encryptedFile, indent=4, sort_keys=False)
    encryptedFile.close()
    ```
    - The code uses `args.encrypted` to open a file for writing without path validation, leading to path traversal in writing encrypted output.

- **Security Test Case:**
    1. Save `encrypted-sim-gen.py` locally.
    2. Create dummy key files `dummy_public_key.pem`, `dummy_private_key.pem`.
    3. Create dummy SIM data file `dummy_sims.json`.
    4. Open terminal, navigate to the script's directory.
    5. Execute: `python encrypted-sim-gen.py -A dummy_public_key.pem -P dummy_private_key.pem -s dummy_sims.json -e "/tmp/evil_encrypted.json" -d dummy_decrypted.json`
    6. Check if `/tmp/evil_encrypted.json` is created with encrypted SIM data. If created in `/tmp`, path traversal is confirmed.