### Vulnerability List

- Vulnerability Name: Sensitive Data Logging
- Description:
    1. A user intends to analyze cryptographic artifacts, potentially including sensitive private keys or signatures, using the Paranoid Crypto library.
    2. The user executes one of the Paranoid Crypto checks, such as `paranoid.CheckAllRSA`, `paranoid.CheckAllEC`, `paranoid.CheckAllECDSASigs`, or `randomness_tests.TestSource`.
    3. During execution, the Paranoid Crypto library utilizes `absl.logging` to record details about the analysis process. This logging might inadvertently include the sensitive cryptographic artifacts or intermediate calculations derived from them.
    4. If the user operates the library in an insecure environment where log files, console output logs, or temporary files are accessible to unauthorized parties, an attacker could potentially retrieve these logs and gain access to the exposed sensitive cryptographic artifacts.
- Impact:
    Exposure of sensitive cryptographic keys or related cryptographic data. This can lead to the compromise of cryptographic systems relying on these keys, enabling unauthorized access, data breaches, or further malicious activities.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    None. The provided project files do not include any explicit mitigations against logging sensitive data. The library uses `absl.logging` for informational output, but there is no mechanism to prevent the logging of sensitive cryptographic information.
- Missing Mitigations:
    - Implement secure logging practices: Modify the logging mechanism to avoid direct logging of sensitive data. If logging is essential for debugging or auditing, implement sanitization or redaction of sensitive information before it is logged.
    - Provide clear documentation and warnings: Include prominent warnings in the documentation, advising users about the risks associated with using the library with sensitive data in insecure environments. Emphasize the potential for sensitive information exposure through logs.
    - Implement configurable logging: Introduce a configuration option to allow users to disable or fine-tune logging, especially when processing sensitive data. This could include options to select the logging level or specify which types of information are logged.
- Preconditions:
    1. The user executes Paranoid Crypto library checks on sensitive cryptographic artifacts, such as private keys, public keys used in tests that should remain private, or signatures.
    2. Logging is enabled in the Paranoid Crypto library. This could be the default setting or explicitly configured by the user through command-line flags or configuration files.
    3. The computational environment where the Paranoid Crypto library is executed is insecure. This means an attacker can access the file system, console output, or any other logging mechanisms used by the library in that environment.
- Source Code Analysis:
    - Example files like `examples/ec_public_keys.py`, `examples/rsa_public_keys.py`, `examples/ecdsa_signatures.py`, and `examples/randomness.py` demonstrate the use of `absl.logging` for outputting information during the execution of checks. For instance, they log messages like "-------- Testing ... keys --------", test names, test results ("passed", "failed"), and execution times.
    - Review of `paranoid_crypto/lib/paranoid.py` and `paranoid_crypto/lib/randomness_tests/random_test_suite.py` code is necessary to confirm if sensitive data, such as the input cryptographic artifacts themselves (keys, signatures), or intermediate sensitive values derived from them, are being logged using `absl.logging.info`, `absl.logging.debug`, or similar logging functions within the core check functions.
    - If the source code in `paranoid_crypto/lib/paranoid.py` and `paranoid_crypto/lib/randomness_tests/random_test_suite.py` includes logging statements that output the input cryptographic artifacts or parts thereof when checks are run with log level greater than 0, then this vulnerability is present. Given the purpose of logging for debugging and informational output, and without explicit sanitization of inputs, it is highly probable that sensitive data is logged.

- Security Test Case:
    1. Setup:
        a. Install the `paranoid_crypto` library in a test environment.
        b. Create a directory for logs, e.g., `test_logs`.
        c. Create a dummy RSA private key using openssl or cryptography library and extract the public key components (n, e) in PEM format to a file named `test_key.pem`.
        d. Modify the `examples/rsa_public_keys.py` example script:
            i.  Update the `rsa_key1` and `rsa_key2` variables to load RSA public key parameters from `test_key.pem` instead of using hardcoded values. Use a cryptography library to load PEM key and get public numbers.
    2. Execution:
        a. Run the modified `examples/rsa_public_keys.py` script with logging enabled and directed to a log file within the `test_logs` directory. For example:
           ```bash
           mkdir test_logs
           python3 examples/rsa_public_keys.py --log_dir=test_logs
           ```
        b. Or, to ensure more verbose logging, if available, use a debug log level:
           ```bash
           mkdir test_logs
           python3 examples/rsa_public_keys.py --log_dir=test_logs --verbosity=debug # if verbosity control is available in absl flags
           ```
    3. Analysis:
        a. Examine the log file generated in the `test_logs` directory (e.g., under `test_logs/absl.log.INFO.timestamp.*` or similar, depending on `absl.logging` configuration).
        b. Search the log file for the RSA public key components (n, e) from `test_key.pem` or any part of the sensitive data that was intended to be analyzed.
        c. If the RSA public key components or any other sensitive cryptographic information from the test key are found in the log file, it confirms that the library is logging sensitive data, thus validating the Sensitive Data Logging vulnerability.