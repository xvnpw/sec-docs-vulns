### Vulnerability List

- Vulnerability Name: AWS KMS Key Misconfiguration leading to Unauthorized Cryptographic Operations
- Description:
    1. An attacker gains unauthorized access to an application that uses the `python-jose_aws-kms-extension` library. This could be through various means, such as exploiting application vulnerabilities or compromised credentials.
    2. The application is configured to use AWS KMS keys for JWE encryption/decryption and JWS signing/verification.
    3. The AWS KMS key policy associated with the application's KMS keys is overly permissive. For example, it might allow broader IAM roles or principals to perform `kms:Decrypt` or `kms:Sign` actions than necessary for the application's intended functionality.
    4. The attacker leverages the compromised application to initiate JWE decryption or JWS signing operations using the application's KMS keys. The application, using the library, will then make calls to AWS KMS API.
    5. Due to the overly permissive KMS key policy, the KMS API calls initiated by the attacker through the compromised application are authorized by AWS KMS.
    6. The attacker successfully performs unauthorized cryptographic operations (decryption or signing) beyond the application's intended scope, potentially gaining access to sensitive data or forging signatures.
- Impact:
    - High to Critical. Depending on the sensitivity of the data protected by encryption or the criticality of the signing process, the impact could range from high to critical. Unauthorized decryption can lead to data breaches, and unauthorized signing can lead to integrity compromises and trust issues.
- Vulnerability Rank: High/Critical
- Currently Implemented Mitigations:
    - None. The library itself does not implement any mitigations for KMS key policy misconfigurations. It relies on the user to configure AWS KMS securely.
- Missing Mitigations:
    - **Documentation and Guidance:** Missing documentation that clearly outlines the security responsibilities of users in configuring KMS key policies. The documentation should emphasize the principle of least privilege when setting up KMS key policies for use with this library. It should include examples of restrictive key policies that limit access to only the necessary IAM roles or principals and actions required by the application.
- Preconditions:
    1. An application using `python-jose_aws-kms-extension` is deployed and accessible to attackers.
    2. The application is configured to use AWS KMS keys for cryptographic operations.
    3. The KMS key policy for the application's KMS keys is misconfigured to be overly permissive, granting excessive permissions (like `kms:Decrypt` or `kms:Sign`) to principals beyond those strictly required by the application.
    4. An attacker gains unauthorized access to the application.
- Source Code Analysis:
    - The library utilizes `boto3` to interact with the AWS KMS API.
    - Files like `jose_aws_kms_extension/backends/kms/symmetric/encryption/boto_kms_symmetric_encryption_key.py` and `jose_aws_kms_extension/backends/kms/asymmetric/signing/boto_kms_asymmetric_signing_key.py` contain methods (`generate_data_key`, `decrypt`, `sign`, `verify`) that directly invoke KMS API operations.
    - For example, in `BotoKMSSymmetricEncryptionKey.generate_data_key`, the code directly calls `self._kms_client.generate_data_key` without any policy checks:
      ```python
      data_key_response = self._kms_client.generate_data_key(
          KeyId=self._key,
          KeySpec=key_spec,
          EncryptionContext=self._encryption_context,
          GrantTokens=self._grant_tokens,
      )
      ```
    - Similarly, in `BotoKMSAsymmetricSigningKey.sign`, the code calls `self._kms_client.sign`:
      ```python
      res: SignResponseTypeDef = self._kms_client.sign(
          KeyId=self._key,
          Message=self._hash_provider(msg).digest(),
          MessageType=_MESSAGE_TYPE.DIGEST,
          SigningAlgorithm=self._algorithm,  # type: ignore[arg-type]
          GrantTokens=self._grant_tokens,
      )
      ```
    - The library code does not include any KMS policy validation or enforcement of least privilege. It assumes that the KMS key and its associated policy are properly configured externally.
    - The `README.md` provides usage examples, but it lacks security guidance on KMS key policy configuration.
- Security Test Case:
    1. **Setup:**
        - Deploy a sample application that uses `python-jose_aws-kms-extension` for JWE encryption and decryption.
        - Configure the application to use a specific AWS KMS key for encryption and decryption operations.
        - **Misconfigure the KMS Key Policy:**  Modify the KMS key policy to be overly permissive. For instance, grant `kms:Decrypt` and `kms:Encrypt` permissions to a wide range of IAM principals or even make it publicly accessible (for testing purposes only and never in a production environment). An example of an overly permissive policy could be granting decrypt permissions to `arn:aws:iam::*:*`.
        - Assume an attacker has gained control or access to the deployed application instance (e.g., through some other vulnerability or insider access).
    2. **Exploit (Unauthorized Decryption):**
        - As an attacker, use the compromised application to attempt to decrypt a JWE token that was originally encrypted using the KMS key.
        - Initiate a decryption request through the application's interface. This action will cause the application to use the `python-jose_aws-kms-extension` library to call the KMS `Decrypt` API.
        - Observe if the decryption operation is successful. If the decryption is successful even when, under a least-privilege KMS policy, the attacker (or the assumed compromised application role) should not have `kms:Decrypt` permissions, it indicates a vulnerability due to the overly permissive KMS key policy.
    3. **Expected Result:**
        - With an overly permissive KMS key policy, the attacker will be able to successfully decrypt the JWE token through the compromised application, even if they should not have direct access to decrypt using the KMS key under a correctly configured, least-privilege policy. This demonstrates the vulnerability arising from KMS key misconfiguration.