- Vulnerability Name: Incomplete Claim Verification in JWT Verification Process
- Description:
    - Step 1: An application developer uses the `jws` library to implement JWT verification.
    - Step 2: The developer initializes `JwtPublicKeyVerify` or `JwtMacVerify` without providing values for `issuer`, `subject`, or `audiences` during the verifier's constructor call. For example: `verifier = jws.JwtPublicKeyVerify(jwk_pub_key)`.
    - Step 3: The application then uses this `verifier` instance to verify JWTs received from users or external systems.
    - Step 4: An attacker crafts a malicious JWT. This JWT has a valid signature that will pass the signature verification performed by the `jws` library. However, the JWT contains incorrect or unexpected values for claims like 'aud' (audience), 'iss' (issuer), or 'sub' (subject). For instance, the 'aud' claim might be set to an audience that the application does not expect or should not authorize.
    - Step 5: The application calls `verifier.verify(malicious_jwt)` to verify the JWT.
    - Step 6: The `jws` library successfully verifies the signature of the JWT because it is valid.
    - Step 7: Inside the `verify` function, the `_verify_claims` function is called. Because the `issuer`, `subject`, and `audiences` parameters were not provided during `JwtPublicKeyVerify` or `JwtMacVerify` initialization in Step 2, the checks for these claims are skipped within the `_verify_claims` function.
    - Step 8: The `verify` function returns the payload of the malicious JWT, indicating successful verification, even though claim verification was incomplete.
    - Step 9: The application, mistakenly believing the JWT is fully valid based on the library's output, proceeds to authorize the user or action based on the claims in the JWT, including the potentially malicious or incorrect claims like 'aud', 'iss', or 'sub'.
- Impact:
    - Authentication Bypass: If the application relies on the 'sub' (subject) or 'iss' (issuer) claims for authentication, an attacker can forge these claims to impersonate another user or bypass authentication entirely.
    - Authorization Bypass: If the application uses the 'aud' (audience) claim for authorization, an attacker can craft a JWT intended for a different audience or no audience, but the application will still accept it, leading to unauthorized access to resources or functionalities.
    - In general, this vulnerability allows attackers to manipulate claims in JWTs that are meant to be verified, leading to incorrect application behavior and potential security breaches.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None in the library to enforce claim verification if the application developer does not configure it.
    - The library provides the functionality to verify claims if the application developer explicitly provides the expected `issuer`, `subject`, and `audiences` during `JwtPublicKeyVerify` or `JwtMacVerify` object creation. This is shown in the example usage in `/code/README.md`.
- Missing Mitigations:
    - Documentation Enhancement: Improve documentation to clearly emphasize the importance of claim verification (especially 'aud', 'iss', 'sub') in JWT security. Provide explicit warnings and best practices on how to properly initialize `JwtPublicKeyVerify` and `JwtMacVerify` with expected claim values and how to handle claim verification results in the application code.
    - Example Code Improvement: Update example code to always include claim verification setup, demonstrating how to pass `issuer`, `subject`, and `audiences` to the verifier constructors.
    - Consider adding a 'strict' mode: Optionally, the library could offer a 'strict' mode where claim verification for 'aud', 'iss', 'sub' is enforced by default, or at least triggers a warning if these parameters are not configured when creating a verifier. However, this might introduce backward compatibility issues and is a more complex change.
- Preconditions:
    - An application uses the `jws` library for JWT verification.
    - The application relies on JWT claims, specifically 'aud', 'iss', or 'sub', for making authentication or authorization decisions.
    - The application initializes `JwtPublicKeyVerify` or `JwtMacVerify` *without* providing the `issuer`, `subject`, or `audiences` parameters, despite needing to validate these claims for security purposes.
    - The application's backend or resource server is publicly accessible to attackers who can send crafted JWTs.
- Source Code Analysis:
    - File: `/code/jws/jwt.py`
    - Function: `_verify_claims(payload, issuer, subject, audiences, clock_skew_tolerance)`
    - Code Snippet:
    ```python
    def _verify_claims(payload, issuer, subject, audiences, clock_skew_tolerance):
      if issuer is not None: # Check only if issuer is provided during verifier init
        if payload.get("iss", None) is None:
          return False
        if not isinstance(payload["iss"],
                          six.string_types) or payload["iss"] != issuer:
          return False
      if subject is not None: # Check only if subject is provided during verifier init
        if payload.get("sub", None) is None:
          return False
        if not isinstance(payload["sub"],
                          six.string_types) or payload["sub"] != subject:
          return False
      if audiences is not None: # Check only if audiences is provided during verifier init
        if payload.get("aud", None) is None:
          return False
        if not isinstance(payload["aud"], six.string_types) or not any(
            payload["aud"] == s for s in audiences):
          return False
      # ... (exp and nbf checks are always performed if present)
      return True
    ```
    - Analysis:
        - The `_verify_claims` function explicitly checks if `issuer`, `subject`, and `audiences` are `not None` before proceeding with claim validation.
        - These parameters (`issuer`, `subject`, `audiences`) are passed directly from the `JwtPublicKeyVerify` and `JwtMacVerify` constructors.
        - If a developer initializes `JwtPublicKeyVerify` or `JwtMacVerify` without providing these claim parameters, they will be `None` by default in the constructor, and subsequently passed as `None` to `_verify_claims`.
        - Consequently, the conditional checks `if issuer is not None:`, `if subject is not None:`, and `if audiences is not None:` will evaluate to `False`, causing the claim verification logic for 'iss', 'sub', and 'aud' to be skipped entirely.
        - The signature verification in `JwsPublicKeyVerify` or `JwsMacVerify` (in `/code/jws/jws.py`) is performed correctly and independently of claim verification. Therefore, a JWT with a valid signature but invalid claims can bypass claim verification if the verifier is not properly configured.
- Security Test Case:
    - Step 1: Setup Test Environment
        - Assume you have a test application that uses the `jws` library for JWT verification. You can simulate this by writing a simple Python script that uses `jws` library.
        - In the test application, initialize `JwtPublicKeyVerify` *without* setting `issuer`, `subject`, and `audiences`:
        ```python
        import jws
        from jws import CleartextJwkSetReader

        # Use the public key from test suite or load your own.
        json_rsa_pub_key = r"""
        {
          "kty":"RSA",
          "n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
          "e":"AQAB",
          "alg":"RS256"
        }"""
        pub_key = CleartextJwkSetReader.from_json(json_rsa_pub_key)
        verifier = jws.JwtPublicKeyVerify(pub_key) # Claims verification is NOT configured
        ```
        - Assume the application is designed to authorize requests only if the JWT's 'aud' claim is 'valid-audience'.
    - Step 2: Craft Malicious JWT
        - Use a valid RSA private key that corresponds to the public key used in the test application. You can use the private key from the test suite for this purpose or generate your own key pair.
        - Create a JWT with the following characteristics:
            - Header: `{'alg': 'RS256'}`
            - Payload: `{'aud': 'INCORRECT-AUDIENCE', 'sub': 'attacker', 'iss': 'attacker-issuer', 'exp': <valid_expiry_timestamp>}` (Replace `<valid_expiry_timestamp>` with a future timestamp).  The key is to set 'aud' to something *other* than 'valid-audience'.
        - Sign the JWT using the RSA private key. You can use the `jws` library itself to sign the token using the private key counterpart of `json_rsa_pub_key`.
        ```python
        json_rsa_priv_key = r"""
        {
          "kty":"RSA",
          "n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
          "e":"AQAB",
          "d":"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ",
          "alg":"RS256"
         }"""
        priv_key = CleartextJwkSetReader.from_json(json_rsa_priv_key)
        signer = jws.JwtPublicKeySign(priv_key)
        test_header_rsa = {'alg': 'RS256'}
        test_payload_malicious = {'aud': 'INCORRECT-AUDIENCE', 'sub': 'attacker', 'iss': 'attacker-issuer', 'exp': _get_unix_timestamp() + 3600} # Valid expiry
        malicious_jwt = signer.sign(test_header_rsa, test_payload_malicious)
        ```
    - Step 3: Verify JWT with Test Application
        - In your test application script, use the `verifier` (initialized in Step 1 without claim configuration) to verify the `malicious_jwt` crafted in Step 2.
        ```python
        try:
            verified_payload = verifier.verify(malicious_jwt)
            print("JWT Verification Successful (but claims were not fully checked!)")
            print("Verified Payload:", verified_payload)
            # In a real app, if verification succeeds here, the app might proceed with authorization
            # based on claims, which would be incorrect in this case because 'aud' is wrong.
        except jws.SecurityException as e:
            print("JWT Verification Failed (as expected if claims were checked correctly):", e)
        ```
    - Step 4: Observe Results
        - Run the test application script.
        - Expected Outcome: The script will output "JWT Verification Successful (but claims were not fully checked!)" and print the verified payload. This demonstrates that the `jws` library verified the signature successfully but *did not* reject the JWT due to the incorrect 'aud' claim because claim verification for 'aud' was not configured in the `JwtPublicKeyVerify` initialization.
        - This proves the vulnerability: By not configuring claim verification, applications can be tricked into accepting JWTs with invalid claims, as long as the signature is valid.