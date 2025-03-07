- Vulnerability name: ECDSA Signature Format Mismatch Vulnerability
- Description: The library converts ECDSA signatures between JWS format (concatenated r and s) and DER format (used by cryptography.io). In `JwsPublicKeyVerify.verify`, the code checks if the signature length is divisible by 2, but it does not explicitly validate if the length is exactly twice the expected curve length for the given algorithm (e.g., 64 bytes for ES256). Subsequently, it splits the signature in half, assuming the first half is 'r' and the second half is 's'. If an attacker manipulates the signature to have an incorrect length that is still divisible by 2, or if the splitting logic is bypassed, it might be possible to bypass signature verification or forge signatures.
- Impact: Signature verification bypass, potentially leading to authentication bypass or authorization bypass.
- Vulnerability rank: medium
- Currently implemented mitigations: The library uses `cryptography.io` for underlying ECDSA signature verification, which is a robust cryptographic library. It also performs basic checks to ensure the token format is correct and algorithm and key types are compatible.
- Missing mitigations:
    - Explicitly validate the length of the ECDSA signature against the expected length (twice the curve length) before attempting to split it into 'r' and 's' in `JwsPublicKeyVerify.verify`.
    - Implement more robust error handling and logging for signature format conversion issues to aid in debugging and security monitoring.
    - Add comprehensive test cases that specifically test scenarios with invalid ECDSA signature lengths and formats to ensure proper rejection.
- Preconditions:
    - The attacker can manipulate the JWS token, specifically the signature part, during transmission or storage.
    - The application utilizes ECDSA algorithms (ES256, ES384, ES512) for JWS verification.
- Source code analysis:
    - File: `/code/jws/jws.py`
    - Class: `JwsPublicKeyVerify`
    - Method: `verify(self, token)`
    - Vulnerable code block (around line 130):
    ```python
    if header_json["alg"][:2] == "ES":
        length = len(sig_bytes)
        if length % 2 != 0: # Vulnerable condition: assumes even length but not exact length
            raise SecurityException("Token's length is not divisible by 2")
        [r, s] = [sig_bytes[0:length // 2], sig_bytes[length // 2:]] # Vulnerable split logic: assumes length is exactly twice curve length
        mod_sig_bytes = utils.encode_dss_signature(
            jwsutil.bytes_to_int(r), jwsutil.bytes_to_int(s))
        try:
            verifier.verify(mod_sig_bytes, data)
            verified = True
        except:
            raise SecurityException("Invalid signature")
    ```
    The vulnerability lies in the assumption that if the signature length is divisible by 2, it is valid for splitting into 'r' and 's'. This check is insufficient as it does not enforce the signature to be exactly twice the curve length, which is critical for correct ECDSA signature format conversion.

- Security test case:
    1. Setup: Use the existing test setup for ECDSA signing and verification, such as `test_jws_ecdsa_signer_verifier_es256` in `/code/tests/jws_test.py`.
    2. Modify Token Signature: After generating a valid signed token with ES256, intercept the token and modify its signature part. Pad the signature with a few extra bytes (e.g., 2 bytes) of zero padding to make the signature length slightly longer than expected but still divisible by 2. Encode the modified signature part using base64url.
    3. Construct Malicious Token: Reconstruct the JWS token by replacing the original signature part with the modified, padded signature part. Keep the header and payload parts unchanged.
    4. Verification Attempt: Attempt to verify the maliciously crafted token using `JwsPublicKeyVerify`.
    5. Expected Outcome: The verification MUST fail and raise a `SecurityException`. If the verification unexpectedly succeeds, it confirms the ECDSA Signature Format Mismatch Vulnerability. This indicates that the library is not strictly validating the signature length and is potentially vulnerable to signature manipulation attacks.