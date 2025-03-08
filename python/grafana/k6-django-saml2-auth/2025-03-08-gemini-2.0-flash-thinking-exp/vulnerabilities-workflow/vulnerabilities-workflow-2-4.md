### Vulnerability List

#### XML Signature Wrapping Vulnerability

- Description:
    1. An attacker intercepts a legitimate SAML Response from the Identity Provider (IdP) to the Service Provider (SP) (Django application).
    2. The attacker manipulates the XML structure of the SAML Response by adding a new assertion that they crafted. This is the "wrapping" part, where the original signed assertion is wrapped within a modified XML structure.
    3. Importantly, the attacker preserves the original, valid XML Signature from the legitimate SAML Assertion and positions it to appear as if it is signing the attacker's malicious assertion or the entire modified SAML Response.
    4. The attacker sends the manipulated SAML Response to the Django SAML2 Authentication SP endpoint (`acs` view).
    5. Due to improper or incomplete XML signature verification on the SP side, the system might only validate the presence of a signature and its basic validity (e.g., cryptographic correctness) but fail to verify *what* exactly is being signed.
    6. If the vulnerability exists, the Django SAML2 Authentication library could be tricked into accepting the manipulated SAML Response as valid, because it contains a valid signature, even though the signature might not cover the attacker's injected malicious content.
    7. The system processes the attacker's crafted assertion, potentially granting unauthorized access or privileges based on the attacker-controlled content.

- Impact:
    - Authentication bypass: An attacker can gain unauthorized access to the Django application without valid credentials by crafting a SAML response that the application incorrectly validates.
    - Privilege escalation: By manipulating the attributes within the SAML assertion, an attacker might be able to elevate their privileges within the application, potentially gaining administrative rights or access to sensitive data.
    - Data manipulation: In scenarios where SAML assertions carry authorization or attribute information used for application logic, a successful wrapping attack could lead to data manipulation or unauthorized actions within the application.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - `WANT_ASSERTIONS_SIGNED = True` setting: This setting in `settings.py` enforces that the service provider expects assertions within the SAML response to be signed. This is mentioned in the `README.md` as a configurable option.
    - `WANT_RESPONSE_SIGNED = True` setting: This setting in `settings.py` enforces that the service provider expects the entire SAML response to be signed. This is also mentioned in the `README.md` as a configurable option.
    - These settings are configurable via `settings.py` as described in the `README.md` under "Module Settings".

- Missing Mitigations:
    - Robust XML Signature Verification: The current mitigations rely on settings to *require* signatures, but they do not guarantee *robust* verification against wrapping attacks. A proper mitigation would involve:
        - Verifying that the signature covers the *entire* SAML Assertion element and/or the relevant parts of the SAML Response that are expected to be signed.
        - Using an XML parser and signature validation library that is explicitly designed to prevent XML Signature Wrapping attacks. This often involves canonicalization and secure parsing practices to ensure that the signature validation is performed on the intended XML content and not on a manipulated structure.
        - Implementing checks to ensure that the signed elements are the ones expected and that there are no unexpected or redundant elements that could be used for wrapping.

- Preconditions:
    - `WANT_ASSERTIONS_SIGNED` and `WANT_RESPONSE_SIGNED` are set to `True` (or are not explicitly set to `False` as `True` is the default). While these settings are intended to enhance security, if the underlying signature verification is flawed, they might not prevent wrapping attacks and could create a false sense of security.
    - The attacker needs to be able to intercept SAML responses between the IdP and SP. This is often possible in real-world scenarios, especially if communication channels are not properly secured or if the attacker is in a privileged network position.
    - The Identity Provider must be configured to sign SAML Assertions and/or Responses, which is a common security practice and thus a likely precondition in deployments using this library.

- Source Code Analysis:
    1. **`django_saml2_auth/saml.py:decode_saml_response` function:** This function is the entry point for processing incoming SAML responses.
    2. **`saml2.client.Saml2Client.parse_authn_request_response`:** This function from the `pysaml2` library is used to parse and potentially verify the signature of the SAML response. The code in `decode_saml_response` calls this function:
       ```python
       authn_response = saml_client.parse_authn_request_response(response, entity.BINDING_HTTP_POST)
       ```
    3. **Signature Verification in `pysaml2`:** The security of this Django SAML2 Authentication library heavily relies on the `pysaml2` library's implementation of XML signature verification. To determine if a wrapping vulnerability exists, we would need to:
        - **Review `pysaml2` Source Code:** Analyze the source code of `pysaml2`, specifically the `parse_authn_request_response` function and its related signature validation mechanisms. Look for how `pysaml2` handles XML signatures and if it is designed to prevent wrapping attacks. (This would require a separate, in-depth code review of `pysaml2`, which is outside the scope of analyzing *this* project's code directly, but crucial for a complete vulnerability assessment).
        - **Check `pysaml2` Documentation and Security Advisories:** Review the documentation of `pysaml2` for any information on XML Signature Wrapping and security considerations. Also, check for any known security vulnerabilities or advisories related to XML Signature Wrapping in `pysaml2`.
    4. **Lack of Explicit Wrapping Attack Mitigation in `django-saml2-auth`:**  Within the provided code of `django-saml2-auth`, there is no explicit code that is designed to *specifically* mitigate XML Signature Wrapping attacks beyond relying on `pysaml2` and the `WANT_ASSERTIONS_SIGNED` and `WANT_RESPONSE_SIGNED` settings.
    5. **Vulnerability Likelihood:** If `pysaml2`'s XML signature verification is not robust against wrapping attacks (which is a known potential issue in many XML signature libraries if not carefully implemented), then `django-saml2_auth` would inherit this vulnerability.

    **Visualization of XML Signature Wrapping Attack:**

    ```
    [IdP] --> SAML Response (Signed Assertion) --> [Attacker] --> Manipulated SAML Response (Wrapped Assertion, Original Signature) --> [SP - Django App]

    [SP - Django App] -- Processes Response --> [Incorrectly Validates Signature] --> [Authentication Bypass]
    ```

- Security Test Case:
    1. **Setup:**
        - Set up a Django application using `django-saml2-auth` with `WANT_ASSERTIONS_SIGNED = True` and `WANT_RESPONSE_SIGNED = True` in `settings.py`.
        - Configure a SAML Identity Provider (e.g., Okta, Azure AD, or a test IdP like SimpleSAMLphp) to work with the Django application. Ensure the IdP is configured to sign SAML Assertions.
        - Use a tool like SAML Tracer (browser extension) or Burp Suite to intercept the SAML Response during a legitimate login flow.
    2. **Capture Legitimate SAML Response:**
        - Initiate a SAML login to the Django application through the configured IdP.
        - Using the interception tool, capture a valid SAML Response from the IdP just before it is sent to the Django application's `acs` endpoint.
        - Save this legitimate SAML Response XML.
    3. **Manipulate SAML Response (XML Wrapping):**
        - Using an XML editor or a script, manipulate the captured SAML Response XML. The goal is to add a *new, malicious* Assertion element *without* a valid signature, and then "wrap" the original, *validly signed* Assertion in a way that the signature appears to cover the whole modified response or the malicious assertion.
        - A common technique is to insert the malicious assertion *before* the original signed assertion or to wrap the original assertion inside a new, attacker-controlled XML structure.
        - Ensure the original, valid `<ds:Signature>` element from the legitimate response is preserved and is positioned in a way that *might* be misinterpreted as signing the manipulated content.
    4. **Send Manipulated SAML Response:**
        - Base64 encode the manipulated SAML Response XML.
        - Using a tool like `curl` or a browser, craft a POST request to the Django application's `acs` endpoint (`/sso/acs/` or the configured path).
        - Include the Base64 encoded manipulated SAML Response as the `SAMLResponse` parameter in the POST request body.
    5. **Observe Authentication Outcome:**
        - Send the crafted POST request to the Django application.
        - Observe the application's behavior.
        - **Expected Vulnerable Behavior:** If the application is vulnerable to XML Signature Wrapping, it will incorrectly validate the manipulated SAML Response and grant the attacker access as if they were a legitimate user. This would typically manifest as a successful login and redirection to the default or requested "next" URL.
        - **Expected Secure Behavior:** If the application is *not* vulnerable, it should detect the manipulation, reject the SAML Response as invalid (due to signature verification failure on the modified content), and display an error or deny access.
    6. **Analyze Logs (if vulnerable):**
        - If the application grants access, examine the Django application's logs and the SAML library's debug logs (if enabled via `DEBUG = True` in `SAML2_AUTH` settings).
        - Verify if the logs indicate that the manipulated assertion was processed and user attributes were extracted from it, confirming the wrapping attack's success.