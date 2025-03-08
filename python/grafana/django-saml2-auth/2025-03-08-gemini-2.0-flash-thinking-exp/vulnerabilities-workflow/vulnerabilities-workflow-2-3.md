- Vulnerability Name: SAML Response Signature Bypass due to Missing Signature Requirement Configuration
- Description:
    1. An attacker intercepts a valid SAML response.
    2. The attacker modifies the SAML response, for example, changing user attributes to gain elevated privileges.
    3. The attacker sends the modified SAML response to the application's ACS endpoint.
    4. If the Django SAML2 Auth library is not configured to require SAML response signatures (`WANT_RESPONSE_SIGNED` or `WANT_ASSERTIONS_SIGNED` set to False), the library will not verify the signature of the SAML response.
    5. The application processes the modified SAML response as valid, potentially granting unauthorized access or privileges to the attacker based on the manipulated attributes.
- Impact:
    - High: Unauthorized access to user accounts and application functionalities. An attacker can potentially impersonate any user, including administrators, by forging SAML responses. This can lead to complete compromise of the application and its data.
- Vulnerability Rank: High
- Currently implemented mitigations:
    - The code defaults `WANT_ASSERTIONS_SIGNED` and `WANT_RESPONSE_SIGNED` to `True` in `get_saml_client` function within `django_saml2_auth/saml.py`. This is a good security default.
    - The documentation in `README.md` mentions these settings and their importance, implicitly encouraging users to keep signature verification enabled.
- Missing mitigations:
    - There is no explicit check in the code to ensure that `WANT_RESPONSE_SIGNED` or `WANT_ASSERTIONS_SIGNED` are actually set to `True` in the user's `settings.py`. The application relies on the default values if these settings are not explicitly defined.
    - No warning or error is raised if the user explicitly sets `WANT_RESPONSE_SIGNED` or `WANT_ASSERTIONS_SIGNED` to `False` in their settings, which could lead to misconfiguration and security vulnerabilities.
- Preconditions:
    - The attacker needs to be able to intercept SAML responses, which is possible in various network scenarios, especially if TLS is not properly enforced or if the attacker is on the same network as the user.
    - The Django SAML2 Auth library must be configured with `WANT_RESPONSE_SIGNED` or `WANT_ASSERTIONS_SIGNED` set to `False` in the Django project's `settings.py` or relying on default (and assuming default is insecure). If the user explicitly sets these to False or does not configure them and assumes default is secure but the default is actually insecure then vulnerability exists. However, in this code, default is secure (`True`). If user explicitly disables it, then vulnerability exists.
- Source code analysis:
    1. In `django_saml2_auth/saml.py`, the `get_saml_client` function configures the `pysaml2` client.
    2. Within the `saml_settings['service']['sp']` dictionary, the options `want_assertions_signed` and `want_response_signed` are set based on Django settings:
    ```python
    "want_assertions_signed": dictor(
        saml2_auth_settings, "WANT_ASSERTIONS_SIGNED", default=True
    ),
    "want_response_signed": dictor(
        saml2_auth_settings, "WANT_RESPONSE_SIGNED", default=True
    ),
    ```
    3. The `dictor` function with `default=True` ensures that if these settings are not defined in `settings.SAML2_AUTH`, they default to `True`, which is secure.
    4. However, if a user explicitly sets these values to `False` in their `settings.py`, signature verification will be disabled.
    5. In `django_saml2_auth/views.py`, the `acs` view calls `decode_saml_response` to process the SAML response. If signature verification is disabled through configuration, this function will not effectively validate the authenticity and integrity of the SAML response beyond basic XML parsing and schema validation (done by `pysaml2` library, but signature verification is a separate step that can be disabled).
    6. The vulnerability lies in the possibility of misconfiguration. If an administrator mistakenly sets `WANT_RESPONSE_SIGNED` or `WANT_ASSERTIONS_SIGNED` to `False` (or believes the default is `False` and does not explicitly enable signature verification, though the default is actually secure in this code), the application becomes vulnerable to SAML response manipulation attacks.

- Security test case:
    1. **Setup:** Configure a Django application using `django-saml2-auth`. In `settings.py` within `SAML2_AUTH` dictionary, explicitly set `WANT_RESPONSE_SIGNED = False`. Configure a SAML Identity Provider (IdP) to send SAML responses to this application.
    2. **Capture Valid SAML Response:** Authenticate as a legitimate user against the IdP and capture a valid SAML response using a tool like SAML-tracer.
    3. **Modify SAML Response:** Modify the captured SAML response XML. For example, change the user's email address or add an attribute that grants admin privileges (if attribute mapping is configured to use such attributes for authorization). Remove or invalidate the original signature from the SAML Response, as the application is configured to not verify it.
    4. **Send Modified SAML Response:** Submit the modified SAML response to the application's ACS endpoint (e.g., `/sso/acs/`).
    5. **Verify Bypass:** Check if the application logs the user in based on the modified attributes in the forged SAML response. If the application grants access or privileges based on the manipulated response without signature verification, the vulnerability is confirmed. For example, check if you are logged in as the user specified in the modified SAML response, or if you have gained admin privileges if you added an admin attribute.