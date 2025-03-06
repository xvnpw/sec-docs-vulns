- Vulnerability Name: Secrets Manager Plugin Misconfiguration leading to Credential Exposure

  - Description:
    1. An attacker gains access to the application's configuration, specifically targeting the Secrets Manager Plugin settings.
    2. The attacker modifies the `secrets_manager_secret_id` parameter in the application's configuration to point to a secret under the attacker's control.
    3. The application, when establishing a database connection, uses the modified `secrets_manager_secret_id` to fetch credentials.
    4. Since the `secrets_manager_secret_id` is now controlled by the attacker, the application retrieves and uses database credentials provided by the attacker's secret.
    5. The attacker can craft a secret containing credentials for a database they control.
    6. Consequently, application connects to attacker's database instead of intended Aurora database, potentially sending sensitive data to attacker controlled database or using attacker provided credentials to connect to the legitimate database if attacker crafts secret with valid credentials.

  - Impact:
    Critical. Unauthorized access to the database. Exposure of sensitive data if application sends data to attacker's database. Potential data corruption or manipulation if attacker crafts secret with valid credentials and connects to legitimate database.

  - Vulnerability Rank: Critical

  - Currently Implemented Mitigations:
    None. The library itself does not prevent misconfiguration at the application level.

  - Missing Mitigations:
    - Input validation for `secrets_manager_secret_id` to ensure it adheres to expected format (e.g., ARN format). However, this is not fully effective as attacker-controlled ARN would still be valid.
    - Documentation should strongly emphasize secure configuration practices, highlighting the risks of misconfiguration and importance of securing application configuration.

  - Preconditions:
    - Attacker must gain access to the application's configuration. This could be achieved through various means, such as exploiting vulnerabilities in the application's deployment process, insecure storage of configuration files, or insider access.
    - Application must be configured to use the AWS Secrets Manager Plugin.

  - Source Code Analysis:
    - The vulnerability lies in the design of the Secrets Manager Plugin, which trusts the `secrets_manager_secret_id` provided in the configuration without validation of its source or ownership.
    - The relevant code is within the `AwsSecretsManagerPlugin` in `aws_advanced_python_wrapper/aws_secrets_manager_plugin.py`.
    - The `connect` method fetches the secret using the `secrets_manager_secret_id` from the properties.
    - There is no code to verify the legitimacy or ownership of the secret ID.

  - Security Test Case:
    1. **Setup:**
       - Deploy an instance of an application using the `aws-advanced-python-wrapper` with Secrets Manager Plugin enabled.
       - Create a legitimate AWS Secrets Manager secret with valid database credentials, and configure the application to use this secret ID.
       - Create a malicious AWS Secrets Manager secret with attacker-controlled database credentials.
    2. **Exploit:**
       - Access the application's configuration (e.g., assume access to a configuration file or environment variables).
       - Modify the `secrets_manager_secret_id` in the application's configuration to point to the malicious secret ID.
       - Restart the application or trigger a database connection attempt.
    3. **Verification:**
       - Observe the application's connection attempts. Verify that the application now connects to the attacker-controlled database (e.g., by monitoring logs, network traffic, or database access logs of the attacker-controlled database).
       - Alternatively, if attacker provided valid credentials to legitimate database, verify unauthorized access using those credentials.

- Vulnerability Name: IAM Authentication Plugin Misconfiguration leading to Credential Exposure

  - Description:
    1. An attacker gains access to the application's configuration, specifically targeting the IAM Authentication Plugin settings.
    2. The attacker modifies the `profile_name` parameter in the application's configuration to point to an IAM profile under the attacker's control.
    3. The application, when establishing a database connection, uses the modified `profile_name` to fetch IAM credentials.
    4. Since the `profile_name` is now controlled by the attacker, the application uses AWS credentials from attacker's IAM profile to authenticate to the database.
    5. The attacker could configure their IAM profile to have elevated privileges or to access a different database instance.
    6. Consequently, application might gain unintended access to the database using attacker's IAM role.

  - Impact:
    High. Unauthorized database access using attacker-controlled IAM role. Potential for privilege escalation if attacker's IAM role has greater permissions than intended application role.

  - Vulnerability Rank: High

  - Currently Implemented Mitigations:
    None. The library itself does not prevent misconfiguration at the application level.

  - Missing Mitigations:
    - Documentation should strongly emphasize secure configuration practices, highlighting the risks of misconfiguration and importance of securing application configuration.
    - Consider implementing principle of least privilege for IAM roles used by applications.

  - Preconditions:
    - Attacker must gain access to the application's configuration.
    - Application must be configured to use the IAM Authentication Plugin.

  - Source Code Analysis:
    - The vulnerability stems from the IAM Authentication Plugin trusting the `profile_name` from application configuration without validating its source.
    - Relevant code is in `aws_advanced_python_wrapper/iam_plugin.py` within `IamAuthPlugin`.
    - The `connect` method uses `profile_name` from properties to load AWS configuration.
    - No validation exists to confirm the intended profile is used, allowing attacker substitution.

  - Security Test Case:
    1. **Setup:**
       - Deploy an application using `aws-advanced-python-wrapper` with IAM Authentication Plugin.
       - Configure application to use a legitimate IAM profile (`legitimate_profile`) with limited database access.
       - Create a malicious IAM profile (`attacker_profile`) with potentially broader database permissions or access to a different database instance.
    2. **Exploit:**
       - Access application's configuration (e.g., configuration file or environment variables).
       - Modify `profile_name` parameter to `attacker_profile`.
       - Restart application or trigger database connection.
    3. **Verification:**
       - Check application's database access logs or permissions. Verify application is now using permissions associated with `attacker_profile` instead of `legitimate_profile`.
       - Attempt actions requiring elevated privileges or access to different database, confirming unauthorized access through attacker-controlled IAM profile.