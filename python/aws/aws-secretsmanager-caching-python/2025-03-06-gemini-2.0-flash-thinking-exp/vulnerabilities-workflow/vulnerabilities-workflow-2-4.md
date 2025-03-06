### Vulnerability List

- Vulnerability Name: Secret ID Injection
- Description:
    - An attacker can perform a secret ID injection attack by manipulating the `secret_id` parameter in applications using the `@InjectSecretString` or `@InjectedKeywordedSecretString` decorators.
    - This vulnerability occurs when applications dynamically construct the `secret_id` based on user-controlled input without proper validation.
    - Step-by-step trigger:
        1. An application uses either `@InjectSecretString` or `@InjectedKeywordedSecretString` decorator to retrieve secrets.
        2. The application constructs the `secret_id` argument for the decorator dynamically based on user-provided input (e.g., URL parameters, form data, etc.).
        3. An attacker crafts a malicious input designed to manipulate the `secret_id`. For example, if the application intends to fetch secret 'application-secret' but takes a parameter to specify environment, and constructs secret id like `'app-secret-' + environment`, attacker can provide environment like `'..another-app-secret'` to access `'app-secret-..another-app-secret'` or similar. If no input sanitization is in place, direct secret ID injection is possible if the application directly uses user input as `secret_id`.
        4. The attacker sends a request to the application with the malicious input.
        5. The application, without proper validation, uses the attacker-controlled input to construct the `secret_id` and passes it to the decorator.
        6. The decorator uses the injected `secret_id` to fetch a secret from AWS Secrets Manager.
        7. If the attacker has sufficient permissions to access the application and the injected secret exists in AWS Secrets Manager, the attacker can retrieve the content of an unintended secret.
- Impact:
    - Unauthorized access to secrets within AWS Secrets Manager.
    - An attacker can potentially retrieve sensitive information such as API keys, database credentials, or other confidential data that is stored as secrets and managed by AWS Secrets Manager.
    - This could lead to further unauthorized actions, data breaches, or compromise of the application and its resources.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The library code itself does not include any input validation or sanitization for the `secret_id` parameter in the decorators.
- Missing Mitigations:
    - Input validation and sanitization must be implemented by developers in the applications that are using this library, specifically where user-controlled input is used to construct the `secret_id` for the decorators.
    - Documentation should be enhanced to explicitly warn against the dangers of constructing `secret_id` from user-controlled input without thorough validation. It should provide guidance on recommended sanitization and validation techniques to prevent secret ID injection attacks.
- Preconditions:
    1. The application utilizes either the `@InjectSecretString` or `@InjectedKeywordedSecretString` decorator from the `aws-secretsmanager-caching-python` library.
    2. The application dynamically determines the `secret_id` argument for these decorators based on input that can be influenced by a user or external actor.
    3. The application lacks sufficient input validation or sanitization measures for the user-controlled input before it is used to construct the `secret_id`.
- Source Code Analysis:
    - File: `/code/src/aws_secretsmanager_caching/decorators.py`
    - Classes: `InjectSecretString`, `InjectKeywordedSecretString`
    - Analysis:
        1. Both `InjectSecretString` and `InjectKeywordedSecretString` decorators accept `secret_id` as a parameter in their `__init__` methods.
        2. The `secret_id` is stored as `self.secret_id` within the decorator instance without any validation or modification.
        3. In the `__call__` methods of both decorators, `self.cache.get_secret_string(secret_id=self.secret_id)` is called, directly passing the stored `self.secret_id` to the `get_secret_string` method of the `SecretCache` class.
        4. The `SecretCache.get_secret_string` method (in `/code/src/aws_secretsmanager_caching/secret_cache.py`) then uses this `secret_id` to retrieve the secret from AWS Secrets Manager via the AWS SDK for Python (Boto3).
        5. No input validation, sanitization, or checks are performed on the `secret_id` within the `aws-secretsmanager-caching-python` library itself before making the AWS Secrets Manager API call.
        - Visualization:
            ```
            [Application Code] --> User Input --> [Construct secret_id] --> @Decorator(secret_id) --> SecretCache.get_secret_string(secret_id) --> AWS Secrets Manager API
                                                                 ^ No Validation Here ^
            ```
        - Conclusion: The library directly uses the provided `secret_id` without any validation. If the application constructs this `secret_id` from user-provided data without sanitization, it becomes vulnerable to secret ID injection.
- Security Test Case:
    - Step-by-step test:
        1. **Setup:**
            - Assume you have a running application that uses the `aws-secretsmanager-caching-python` library and exposes an endpoint that utilizes the `@InjectSecretString` decorator.
            - This application dynamically constructs the `secret_id` from a user-provided input, for example, a query parameter named `secretName`.
            - For demonstration purposes, assume the vulnerable application code looks like this (simplified example, not from the provided files):
              ```python
              from aws_secretsmanager_caching import SecretCache, InjectSecretString
              from flask import Flask, request

              app = Flask(__name__)
              cache = SecretCache()

              @app.route('/get_secret')
              def get_secret():
                  secret_name = request.args.get('secretName') # User controlled input
                  @InjectSecretString(secret_name, cache)
                  def decorated_function(secret_value):
                      return secret_value
                  return decorated_function()

              if __name__ == '__main__':
                  app.run(debug=True)
              ```
            - Assume there are two secrets in AWS Secrets Manager:
                - `safe-secret` with value "This is a safe secret."
                - `admin-secret` with value "This is the admin secret."
            - The application is intended to only allow access to `safe-secret` but is vulnerable due to insecure `secret_id` handling.
        2. **Targeted Request:**
            - As an attacker, craft a malicious URL to inject a different `secret_id`. Instead of accessing the intended `safe-secret`, attempt to access `admin-secret`.
            - Send a request to the vulnerable endpoint with the injected `secret_id` in the `secretName` parameter:
              ```
              GET /get_secret?secretName=admin-secret HTTP/1.1
              Host: vulnerable-app.com
              ```
        3. **Expected Outcome:**
            - If the application is vulnerable to secret ID injection, the application will:
                - Use the provided `secretName` value "admin-secret" as the `secret_id`.
                - Use the `@InjectSecretString` decorator to retrieve the secret associated with `admin-secret` from AWS Secrets Manager using the `SecretCache`.
                - Return the value of `admin-secret` ("This is the admin secret.") in the HTTP response to the attacker.
        4. **Verification:**
            - Observe the response from the application.
            - If the response contains "This is the admin secret.", it confirms that the secret ID injection was successful, and the attacker was able to retrieve the `admin-secret` by manipulating the `secretName` input.