### Vulnerability List

- Vulnerability name: Hardcoded AWS Credentials in Example Code
- Description:
    1. A developer uses the example code provided in the `README.md` file to implement AWS SigV4 authentication for their Cassandra driver.
    2. The example code in the "Programmatically Configure the Driver With a boto3 session" and "Programmatically Configure the Drive with raw AWS Credentials" sections of the `README.md` includes hardcoded AWS access key ID, secret access key, and session token.
    3. The developer, without realizing the security implications, copies this example code directly into their application code and replaces the example values with their actual AWS credentials.
    4. The developer then commits this code to a public or accessible repository or deploys the application, unintentionally exposing their AWS credentials.
    5. An attacker can find these exposed credentials in the public repository or application code.
    6. The attacker can then use these credentials to access the AWS account and resources associated with those credentials, potentially leading to data breaches, unauthorized access, or other malicious activities.
- Impact: Full compromise of AWS account and resources if the hardcoded credentials have sufficient permissions. This can lead to data breaches, data loss, unauthorized resource usage, and potential financial impact.
- Vulnerability rank: Critical
- Currently implemented mitigations:
    - None. The README provides example code with explicitly hardcoded credentials without any warning or best practice advice against doing so.
- Missing mitigations:
    - **Security Warning in README:** Add a prominent warning in the `README.md` file, right before the example code blocks, explicitly advising users against hardcoding AWS credentials in their applications. This warning should highlight the security risks and recommend secure credential management practices.
    - **Best Practices Documentation:** Include a dedicated section in the `README.md` or a separate documentation file detailing best practices for managing AWS credentials when using this plugin. This section should recommend methods like using environment variables, AWS configuration files, IAM roles, or dedicated secret management services instead of hardcoding credentials.
    - **Secure Example Code:** Modify the example code to demonstrate secure credential handling. For instance, show how to initialize a `boto3.Session` without explicitly passing credentials, relying on the default credential providers, or using environment variables for region configuration.
- Preconditions:
    - A developer uses the example code from the `README.md` as a template for implementing the authentication plugin.
    - The developer is not fully aware of the security risks of hardcoding credentials or does not follow secure coding practices.
    - The developer exposes the application code containing hardcoded credentials in a public repository or accessible environment.
- Source code analysis:
    - **File: /code/README.md**
    - The `README.md` file contains example code blocks under sections "Programmatically Configure the Driver With a boto3 session" and "Programmatically Configure the Drive with raw AWS Credentials".
    - These code blocks directly instantiate `boto3.Session` and `SigV4AuthProvider` with hardcoded values for `aws_access_key_id`, `aws_secret_access_key`, and `aws_session_token`.
    ```python
    boto_session = boto3.Session(aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
                                 aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                                 aws_session_token="AQoDYXdzEJr...<remainder of token>",
                                 region_name="us-east-2")
    auth_provider = SigV4AuthProvider(boto_session)
    ```
    ```python
    auth_provider = SigV4AuthProvider(aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
                                     aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                                     aws_session_token="AQoDYXdzEJr...<remainder of token>",
                                     region_name="us-east-2")
    ```
    - The use of `AKIAIOSFODNN7EXAMPLE` and `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` as example credentials might mislead developers into thinking it is acceptable to hardcode their own credentials in a similar manner, especially if they are new to AWS security best practices.
- Security test case:
    1. Create a public GitHub repository.
    2. Create a Python application that uses the `cassandra-sigv4` plugin and includes example code from the `README.md`, replacing the example credentials with your own test AWS credentials (ensure these test credentials have limited permissions to minimize risk during testing).
    3. Commit and push this code to the public GitHub repository.
    4. Wait for a short period (e.g., a few hours) to allow search engines and automated credential scanners to index the repository.
    5. Use online tools or scripts designed to scan public repositories for exposed credentials (or manually search GitHub for the committed access key).
    6. Verify if the test AWS credentials can be found in the public repository.
    7. (Optional but recommended for complete validation) Attempt to use the found credentials to authenticate against AWS services (using the limited permission test credentials) to confirm they are valid and functional.

This test case demonstrates how easily hardcoded credentials in example code can be exposed and discovered in public repositories, validating the vulnerability.