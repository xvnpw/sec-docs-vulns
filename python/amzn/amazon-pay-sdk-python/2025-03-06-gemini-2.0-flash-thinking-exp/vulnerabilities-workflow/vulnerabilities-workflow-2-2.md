### Vulnerability List:

- Vulnerability Name: Insecure API Credential Management via Hardcoding in Client Instantiation

- Description:
    1. The `README.md` documentation provides example code for instantiating the `AmazonPayClient` class.
    2. This example code directly embeds sensitive API credentials (mws_access_key, mws_secret_key, merchant_id) as string literals within the client instantiation code.
    3. Developers following this example might directly copy and paste this code into their applications, replacing the placeholder values with their actual API credentials.
    4. This practice leads to hardcoding API credentials directly into the application's source code.
    5. If the application's source code repository is publicly accessible or becomes compromised, the hardcoded API credentials will be exposed to unauthorized parties.
    6. Attackers can extract these credentials and gain unauthorized access to the merchant's Amazon Pay account.

- Impact:
    - **High**: Unauthorized access to the Amazon Pay merchant account.
    - Financial loss due to unauthorized transactions.
    - Data breach potentially exposing customer transaction data.
    - Reputational damage for the merchant.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None in the provided code or documentation to prevent hardcoding of credentials in client instantiation.
    - The code itself allows for setting credentials via environment variables, which is a more secure alternative, but this is not emphasized in the `README.md` example.

- Missing Mitigations:
    - **Documentation Update**: The `README.md` should be updated to strongly discourage hardcoding API credentials in the client instantiation examples. It should instead promote secure methods such as using environment variables or secure configuration management practices.
    - **Security Best Practices Guide**:  Include a dedicated section in the documentation outlining security best practices for managing Amazon Pay API credentials. This section should emphasize:
        - Avoiding hardcoding credentials directly in source code.
        - Utilizing environment variables for credential storage.
        - Employing secure configuration management tools and practices.
        - Regularly rotating API credentials.
        - Limiting access to systems where credentials are stored.

- Preconditions:
    - Developers use the deprecated Amazon Pay Python SDK and follow the insecure example in the `README.md` for client instantiation.
    - The application's source code containing hardcoded credentials is accessible to unauthorized individuals (e.g., public repository, compromised server, insider threat).

- Source Code Analysis:
    1. **File: `/code/README.md`**:
    2. Locate the "Client Code Examples" section.
    3. Observe the instantiation example for `AmazonPayClient`:
    ```python
    from amazon_pay.client import AmazonPayClient

    client = AmazonPayClient(
            mws_access_key='YOUR_ACCESS_KEY',
            mws_secret_key='YOUR_SECRET_KEY',
            merchant_id='YOUR_MERCHANT_ID',
            region='na',
            currency_code='USD',
            sandbox=True)
    ```
    4. Notice that the values for `mws_access_key`, `mws_secret_key`, and `merchant_id` are provided as string literals `'YOUR_ACCESS_KEY'`, `'YOUR_SECRET_KEY'`, and `'YOUR_MERCHANT_ID'`.
    5. The documentation encourages replacing these placeholders with actual keys, without explicitly warning against hardcoding or suggesting secure alternatives in this prominent example.
    6. While the documentation mentions environment variables as an alternative method for providing credentials, it's presented as a fallback if parameters are "not passed in", rather than the recommended secure approach.

- Security Test Case:
    1. **Setup**:
        - Assume an attacker has access to a public GitHub repository containing an application that uses this deprecated Amazon Pay Python SDK.
        - The developer has followed the `README.md` example and hardcoded their sandbox Amazon Pay API credentials directly into the application's Python code (e.g., in `client.py` file).
    2. **Action**:
        - The attacker clones the public GitHub repository of the application.
        - The attacker opens the `client.py` (or any file where `AmazonPayClient` is instantiated) and inspects the code.
        - The attacker searches for lines instantiating `AmazonPayClient` and extracts the values provided for `mws_access_key`, `mws_secret_key`, and `merchant_id`. These are the hardcoded sandbox API credentials.
    3. **Expected Result**:
        - The attacker successfully retrieves the sandbox `mws_access_key`, `mws_secret_key`, and `merchant_id` directly from the source code.
        - The attacker can now use these credentials to make unauthorized API calls to the merchant's Amazon Pay sandbox account.
    4. **Exploit Scenario (Beyond Test Case)**:
        - If the application were deployed with production credentials hardcoded and the source code or the deployed application (e.g., via decompilation or server access) became accessible to an attacker, the attacker could similarly extract production credentials.
        - Using production credentials, the attacker could perform actions like initiating unauthorized payments, modifying account settings, or accessing sensitive transaction data within the merchant's real Amazon Pay account, leading to financial and reputational damage.