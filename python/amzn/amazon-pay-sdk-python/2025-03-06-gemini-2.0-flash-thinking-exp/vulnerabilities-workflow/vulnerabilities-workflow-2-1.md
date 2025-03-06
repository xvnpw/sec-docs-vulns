### Vulnerability 1: Insecure Storage of API Credentials

* Description:
    1. Developers using the Amazon Pay Python SDK are required to provide their Amazon Pay API credentials, specifically `mws_access_key` and `mws_secret_key`, to authenticate API requests.
    2. The SDK's documentation and examples in the `README.md` file illustrate instantiating the `AmazonPayClient` by directly passing these credentials as parameters in the code.
    3. If developers follow these examples directly and hardcode the `mws_access_key` and `mws_secret_key` within their application's source code or configuration files, these sensitive credentials can be easily exposed.
    4. Exposure can occur through various means, such as committing the code to public version control repositories (e.g., GitHub), insecure storage of configuration files, or accidental leakage in logs.
    5. Once exposed, malicious actors can obtain these credentials.
    6. With compromised `mws_access_key` and `mws_secret_key`, attackers can impersonate the legitimate merchant and make unauthorized API calls to Amazon Pay.
    7. These unauthorized calls can include actions like initiating payments, capturing funds, processing refunds, and accessing sensitive order and customer data.

* Impact:
    - Unauthorized access to the merchant's Amazon Pay account and resources.
    - Financial loss due to unauthorized transactions (e.g., unauthorized captures or refunds).
    - Exposure of sensitive customer and order data, leading to potential privacy breaches and compliance violations (e.g., GDPR, PCI DSS).
    - Reputational damage to the merchant due to security incidents.
    - Potential misuse of the payment system for fraudulent activities.

* Vulnerability Rank: Critical

* Currently Implemented Mitigations:
    - None. The SDK itself does not implement any mitigations against insecure credential storage. It provides flexibility in how credentials are provided (parameters or environment variables) but doesn't guide developers towards secure practices.

* Missing Mitigations:
    - **Documentation Enhancement:** The documentation should be updated to strongly discourage hardcoding API credentials directly in the code. It should explicitly recommend using secure environment variables or dedicated secrets management solutions for storing and retrieving sensitive credentials. The `README.md` example should be revised to demonstrate loading credentials from environment variables instead of hardcoding them.
    - **Security Best Practices Guidance:**  Include a dedicated section in the documentation outlining security best practices for handling API credentials, such as:
        - Never hardcode credentials in source code.
        - Utilize environment variables or secure configuration management.
        - Implement access controls to restrict access to systems storing credentials.
        - Regularly rotate API credentials.
        - Monitor for potential credential exposure (e.g., using code scanning tools).
    - **Consider SDK-level Warnings (Potentially Out of Scope):** While it might be intrusive for an SDK, consider adding a warning message (perhaps in debug logging if logging is enabled) if the `AmazonPayClient` is instantiated with credentials passed directly as parameters, suggesting the use of environment variables as a more secure alternative. However, carefully consider the user experience impact.

* Preconditions:
    - An application is built using the deprecated Amazon Pay Python SDK.
    - The developer chooses to hardcode or insecurely manage the `mws_access_key` and `mws_secret_key` for the Amazon Pay API.
    - The application code or its configuration files containing the hardcoded credentials are exposed, for example, by being committed to a public repository or stored insecurely.

* Source Code Analysis:
    - **File: /code/amazon_pay/client.py**
    - The `AmazonPayClient.__init__` method is designed to accept `mws_access_key` and `mws_secret_key` as direct parameters:
    ```python
    def __init__(
            self,
            mws_access_key=None,
            mws_secret_key=None,
            merchant_id=None,
            region=None,
            currency_code=None,
            sandbox=False,
            handle_throttle=True,
            application_name=None,
            application_version=None,
            log_enabled=False,
            log_file_name=None,
            log_level=None):
        # ...
        env_param_map = {'mws_access_key': 'AP_MWS_ACCESS_KEY',
                         'mws_secret_key': 'AP_MWS_SECRET_KEY',
                         'merchant_id': 'AP_MERCHANT_ID',
                         'region': 'AP_REGION',
                         'currency_code': 'AP_CURRENCY_CODE'}
        for param in env_param_map:
            if eval(param) is None:
                try:
                    setattr(self, param, os.environ[env_param_map[param]])
                except:
                    raise ValueError('Invalid {}.'.format(param))
            else:
                setattr(self, param, eval(param))
        # ...
    ```
    - This code snippet shows that the SDK is designed to first check for parameters passed directly to the `AmazonPayClient` constructor. If these parameters are `None`, it then attempts to load them from environment variables. This mechanism is flexible, but the example in `README.md` promotes the less secure practice of direct parameter passing.

    - **File: /code/README.md**
    - The "Client Code Examples" section demonstrates instantiating `AmazonPayClient` with hardcoded credentials:
    ```python
    from amazon_pay.client import AmazonPayClient

    client = AmazonPayClient(
            mws_access_key='YOUR_ACCESS_KEY', # <== Hardcoded credential example
            mws_secret_key='YOUR_SECRET_KEY', # <== Hardcoded credential example
            merchant_id='YOUR_MERCHANT_ID',
            region='na',
            currency_code='USD',
            sandbox=True)
    ```
    - This example directly encourages developers to replace `'YOUR_ACCESS_KEY'` and `'YOUR_SECRET_KEY'` with their actual credentials, potentially leading to hardcoding if developers copy and paste this example without understanding the security implications.

* Security Test Case:
    1. **Setup:** Create a new public repository on GitHub (or a similar public code hosting platform).
    2. **Application Code:** Create a simple Python script (e.g., `test_amazon_pay.py`) that utilizes the `amazon-pay` SDK.  Instantiate the `AmazonPayClient` within this script, directly embedding placeholder values for `mws_access_key` as `'YOUR_ACCESS_KEY_DUMMY'` and `mws_secret_key` as `'YOUR_SECRET_KEY_DUMMY'`, while using valid values for `merchant_id`, `region`, and `currency_code` (for the sandbox environment). Include a basic API call, such as `client.get_service_status()`.
        ```python
        import os
        from amazon_pay.client import AmazonPayClient

        client = AmazonPayClient(
                mws_access_key='YOUR_ACCESS_KEY_DUMMY',
                mws_secret_key='YOUR_SECRET_KEY_DUMMY',
                merchant_id='YOUR_MERCHANT_ID', # Replace with your sandbox merchant ID
                region='na',
                currency_code='USD',
                sandbox=True)

        status = client.get_service_status()
        if status.success:
            print("Amazon Pay Service Status: Success")
        else:
            print("Amazon Pay Service Status: Error")
        ```
    3. **Commit and Push:** Commit the `test_amazon_pay.py` file to the public GitHub repository.
    4. **GitHub Code Search:** Wait for a few minutes to allow GitHub to index the newly committed code. Then, use GitHub's code search feature (or a similar code search engine like Grep.app or Sourcegraph) and search for the string `"YOUR_ACCESS_KEY_DUMMY"`.
    5. **Verification:** If the public repository created in step 1 and the `test_amazon_pay.py` file are found in the GitHub code search results, it confirms that credentials hardcoded as demonstrated in the SDK's example can be easily discoverable when code is publicly exposed.
    6. **Cleanup:**  After the test, remember to remove the public repository if it was created solely for testing purposes to avoid any potential confusion or unintended exposure, even though dummy credentials were used.

**Note:** This test case is designed to demonstrate the *discoverability* of hardcoded credentials due to examples and the SDK's input method. It does not involve using valid, real API credentials or attempting to perform unauthorized actions, as that would be unethical and potentially illegal. The purpose is solely to highlight the vulnerability arising from insecure credential handling practices encouraged by the provided documentation and examples.