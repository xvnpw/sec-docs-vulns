- Vulnerability Name: Insecure Storage of Access Tokens in Example Code

- Description:
    - The `README.md` file provides a "Quick Start" guide with a code example (`test.py`) in the "Bootstrapping" section.
    - This example directly hardcodes `my_app_id`, `my_app_secret`, and `my_access_token` as string literals within the Python script.
    - Developers following this "Quick Start" guide might copy and paste this code directly into their applications for testing or initial setup.
    - If developers fail to replace these hardcoded values with secure methods of obtaining and storing access tokens before deploying their applications, the access tokens will be exposed within the application's source code.
    - Attackers who gain access to the application's source code (e.g., through public repositories, misconfigured servers, or compromised developer machines) can easily extract these hardcoded access tokens.
    - With these access tokens, attackers can then impersonate the Facebook user or Page associated with the token and gain unauthorized access to Facebook Business accounts and data.

- Impact:
    - **High/Critical:** Unauthorized access to Facebook Business accounts.
    - Data breach: Attackers can access and exfiltrate sensitive business data managed through Facebook APIs.
    - Account takeover: Attackers can take full control of Facebook Business accounts, potentially leading to financial loss, reputational damage, and misuse of advertising budgets.
    - Privacy violation: Exposure of user or Page data associated with the access token.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - **None:** The provided code example in `README.md` has no built-in mitigations for insecure token storage.
    - The README does have a note recommending turning on 'App Secret Proof for Server API calls', but this is a general security recommendation for Facebook apps and not a mitigation for hardcoding tokens within application code itself.

- Missing Mitigations:
    - **Secure Token Storage Guidance:** The SDK documentation and "Quick Start" guide lack clear and prominent warnings against hardcoding access tokens. They should strongly advise developers to use secure storage mechanisms such as environment variables, configuration files (outside of the code repository), or dedicated secret management systems.
    - **Example Code Improvement:** The example code should be modified to avoid hardcoding tokens. It could use placeholder values and clearly instruct users to replace them with tokens obtained through secure means, or ideally, demonstrate reading tokens from environment variables.
    - **Security Best Practices Documentation:** A dedicated section on security best practices should be added to the documentation, explicitly addressing the risks of insecure token handling and providing concrete recommendations for secure storage and management.

- Preconditions:
    1. Developers use the `facebook-business` Python SDK.
    2. Developers follow the "Quick Start" guide in `README.md` and copy the example code.
    3. Developers fail to replace the hardcoded access tokens in the example code with secure methods before deploying their application.
    4. Attackers gain access to the application's source code.

- Source Code Analysis:
    ```markdown
    File: /code/README.md

    ...

    ### Bootstrapping

    ### Create test.py
    Create a test.py file with the contents below (assuming your system is using python 2.7 and installed under /opt/homebrew/lib/python2.7/site-packages. Update to your proper python location.):

    ```python
    import sys
    sys.path.append('/opt/homebrew/lib/python2.7/site-packages') # Replace this with the place you installed facebookads using pip
    sys.path.append('/opt/homebrew/lib/python2.7/site-packages/facebook_business-3.0.0-py2.7.egg-info') # same as above

    from facebook_business.api import FacebookAdsApi
    from facebook_business.adobjects.adaccount import AdAccount

    my_app_id = 'your-app-id'
    my_app_secret = 'your-appsecret'
    my_access_token = 'your-page-access-token'
    FacebookAdsApi.init(my_app_id, my_app_secret, my_access_token)
    my_account = AdAccount('act_<your-adaccount-id>')
    campaigns = my_account.get_campaigns()
    print(campaigns)
    ```
    **Analysis:**
    - Lines 9-11 of `test.py` in `README.md` directly assign string literals to variables `my_app_id`, `my_app_secret`, and `my_access_token`. These variables are then used in `FacebookAdsApi.init()`.
    - The comments "your-app-id", "your-appsecret", and "your-page-access-token" are placeholders, but the example strongly implies direct replacement within the code file.
    - This encourages a copy-paste approach that can lead to developers unintentionally hardcoding sensitive information in their applications.

- Security Test Case:
    1. **Setup a test application:** Create a simple Python application that uses the `facebook-business` SDK and includes the `test.py` code example from the `README.md`, replacing placeholders with valid (but test) App ID, App Secret, and Access Token.
    2. **Simulate insecure deployment:**  Imagine deploying this application in a way that the source code could be accessed by an attacker (e.g., pushing to a public GitHub repository, deploying to a misconfigured server accessible to attackers). For the purpose of this test, simply make the `test.py` file publicly readable.
    3. **Attacker Access:** As an attacker, gain access to the `test.py` file (e.g., by browsing the public repository or accessing the server).
    4. **Extract Tokens:** Open `test.py` and read the values assigned to `my_app_id`, `my_app_secret`, and `my_access_token`.
    5. **Verify Access Token Validity:** Use the extracted `my_access_token` to make an API request to Facebook using Graph Explorer or `curl` to access a protected resource (e.g., user's ad accounts). If successful, this proves the access token is valid and can be used by an attacker.
    ```bash
    curl -i -X GET "https://graph.facebook.com/vXX.X/me/adaccounts?access_token=<YOUR_EXTRACTED_ACCESS_TOKEN>"
    ```
    6. **Observe Impact:** A successful response from the Facebook API confirms that the attacker has gained unauthorized access using the extracted hardcoded access token. This demonstrates the vulnerability and its potential impact.