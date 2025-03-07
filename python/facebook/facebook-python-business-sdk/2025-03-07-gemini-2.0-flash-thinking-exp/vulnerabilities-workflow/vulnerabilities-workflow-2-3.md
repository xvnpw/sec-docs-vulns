* Vulnerability Name: Hardcoded User-Agent String
* Description:
    1. The SDK uses a hardcoded User-Agent string in `facebook_business/api.py`.
    2. This User-Agent string includes the SDK version.
    3. An attacker can use this information to identify applications using vulnerable versions of the SDK.
    4. Once identified, attackers can target these applications with exploits specific to those SDK versions.
* Impact:
    - Information Disclosure: The User-Agent string reveals the SDK version, potentially allowing attackers to identify vulnerable applications.
    - Increased Attack Surface: Knowing the SDK version simplifies targeting applications with version-specific exploits.
* Vulnerability Rank: medium
* Currently Implemented Mitigations:
    - None. The User-Agent string is hardcoded and always sent with requests.
* Missing Mitigations:
    - Remove the SDK version from the default User-Agent string.
    - Consider making the User-Agent string configurable or dynamically generated without sensitive version information.
* Preconditions:
    - An attacker needs to be able to intercept or observe HTTP requests made by an application using the SDK. This is a common scenario in network attacks, especially if the application communicates over unencrypted channels or the attacker is positioned within the network.
* Source Code Analysis:
    1. File: `/code/facebook_business/api.py`
    2. Line 63: `HTTP_DEFAULT_HEADERS = { 'User-Agent': "fbbizsdk-python-%s" % SDK_VERSION, }`
    3. The `SDK_VERSION` is retrieved from `apiconfig.ads_api_config['SDK_VERSION']` which is hardcoded in `/code/facebook_business/apiconfig.py`
    4. This hardcoded User-Agent string is added to every API request made by the SDK in the `call` method.
    5. Line 174: `headers = headers.copy()`
    6. Line 175: `headers.update(FacebookAdsApi.HTTP_DEFAULT_HEADERS)`
* Security Test Case:
    1. Setup a test Python application that uses the `facebook-business` SDK and makes an API call (e.g., fetching ad accounts).
    2. Use a network intercepting tool (like Wireshark or tcpdump) or a proxy (like Burp Suite) to capture the HTTP request sent by the application.
    3. Examine the captured HTTP request headers.
    4. Verify that the `User-Agent` header is present and contains the hardcoded string `fbbizsdk-python-v<version>`.
    5. Example `User-Agent` header: `User-Agent: fbbizsdk-python-v22.0.2`