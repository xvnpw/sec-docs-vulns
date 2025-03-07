- Vulnerability Name: Man-in-the-Middle vulnerability due to lack of enforced HTTPS and certificate verification

- Description:
    1. A user installs the `hpc-acm` Python library.
    2. The user configures the library to interact with an Azure HPC Pack ACM server.
    3. The user, either intentionally or unintentionally, sets the `hpc_acm.configuration.host` to use `http://` instead of `https://`, or connects over an insecure network where a Man-in-the-Middle (MitM) attacker is present.
    4. The user executes code that uses the library to make API requests to the HPC Pack ACM server.
    5. If HTTPS is not enforced and certificate verification is not properly configured (or disabled), the network traffic between the user's application and the HPC Pack ACM server is not encrypted.
    6. A MitM attacker, positioned on the network path, intercepts the unencrypted traffic.
    7. The attacker extracts the OAuth2 access token from the intercepted HTTP requests.
    8. The attacker uses the stolen OAuth2 access token to authenticate to the HPC Pack ACM REST API, gaining unauthorized access to manage the HPC cluster.

- Impact:
    - Unauthorized access to the Azure HPC Pack cluster.
    - An attacker can perform actions on the HPC cluster using the stolen OAuth2 access token, potentially including:
        - Viewing sensitive information about nodes, jobs, and cluster configuration.
        - Canceling or creating jobs.
        - Modifying node configurations (depending on API permissions).
        - Disrupting cluster operations.
        - Potential data exfiltration or manipulation depending on the scope of API access.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - Default HTTPS protocol in example code: The `README.md` example uses `https://` in the `hpc_acm.configuration.host` example, suggesting secure communication.
    - Default SSL verification: In `/code/hpc_acm/configuration.py`, `self.verify_ssl` is set to `True` by default, enabling SSL certificate verification.

- Missing Mitigations:
    - Enforced HTTPS: The library does not enforce the use of HTTPS. Users can still configure `hpc_acm.configuration.host` with `http://` and potentially disable `verify_ssl`, making the connection insecure.
    - Documentation Warning: The documentation (`README.md` and other docs) does not explicitly warn users about the security risks of using HTTP or disabling HTTPS verification. It also lacks clear guidance on ensuring secure HTTPS connections, including the importance of server certificate validation and the risks of bypassing it.
    - Code-level Warning: The library does not issue any warnings or errors if the user configures it to use `http://` or disables SSL verification.

- Preconditions:
    - The user configures the `hpc-acm` library to connect to the HPC Pack ACM server over HTTP or HTTPS with disabled or improperly configured certificate verification.
    - The user's network is susceptible to Man-in-the-Middle attacks (e.g., using public Wi-Fi, compromised network infrastructure).
    - An attacker is present on the network and actively monitoring traffic.

- Source Code Analysis:
    1. **`/code/hpc_acm/configuration.py`**:
        - The `Configuration` class sets `self.verify_ssl = True` by default. This is a positive security measure, as it enables SSL verification by default.
        - However, the `host` attribute, which defines the API endpoint, can be set by the user to either `http://` or `https://` without any restrictions or warnings within the code.
        ```python
        class Configuration(six.with_metaclass(TypeWithDefault, object)):
            # ...
            def __init__(self):
                # ...
                # Default Base url
                self.host = "https://localhost/v1"
                # ...
                # SSL/TLS verification
                # Set this to false to skip verifying SSL certificate when calling API
                # from https server.
                self.verify_ssl = True
                # ...
        ```
    2. **`/code/hpc_acm/rest.py`**:
        - The `RESTClientObject` class uses the `Configuration` object to initialize `urllib3.PoolManager`. It correctly utilizes `configuration.verify_ssl` and `configuration.ssl_ca_cert` to set up SSL verification for `urllib3` requests.
        ```python
        class RESTClientObject(object):
            def __init__(self, configuration, pools_size=4, maxsize=None):
                # ...
                # cert_reqs
                if configuration.verify_ssl:
                    cert_reqs = ssl.CERT_REQUIRED
                else:
                    cert_reqs = ssl.CERT_NONE

                # ca_certs
                if configuration.ssl_ca_cert:
                    ca_certs = configuration.ssl_ca_cert
                else:
                    # if not set certificate file, use Mozilla's root certificates.
                    ca_certs = certifi.where()
                # ...
                self.pool_manager = urllib3.PoolManager(
                    # ...
                    cert_reqs=cert_reqs,
                    ca_certs=ca_certs,
                    # ...
                )
        ```
    3. **`/code/README.md`**:
        - The `README.md` provides an example in "Getting Started" section that uses `https://` for `hpc_acm.configuration.host`.
        ```markdown
        ## Getting Started

        Please follow the [installation procedure](#installation--usage) and then run the following:

        ```python
        # ...
        # Set your API Base Point
        hpc_acm.configuration.host = 'https://YOUR_SERVER_NAME/YOUR_PATH'
        # Configure OAuth2 access token for authorization: aad
        hpc_acm.configuration.access_token = 'YOUR_ACCESS_TOKEN'
        # ...
        ```
        - **However, it lacks any explicit warning about the importance of using HTTPS and the risks associated with HTTP or disabling SSL verification.** There's no guidance on how to ensure secure connections or the potential security implications if users deviate from the HTTPS example.

- Security Test Case:
    1. **Setup MitM Proxy:** Use a tool like `mitmproxy` or `Burp Suite` to set up a Man-in-the-Middle proxy that can intercept HTTP/HTTPS traffic. Configure the proxy to listen on a specific port (e.g., 8080).

    2. **Configure Library for Insecure Connection:** Modify the example code from `README.md` or create a test script to configure the `hpc-acm` library to connect over HTTP, or HTTPS with disabled verification.

        ```python
        import hpc_acm

        # Insecure HTTP connection (Vulnerable)
        hpc_acm.configuration.host = 'http://YOUR_SERVER_NAME/YOUR_PATH' # Note: http instead of https
        hpc_acm.configuration.verify_ssl = False # Disable SSL verification (Optional, but makes HTTPS insecure too)
        hpc_acm.configuration.access_token = 'YOUR_ACCESS_TOKEN'
        api_instance = hpc_acm.DefaultApi()

        try:
            nodes = api_instance.get_nodes() # Make an API call
            print("Nodes:", nodes)
        except hpc_acm.rest.ApiException as e:
            print("Exception when calling DefaultApi->get_nodes: %s\n" % e)
        ```
        - **Note:** Replace `YOUR_SERVER_NAME/YOUR_PATH` and `YOUR_ACCESS_TOKEN` with appropriate values for a test HPC Pack ACM server.

    3. **Run Test Script with Proxy:** Execute the Python script, ensuring that network traffic from the script is routed through the MitM proxy. This can be achieved by setting the `http_proxy` and `https_proxy` environment variables to point to the MitM proxy address (e.g., `http://127.0.0.1:8080`).

        ```bash
        export http_proxy=http://127.0.0.1:8080
        export https_proxy=http://127.0.0.1:8080
        python your_test_script.py
        ```

    4. **Intercept and Analyze Traffic:** Observe the traffic intercepted by the MitM proxy tool.
        - In `mitmproxy`, you can inspect the HTTP requests and responses.
        - Look for the request headers being sent to the HPC Pack ACM server.
        - If the connection is insecure (HTTP or HTTPS with verification disabled), you will be able to see the `Authorization: Bearer YOUR_ACCESS_TOKEN` header in plaintext within the intercepted HTTP request.

    5. **Verification:**
        - If you can clearly see the OAuth2 access token in the intercepted traffic within the MitM proxy, the vulnerability is confirmed. This demonstrates that an attacker on the network could steal the token if the user connects over an insecure connection.
        - If HTTPS verification was enabled and properly functioning, the connection should be TLS-encrypted, and the MitM proxy would only show encrypted data, not the plaintext access token.

This test case proves that if a user disregards best practices and connects over HTTP or disables HTTPS verification, the OAuth2 access token is exposed to network interception, confirming the Man-in-the-Middle vulnerability.