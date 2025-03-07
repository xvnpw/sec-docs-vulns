## Combined Vulnerability Report

The following vulnerabilities were identified and consolidated from the provided lists.

### 1. Hardcoded Access Token

- **Description:**
    - Users of this Python library are instructed in the `README.md` file to hardcode their Azure HPC Pack ACM REST API `access_token` directly into their Python scripts.
    - The `README.md` example explicitly shows how to set the `access_token` as a string literal: `hpc_acm.configuration.access_token = 'YOUR_ACCESS_TOKEN'`.
    - If these scripts are exposed publicly (e.g., on GitHub), attackers can easily extract the hardcoded `access_token`.

- **Impact:**
    - **Unauthorized Access to HPC Cluster:** An attacker with a valid `access_token` can authenticate to the Azure HPC Pack ACM REST API.
    - **Full API Access:**  The attacker gains the same API access as the legitimate user associated with the token, potentially allowing them to:
        - Retrieve sensitive cluster information.
        - Modify cluster settings and disrupt operations.
        - Cancel or create jobs, manipulating resources.
        - Access job outputs and sensitive data.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - None. The project's documentation currently encourages hardcoding the access token and lacks any warnings or secure alternatives.

- **Missing Mitigations:**
    - **Security Warning in Documentation:**  The documentation should prominently warn against hardcoding access tokens.
    - **Secure Token Storage Recommendations:**  Provide clear guidance on secure alternatives like:
        - Environment variables.
        - Secure configuration files.
        - Azure Key Vault or similar credential managers.
    - **Updated Code Examples:**  Documentation examples should demonstrate secure token configuration using environment variables or configuration files.
    - **Runtime Warning:**  Implement a runtime warning when the library detects an access token being set directly as a string literal.

- **Preconditions:**
    - A user hardcodes their `access_token` into a Python script as instructed by the documentation.
    - The script containing the hardcoded token is exposed to an attacker through public repositories, insecure sharing, or publicly accessible storage.

- **Source Code Analysis:**
    - **`README.md` File:**
        - The "Getting Started" section in `README.md` shows the insecure example: `hpc_acm.configuration.access_token = 'YOUR_ACCESS_TOKEN'`.
        - This actively encourages hardcoding the token.
    - **`hpc_acm/configuration.py` File:**
        ```python
        class Configuration(six.with_metaclass(TypeWithDefault, object)):
            ...
            # access token for OAuth
            self.access_token = ""
            ...
        ```
        - The `Configuration` class directly accepts and stores the `access_token` without security checks or warnings about hardcoding.

- **Security Test Case:**
    1. **Setup Test Environment:** Access to an Azure HPC Pack ACM REST API endpoint and the `hpc-acm` library installed.
    2. **Create Insecure Script:** Create `insecure_script.py` with a hardcoded dummy token:
        ```python
        import hpc_acm
        hpc_acm.configuration.host = 'https://YOUR_SERVER_NAME/YOUR_PATH'
        hpc_acm.configuration.access_token = 'INSECURE_HARDCODED_TOKEN'
        api_instance = hpc_acm.DefaultApi()
        try:
            nodes = api_instance.get_nodes()
            print("Successfully accessed nodes using hardcoded token.")
        except hpc_acm.rest.ApiException as e:
            print(f"API Exception: {e}")
        ```
    3. **Expose the Script:** Simulate public exposure by committing to a public (or private for testing) GitHub repo or placing it in public web storage.
    4. **Attacker Access and Token Extraction:** As an attacker, access the exposed script and extract `INSECURE_HARDCODED_TOKEN`.
    5. **Attempt API Access with Extracted Token:** Use a separate script or tool with the extracted token:
        ```python
        import hpc_acm
        hpc_acm.configuration.host = 'https://YOUR_SERVER_NAME/YOUR_PATH'
        hpc_acm.configuration.access_token = 'INSECURE_HARDCODED_TOKEN'
        api_instance = hpc_acm.DefaultApi()
        try:
            nodes = api_instance.get_nodes()
            print("Attacker: Successfully accessed nodes using extracted token.")
        except hpc_acm.rest.ApiException as e:
            print(f"Attacker API Exception: {e}")
        ```
    6. **Verify Unauthorized Access:** Run both scripts. Successful API calls using both the hardcoded and extracted tokens confirm the vulnerability.

---

### 2. Man-in-the-Middle vulnerability due to lack of enforced HTTPS and certificate verification

- **Description:**
    1. A user installs and configures the `hpc-acm` library.
    2. The user sets `hpc_acm.configuration.host` to use `http://` or connects via insecure network with a MitM attacker.
    3. The user executes code making API requests.
    4. If HTTPS is not enforced and certificate verification is disabled, traffic is unencrypted.
    5. A MitM attacker intercepts the unencrypted traffic.
    6. The attacker extracts the OAuth2 access token from HTTP requests.
    7. The attacker uses the stolen token for unauthorized access to the HPC cluster API.

- **Impact:**
    - **Unauthorized access to the Azure HPC Pack cluster.**
    - An attacker can use the stolen OAuth2 access token to:
        - View sensitive cluster information.
        - Cancel or create jobs.
        - Modify node configurations.
        - Disrupt cluster operations.
        - Potentially exfiltrate or manipulate data.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - **Default HTTPS protocol in example code:** `README.md` example uses `https://`.
    - **Default SSL verification:** `self.verify_ssl` is set to `True` by default in `/code/hpc_acm/configuration.py`.

- **Missing Mitigations:**
    - **Enforced HTTPS:** The library does not enforce HTTPS; users can still use `http://`.
    - **Documentation Warning:** Lack of explicit warnings in documentation about HTTP risks and disabling SSL verification.
    - **Code-level Warning:** No warnings or errors if the user configures `http://` or disables SSL verification.

- **Preconditions:**
    - User configures the library to use HTTP or HTTPS with disabled/improper certificate verification.
    - User's network is susceptible to MitM attacks (e.g., public Wi-Fi).
    - An attacker is present on the network monitoring traffic.

- **Source Code Analysis:**
    1. **`/code/hpc_acm/configuration.py`**:
        ```python
        class Configuration(six.with_metaclass(TypeWithDefault, object)):
            # ...
            def __init__(self):
                # ...
                # Default Base url
                self.host = "https://localhost/v1"
                # ...
                # SSL/TLS verification
                self.verify_ssl = True
                # ...
        ```
        - `verify_ssl` defaults to `True`, but `host` can be set to `http://` without restrictions.
    2. **`/code/hpc_acm/rest.py`**:
        ```python
        class RESTClientObject(object):
            def __init__(self, configuration, pools_size=4, maxsize=None):
                # ...
                if configuration.verify_ssl:
                    cert_reqs = ssl.CERT_REQUIRED
                else:
                    cert_reqs = ssl.CERT_NONE
                # ...
                self.pool_manager = urllib3.PoolManager(
                    # ...
                    cert_reqs=cert_reqs,
                    ca_certs=ca_certs,
                    # ...
                )
        ```
        - Correctly uses `configuration.verify_ssl` for urllib3 requests.
    3. **`/code/README.md`**:
        ```markdown
        ## Getting Started
        # ...
        hpc_acm.configuration.host = 'https://YOUR_SERVER_NAME/YOUR_PATH'
        # ...
        ```
        - Example uses `https://`, but no warning about HTTP risks or SSL verification.

- **Security Test Case:**
    1. **Setup MitM Proxy:** Use `mitmproxy` or Burp Suite.
    2. **Configure Library for Insecure Connection:**
        ```python
        import hpc_acm
        hpc_acm.configuration.host = 'http://YOUR_SERVER_NAME/YOUR_PATH' # Insecure HTTP
        hpc_acm.configuration.verify_ssl = False # Optional: Disable SSL verification for HTTPS
        hpc_acm.configuration.access_token = 'YOUR_ACCESS_TOKEN'
        api_instance = hpc_acm.DefaultApi()
        try:
            nodes = api_instance.get_nodes()
            print("Nodes:", nodes)
        except hpc_acm.rest.ApiException as e:
            print("Exception when calling DefaultApi->get_nodes: %s\n" % e)
        ```
    3. **Run Test Script with Proxy:**
        ```bash
        export http_proxy=http://127.0.0.1:8080
        export https_proxy=http://127.0.0.1:8080
        python your_test_script.py
        ```
    4. **Intercept and Analyze Traffic:** Observe traffic in the MitM proxy. Look for the `Authorization: Bearer YOUR_ACCESS_TOKEN` header in plaintext in HTTP requests.
    5. **Verification:** If the access token is visible in plaintext in the MitM proxy, the vulnerability is confirmed.