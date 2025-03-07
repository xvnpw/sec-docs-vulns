### Vulnerability List for db-dsc-jobs Project

* Vulnerability Name: Databricks Workspace Redirection via `params.json` Manipulation
* Description:
    1. The application reads the Databricks workspace URI from the `databricks_uri` field in the `params.json` file.
    2. An attacker gains write access to the file system where `params.json` is stored.
    3. The attacker modifies the `params.json` file, replacing the legitimate `databricks_uri` with a URI pointing to an attacker-controlled Databricks workspace or a workspace they want to target without authorization.
    4. The application, when executed, uses the attacker-provided `databricks_uri` to construct API requests.
    5. Consequently, all subsequent API calls for job management (listing, deleting, creating jobs) are directed to the attacker-specified Databricks workspace instead of the intended legitimate workspace.
* Impact:
    - **Unauthorized Access to Data:** If the attacker redirects the application to their workspace, they might gain access to data or resources within that workspace using the application's authenticated credentials.
    - **Data Manipulation in Attacker Workspace:** The application might inadvertently manage jobs (create, delete) in the attacker's Databricks workspace, potentially leading to data corruption or disruption in that workspace.
    - **Lateral Movement (Potentially):** In a more complex scenario, if the attacker's workspace mimics a legitimate Databricks environment and the application is used in an automated or unattended fashion, it could be a step in a lateral movement attack.
* Vulnerability Rank: Medium
* Currently Implemented Mitigations:
    - None. The application code directly uses the `databricks_uri` from the `params.json` file without any validation or sanitization. The README file mentions that the `params.json` needs to be created or modified prior to execution but does not provide specific security guidance on securing this file against unauthorized modification in the context of workspace redirection.
* Missing Mitigations:
    - **Input Validation for `databricks_uri`:** Implement validation to ensure the `databricks_uri` conforms to expected formats (e.g., using regular expressions or URI parsing libraries) and potentially matches a predefined list or pattern of allowed Databricks workspace URIs.
    - **Workspace URI Whitelisting/Hardcoding (If Applicable):** If the application is intended to operate within a specific set of Databricks workspaces, consider whitelisting or even hardcoding the allowed `databricks_uri` values to prevent redirection to arbitrary workspaces.
* Preconditions:
    - The attacker must have write access to the file system where the `params.json` file is stored. This could be achieved through various means depending on the deployment environment, such as exploiting other vulnerabilities in the system, social engineering, or insider threats.
* Source Code Analysis:
    1. **File: `/code/job.py`**:
        ```python
        parser = argparse.ArgumentParser(description='DSC job management for Databricks')
        parser.add_argument('--params', type=str, help='your Databricks and Azure parameter file', default='params.json')
        args = parser.parse_args()

        configuration = json.load(open(args.params))

        databricks_uri = configuration['databricks_uri'] + "/api/2.0/%s"
        ```
        - The code reads the `params.json` file specified by the `--params` argument (or defaults to `params.json` if not provided).
        - It loads the JSON content into the `configuration` variable.
        - Critically, it directly extracts the `databricks_uri` from the `configuration` dictionary and uses it to construct the base URL for Databricks API calls. There is no validation, sanitization, or whitelisting performed on the `databricks_uri` value at this point or anywhere else in the code.
    2. **Subsequent API Calls**:
        - The `databricks_uri` variable is used in functions like `get_db` and `post_db` to construct the full API endpoint URLs. For example in `get_db`:
        ```python
        def get_db(action, returnJson=False):
            url = databricks_uri % action
            log("REST - GET - Calling %s" % action)
            response = requests.get(url, headers=head)
            return response.json() if json else response
        ```
        - This demonstrates that any value provided in `params.json` for `databricks_uri` will be directly used to send requests to that URI.

* Security Test Case:
    1. **Setup:**
        - Create a legitimate `params.json` file pointing to your actual Databricks workspace (e.g., `https://adb-xxxxxxxxxxxxxxx.azuredatabricks.net`).
        - Place a few test jobs in the `/jobs/` directory.
        - Run the application `python job.py --params params.json` and verify it correctly lists, deletes, and recreates jobs in your legitimate workspace.
    2. **Malicious `params.json`:**
        - Create a modified `params.json` file (e.g., `malicious_params.json`) where you change the `databricks_uri` to point to a different URI. This could be:
            - A non-existent or fake Databricks endpoint (e.g., `https://attacker-controlled-databricks.net`).
            - A Databricks workspace you have access to for testing purposes but is different from the intended legitimate workspace.
        ```json
        {
            "authority_type": "pat",
            "client_id": "<your-client-id>",
            "databricks_uri": "https://attacker-controlled-databricks.net",
            "pat_token": "<your-pat-token>"
        }
        ```
        - **Note:** For testing against a fake endpoint, you might encounter connection errors. To test redirection to another workspace, ensure you have valid credentials in `malicious_params.json` that are authorized for the *attacker-controlled* workspace (or reuse the legitimate credentials if applicable and you want to test cross-workspace access - be cautious with credentials).
    3. **Run with Malicious `params.json`:**
        - Execute the application using the modified parameters file: `python job.py --params malicious_params.json`.
    4. **Observe Behavior:**
        - **Network Traffic Analysis:** Use a network proxy or monitoring tool (like Wireshark or Burp Suite) to observe the network requests made by the application. Verify that the application is sending requests to the `databricks_uri` specified in `malicious_params.json` (e.g., `attacker-controlled-databricks.net`) instead of your legitimate Databricks workspace.
        - **Error Messages/Logs:** Check the application's output and any logs for error messages related to connecting to the Databricks workspace. If you pointed to a non-existent endpoint, you should see connection errors related to `attacker-controlled-databricks.net`. If you pointed to another workspace and provided valid credentials for it, the application might execute successfully, but against the wrong workspace.
    5. **Verification:**
        - Confirm that the application is indeed interacting with the Databricks workspace specified in the modified `params.json` and *not* the intended legitimate workspace. This confirms the workspace redirection vulnerability.

* Vulnerability Name: Credential Exposure via Insecure Storage in `params.json`
* Description:
    1. The `params.json` file is designed to store sensitive authentication credentials required for accessing the Databricks workspace. These credentials include `pat_token`, `client_secret`, `private_key_file` (path), and potentially `client_id` depending on the authentication method.
    2. The application, as designed, reads these credentials directly from the `params.json` file in plaintext when it is executed.
    3. If the file system where `params.json` is stored has insecure permissions (e.g., world-readable, accessible to unauthorized users or processes), an attacker with read access to the file system can directly read the `params.json` file.
    4. By reading `params.json`, the attacker can obtain the plaintext credentials such as `pat_token` or `client_secret`.
    5. The attacker can then use these exfiltrated credentials to authenticate directly to the legitimate Databricks workspace and perform unauthorized actions, bypassing the intended security controls of the application environment.
* Impact:
    - **Complete Compromise of Databricks Access:** Successful exfiltration of credentials like `pat_token` or `client_secret` grants the attacker full control over the Databricks workspace associated with those credentials, limited only by the permissions of the authenticated identity.
    - **Data Breach:** Attackers can access sensitive data stored in the Databricks workspace, potentially leading to data breaches and compliance violations.
    - **Malicious Operations:** Attackers can perform any operations within the Databricks workspace that the compromised credentials allow, including creating/deleting jobs, modifying data, accessing secrets, and potentially escalating privileges if the compromised identity has sufficient permissions.
* Vulnerability Rank: High
* Currently Implemented Mitigations:
    - None in the code. The application directly reads and uses credentials from `params.json` without any security measures for credential handling or storage within the application itself. The README file provides documentation on how to use different authentication methods and parameter file examples but does not include specific security warnings or mitigations against insecure storage of credentials in `params.json` beyond implicitly suggesting securing the file.
* Missing Mitigations:
    - **Secure Credential Storage:** The application should not rely on storing sensitive credentials in plaintext JSON files. Implement secure credential management practices:
        - **Environment Variables:** Encourage or enforce the use of environment variables to pass sensitive credentials to the application at runtime, avoiding storage in files.
        - **Secure Key Vaults/Credential Managers:** Integrate with secure key vault services (like Azure Key Vault, HashiCorp Vault, or cloud provider secret managers) to store and retrieve credentials securely.
        - **Operating System Credential Stores:** Utilize operating system-level credential storage mechanisms where appropriate.
    - **Warning/Error on Insecure Storage:** At the very least, the application should include a prominent warning message, either during startup or in the documentation (beyond the README), explicitly stating the security risks of storing credentials in `params.json` and recommending secure alternatives.
    - **File Permission Hardening Guidance:** Enhance documentation to include explicit instructions on setting restrictive file permissions for `params.json` (e.g., read/write only for the user running the application) to minimize the risk of unauthorized access.
* Preconditions:
    - The attacker must have read access to the file system where the `params.json` file is stored. This access could be due to insecure file permissions, vulnerabilities in the system, or insider threats.
* Source Code Analysis:
    1. **File: `/code/job.py`**:
        ```python
        parser = argparse.ArgumentParser(description='DSC job management for Databricks')
        parser.add_argument('--params', type=str, help='your Databricks and Azure parameter file', default='params.json')
        args = parser.parse_args()

        configuration = json.load(open(args.params))
        auth_token = auth.get_auth_token(configuration)
        ```
        - The `job.py` script loads the entire `params.json` file content into the `configuration` variable.
        - It then passes this `configuration` dictionary directly to the `auth.get_auth_token()` function.
    2. **File: `/code/auth.py`**:
        ```python
        def get_auth_token(paramFile):
            result = None
            auth = paramFile["authority_type"]

            if auth == "msi":
                result = json.loads(requests.get(paramFile["authority"] + "&resource=" + paramFile["resource"] + "&client_id=" + paramFile["client_id"], headers={"Metadata": "true"}).text)

            elif auth == "spn-cert" or auth == "spn-key":
                app = msal.ConfidentialClientApplication(
                    paramFile["client_id"], authority=paramFile["authority"],
                    client_credential=  {"thumbprint": paramFile["thumbprint"], "private_key": open(paramFile['private_key_file']).read()} if auth == "spn-cert" else paramFile["client_secret"]
                )
                result = app.acquire_token_for_client(scopes=[paramFile["resource"] + "/.default"])

            elif auth == "pat":
                result = {'access_token': paramFile["pat_token"]}
            ```
        - The `auth.py` script's `get_auth_token()` function directly accesses various credential fields from the `paramFile` dictionary (which is derived from `params.json`):
            - `paramFile["pat_token"]` for Personal Access Token authentication.
            - `paramFile["client_secret"]` for Service Principal with Key authentication.
            - `paramFile['private_key_file']` (path to private key file) for Service Principal with Certificate authentication (while not the key itself in `params.json`, the path is still sensitive config).
        - These sensitive values are directly used for authentication, demonstrating that the application relies on plaintext storage of credentials in `params.json`.

* Security Test Case:
    1. **Setup:**
        - Create a `params.json` file containing valid credentials for any of the supported authentication methods (e.g., use `pat` and include a valid `pat_token`).
        - Set insecure file permissions on `params.json` to make it world-readable (e.g., `chmod 644 params.json` or `chmod a+r params.json` on Linux/macOS, or remove restrictive ACLs on Windows).
    2. **Simulate Attacker Access:**
        - As an attacker who has gained read access to the file system (e.g., through a compromised account or system vulnerability, or simply by being a user with access if permissions are too broad), read the contents of the `params.json` file. This can be done using standard file reading commands like `cat params.json` or `type params.json`.
    3. **Verify Credential Exposure:**
        - Examine the output of reading `params.json`. Confirm that the sensitive credentials you configured (e.g., `pat_token`, `client_secret`) are clearly visible in plaintext within the JSON file.
    4. **Attempt Unauthorized Access (using exfiltrated PAT as example):**
        - Extract the `pat_token` value from the `params.json` file.
        - Use a tool like `curl` or the Databricks CLI to attempt to authenticate to the Databricks workspace using the exfiltrated `pat_token`. For example:
        ```bash
        curl -X GET -H 'Authorization: Bearer <EXFILTRATED_PAT_TOKEN>' https://<your-databricks-uri>/api/2.0/jobs/list
        ```
        - Replace `<EXFILTRATED_PAT_TOKEN>` with the actual token from `params.json` and `<your-databricks-uri>` with your Databricks workspace URI.
    5. **Verification of Unauthorized Access:**
        - If the `curl` command (or similar) successfully returns a response from the Databricks API (e.g., a JSON list of jobs), it confirms that the exfiltrated credentials are valid and can be used to gain unauthorized access to the Databricks workspace. This demonstrates the vulnerability of credential exposure due to insecure storage in `params.json`.