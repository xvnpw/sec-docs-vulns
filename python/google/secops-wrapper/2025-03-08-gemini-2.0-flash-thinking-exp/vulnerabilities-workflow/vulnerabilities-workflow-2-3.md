### Vulnerability List

- **Vulnerability Name:** Service Account Credential Exposure through User Mishandling

- **Description:**
    Users can initialize the SDK using service account credentials by providing a path to a service account JSON file or by directly embedding the service account information as a dictionary within their code. If a user hardcodes the service account file path or the service account information directly into their application code, or unintentionally includes the service account JSON file in a publicly accessible location (e.g., a public code repository), an attacker could potentially obtain these sensitive credentials.  

    Step-by-step trigger:
    1. A user develops an application using the SecOps SDK.
    2. The user chooses to authenticate using a service account.
    3. The user initializes the `SecOpsClient` in their Python code, providing the service account credentials in one of the following insecure ways:
        - Hardcodes the path to the service account JSON file directly in the `service_account_path` parameter.
        - Embeds the entire service account JSON dictionary directly into the `service_account_info` parameter in their code.
    4. The user then commits this code to a public version control repository (e.g., GitHub), or otherwise makes the code or the service account JSON file publicly accessible.
    5. An attacker discovers this publicly exposed code or file.
    6. The attacker extracts the service account credentials (either the file path, the JSON dictionary, or the JSON file itself).
    7. Using these stolen credentials, the attacker can now authenticate to the Google Chronicle API as if they were the legitimate service account.
    8. The attacker gains unauthorized access to the Google Chronicle instance associated with the compromised service account.

- **Impact:**
    Unauthorized access to the user's Google Chronicle instance. The impact depends on the permissions granted to the compromised service account. A successful attacker could:
    - Read sensitive security data stored in Chronicle.
    - Modify Chronicle configurations.
    - Perform actions within the Chronicle environment, such as running queries, managing cases, and exporting data.
    - Potentially escalate privileges within the associated Google Cloud Project if the service account has broader permissions.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    None. The SDK itself does not implement any mitigations against user mishandling of credentials. It relies on the user to follow security best practices for credential management.

- **Missing Mitigations:**
    - **Enhanced Documentation:** The documentation should strongly emphasize the risks of hardcoding or publicly exposing service account credentials. It should include a dedicated security best practices section detailing secure credential management, specifically recommending:
        - **Avoiding hardcoding credentials:** Emphasize using environment variables or secure configuration management systems to store and retrieve credentials.
        - **Secure storage of service account JSON files:** Advise users to store service account JSON files in secure locations, outside of public code repositories and web-accessible directories.
        - **Using Application Default Credentials (ADC) when possible:** Promote ADC as the recommended and often more secure method for authentication, as it reduces the need to explicitly manage service account keys.
        - **Regular credential rotation:** Recommend regular rotation of service account keys to limit the window of opportunity if credentials are compromised.
    - **Code Example Review:**  The code examples in the `README.md` (and other documentation) that demonstrate service account authentication should be reviewed and potentially modified to:
        -  Prioritize and prominently feature ADC as the recommended method.
        -  If service account examples are necessary, demonstrate loading the `service_account_path` from an environment variable instead of a hardcoded string.
        -  Include a clear warning message in the service account authentication examples about the security risks of exposing credentials.

- **Preconditions:**
    - A user chooses to authenticate the SecOps SDK using service account credentials.
    - The user mishandles these credentials by:
        - Hardcoding the service account JSON file path or the `service_account_info` dictionary directly into their application code.
        - Embedding the service account JSON file in a publicly accessible location, such as a public code repository.
        - Unintentionally exposing the environment variable `GOOGLE_APPLICATION_CREDENTIALS` if used in examples and instructions.
    - The user's code or the service account JSON file becomes publicly accessible.
    - An attacker discovers the exposed credentials.

- **Source Code Analysis:**
    1. **`src/secops/auth.py`**: The `SecOpsAuth` class in `src/secops/auth.py` is responsible for handling authentication.
    2. **`_get_credentials` method**: The `_get_credentials` method within `SecOpsAuth` is responsible for loading credentials. It checks for credentials in the following order:
        ```python
        def _get_credentials(
            self,
            credentials: Optional[Credentials],
            service_account_path: Optional[str],
            service_account_info: Optional[Dict[str, Any]]
        ) -> Credentials:
            """Get credentials from various sources."""
            try:
                if credentials:
                    return credentials.with_scopes(self.scopes)

                if service_account_info:
                    return service_account.Credentials.from_service_account_info(
                        service_account_info,
                        scopes=self.scopes
                    )

                if service_account_path:
                    return service_account.Credentials.from_service_account_file(
                        service_account_path,
                        scopes=self.scopes
                    )

                # Try to get default credentials
                credentials, project = google.auth.default(scopes=self.scopes)
                return credentials
            except Exception as e:
                raise AuthenticationError(f"Failed to get credentials: {str(e)}")
        ```
    3. **Vulnerable Credential Loading**: The code directly uses `service_account.Credentials.from_service_account_info(service_account_info, scopes=self.scopes)` and `service_account.Credentials.from_service_account_file(service_account_path, scopes=self.scopes)` when `service_account_info` or `service_account_path` are provided. This functionality is necessary for the SDK to work as designed, but it inherently relies on the user to securely provide and manage these inputs. There are no built-in checks within these methods or the SDK to prevent a user from hardcoding these values directly into their source code or from accidentally exposing the service account JSON file.
    4. **`README.md` Examples**: The `README.md` provides examples that demonstrate how to use `service_account_path` and `service_account_info`.  For example:
        ```python
        client = SecOpsClient(service_account_path="/path/to/service-account.json")
        ```
        and
        ```python
        service_account_info = { ... }
        client = SecOpsClient(service_account_info=service_account_info)
        ```
        These examples, while functional, could inadvertently encourage insecure practices if users directly copy and paste them without understanding the security implications of hardcoding credential paths or embedding credential data.

- **Security Test Case:**
    1. **Setup:**
        - Create a new public GitHub repository.
        - Create a dummy service account JSON file (you can use a real one for testing in a non-production environment, but ensure it has minimal permissions to mitigate risk during testing, or use a mocked service account if possible).
        - Create a Python script named `test_secops_client.py` with the following content, replacing `"YOUR_CUSTOMER_ID"`, `"YOUR_PROJECT_ID"` and `"path/to/your-service-account.json"` with placeholder values or your test values and the actual content of your dummy service account JSON file into `service_account_info`:

        ```python
        from secops import SecOpsClient

        # INSECURE: Hardcoded service account file path
        # client = SecOpsClient(service_account_path="path/to/your-service-account.json")

        # INSECURE: Hardcoded service account info dictionary
        service_account_info = {
            "type": "service_account",
            "project_id": "your-project-id",
            "private_key_id": "your-private-key-id",
            "private_key": "-----BEGIN PRIVATE KEY-----\\n...",
            "client_email": "your-service-account@project.iam.gserviceaccount.com",
            "client_id": "your-client-id",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/..."
        }
        client = SecOpsClient(service_account_info=service_account_info)


        chronicle = client.chronicle(
            customer_id="YOUR_CUSTOMER_ID",
            project_id="YOUR_PROJECT_ID",
            region="us"
        )

        try:
            validation = chronicle.validate_query('target.ip != ""')
            print("Query validation successful:", validation)
        except Exception as e:
            print("Error accessing Chronicle API:", e)
        ```
        - Commit and push `test_secops_client.py` and (optionally, if testing file path exposure) the dummy service account JSON file to your public GitHub repository.

    2. **Attacker Action (Credential Discovery):**
        - As an attacker, use GitHub's code search (or a similar code search engine) to look for publicly exposed service account credentials. Search for keywords and code patterns like:
            - `"SecOpsClient(service_account_path="`
            - `"SecOpsClient(service_account_info = {"`
            - `"type": "service_account"` and `"private_key"`
        - Look for repositories containing files resembling `test_secops_client.py` or similar SDK usage patterns.
        - If the attacker finds your repository, examine the `test_secops_client.py` file. The attacker will be able to extract the hardcoded `service_account_info` dictionary or the `service_account_path`.

    3. **Attacker Action (Unauthorized Access):**
        - The attacker copies the extracted `service_account_info` dictionary or downloads the exposed service account JSON file (if applicable).
        - The attacker creates their own Python script (e.g., `attacker_script.py`) and initializes the `SecOpsClient` using the stolen credentials:

        ```python
        from secops import SecOpsClient

        # Using stolen service_account_info
        stolen_service_account_info = { # Paste the stolen dictionary here }
        attacker_client = SecOpsClient(service_account_info=stolen_service_account_info)

        # OR, if service_account_path was exposed and file downloaded/accessible
        # attacker_client = SecOpsClient(service_account_path="path/to/downloaded-service-account.json")


        attacker_chronicle = attacker_client.chronicle(
            customer_id="TARGET_CUSTOMER_ID", # Replace with the customer ID from the exposed code if available, or try common IDs
            project_id="TARGET_PROJECT_ID",   # Replace with the project ID from the exposed code if available
            region="us"
        )

        try:
            validation = attacker_chronicle.validate_query('target.ip != ""')
            print("Attacker: Successfully validated query using stolen credentials:", validation)
            # Further API calls can be made to access Chronicle data.
        except Exception as e:
            print("Attacker: Failed to access Chronicle API using stolen credentials:", e)
        ```
        - Run `attacker_script.py`. If the service account credentials are valid and the attacker correctly uses the customer ID and project ID (which might also be exposed in the vulnerable code), the attacker will successfully authenticate and access the Chronicle API, demonstrating unauthorized access.

    4. **Expected Result:** The security test case should demonstrate that an attacker can successfully extract service account credentials from publicly exposed code and use these credentials to gain unauthorized access to the Google Chronicle API via the SecOps SDK. This proves the vulnerability of user credential mishandling.