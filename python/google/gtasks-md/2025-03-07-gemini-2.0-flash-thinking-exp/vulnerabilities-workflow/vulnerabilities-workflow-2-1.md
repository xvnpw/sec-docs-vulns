### Vulnerability List

* Vulnerability Name: Insecure Storage of OAuth Client Secrets

* Description:
    1. The `gtasks-md auth` command instructs users to download their OAuth Client ID credentials as a `credentials.json` file from the Google Cloud Console.
    2. The application then saves this `credentials.json` file to the user's configuration directory at `$XDG_DATA_HOME/gtasks-md/{user}/credentials.json`.
    3. The `$XDG_DATA_HOME` directory is typically located in the user's home directory (e.g., `~/.local/share` on Linux).
    4. If the user's system is compromised or if file permissions are misconfigured, an attacker could potentially gain unauthorized read access to this `credentials.json` file.
    5. Obtaining `credentials.json` allows an attacker to impersonate the legitimate user and access their Google Tasks through the Google Tasks API.

* Impact:
    - **Unauthorized Access to Google Tasks:** An attacker who obtains the `credentials.json` file can gain full control over the victim's Google Tasks. This includes viewing, creating, modifying, and deleting tasks and task lists.
    - **Privacy Violation:**  An attacker can access and monitor the victim's tasks, potentially revealing sensitive personal or work-related information stored in Google Tasks.
    - **Data Manipulation:** An attacker can maliciously modify or delete tasks, disrupting the victim's task management and potentially causing data loss.

* Vulnerability Rank: Medium

* Currently Implemented Mitigations:
    - None. The application directly saves the `credentials.json` file to the file system without any additional security measures.

* Missing Mitigations:
    - **Secure Storage Mechanisms:** Implement secure storage for `credentials.json`, such as using a system-specific credential manager (e.g., Credential Store on macOS, Credential Manager on Windows, or Secret Service API on Linux) or encrypting the file at rest.
    - **Permissions Hardening:**  Upon saving `credentials.json`, the application should set restrictive file permissions (e.g., `0600` on Unix-like systems) to ensure that only the user has read and write access. The directory `$XDG_DATA_HOME/gtasks-md/{user}` should also have appropriate permissions.
    - **Security Warning in Documentation:**  The documentation should include a prominent warning about the sensitive nature of the `credentials.json` file and advise users to protect it carefully and avoid sharing it. It should emphasize that unauthorized access to this file can lead to account compromise.

* Preconditions:
    - The user must have run the `gtasks-md auth` command and successfully stored the `credentials.json` file in their `$XDG_DATA_HOME` directory.
    - An attacker must gain unauthorized access to the user's system or be able to socially engineer the user into providing the `credentials.json` file.

* Source Code Analysis:
    1. **`app/googleapi.py`:**
        - The `CREDENTIALS_FILE = "credentials.json"` line defines the filename for the credentials file.
        - The `save_credentials(self, credentials: str)` method in the `GoogleApiService` class is responsible for saving the credentials.
        ```python
        def save_credentials(self, credentials: str):
            """Save credentials to selected user config directory."""
            config_dir = f"{xdg_data_home()}/gtasks-md/{self.user}"

            with open(f"{config_dir}/{CREDENTIALS_FILE}", "w+") as dest_file:
                dest_file.write(credentials)
        ```
        - This code directly writes the provided `credentials` string to a file named `credentials.json` within the user's data directory (`$XDG_DATA_HOME/gtasks-md/{self.user}`). There are no security checks or encryption applied before saving the file.
    2. **`app/__main__.py`:**
        - The `auth(service: GoogleApiService, file: str)` function in `__main__.py` handles the `auth` subcommand.
        ```python
        def auth(service: GoogleApiService, file: str):
            with open(file, "r") as src_file:
                service.save_credentials(src_file.read())
        ```
        - This function reads the `credentials.json` file provided by the user as a command-line argument (`file`) and passes its content to the `service.save_credentials()` method for storage.

* Security Test Case:
    1. **Setup:**
        - Ensure `gtasks-md` is installed and configured for a test user.
        - Run `gtasks-md auth ./path/to/your/credentials.json` (replace `./path/to/your/credentials.json` with a valid `credentials.json` file).
    2. **Locate Credentials File:**
        - Determine the `$XDG_DATA_HOME` directory for the test user (usually `~/.local/share`).
        - Navigate to `$XDG_DATA_HOME/gtasks-md/default/` and verify that `credentials.json` exists.
    3. **Simulate Attacker Access:**
        - As a different user or with elevated privileges (simulating an attacker with local access), attempt to read the contents of `$XDG_DATA_HOME/gtasks-md/default/credentials.json`.
        - If file permissions are default and allow read access to other users or groups, you will be able to read the file.
    4. **Exploit (Conceptual):**
        - Copy the obtained `credentials.json` file to a separate location.
        - Using a Google API client or a script, authenticate with the Google Tasks API using the copied `credentials.json` file.
        - Demonstrate the ability to access and manipulate the Google Tasks of the original test user. (Note: This step might require writing a separate script to interact with the Google Tasks API using the stolen credentials, as the `gtasks-md` tool itself is designed for authorized user interaction).
    5. **Expected Result:**
        - The attacker should be able to read the `credentials.json` file if permissions are not restrictive.
        - With the stolen `credentials.json`, the attacker should be able to authenticate with the Google Tasks API and gain unauthorized access to the victim's Google Tasks, proving the vulnerability.