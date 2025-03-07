### Vulnerability List

* Vulnerability Name: Insecure Storage of Credentials File without User Warning

* Description:
    1. The `gtasks-md auth` command instructs users to provide a `credentials.json` file, which contains sensitive OAuth 2.0 client secrets for accessing Google APIs.
    2. Upon execution of `gtasks-md auth`, the application saves a copy of this `credentials.json` file to the user's data directory at `$XDG_DATA_HOME/gtasks-md/{user}/credentials.json`.
    3. The application does not provide any explicit warning to the user about the sensitive nature of the `credentials.json` file after it is saved.
    4. If an attacker gains unauthorized access to the user's local file system, they can locate and steal the `credentials.json` file.
    5. With the stolen `credentials.json` file, the attacker can impersonate the legitimate user and gain unauthorized access to their Google Tasks, potentially leading to data manipulation or information disclosure.

* Impact:
    * Unauthorized access to the victim's Google Tasks.
    * Ability for the attacker to view, modify, create, or delete tasks and task lists belonging to the victim.
    * Potential exposure of sensitive information stored within Google Tasks.
    * Risk of manipulation of the victim's task management system, leading to disruption or data loss.

* Vulnerability Rank: Medium

* Currently Implemented Mitigations:
    * None. The application saves the `credentials.json` file to the `$XDG_DATA_HOME` directory, which is intended for user-specific data, but no specific security measures or user warnings are implemented regarding the sensitivity of this file.

* Missing Mitigations:
    * **User Warning during `auth` command:** Implement a clear warning message displayed on the command line immediately after the `credentials.json` file is saved. This warning should emphasize the sensitive nature of the file and instruct the user to protect it from unauthorized access, similar to warnings about private keys.
    * **Documentation Update:** Update the documentation (README.md) to include a prominent security note about the `credentials.json` file. This note should explain that this file contains sensitive credentials and must be protected as such. It should advise users on best practices for securing local files and directories.

* Preconditions:
    * The user must have successfully executed the `gtasks-md auth` command, providing a valid `credentials.json` file.
    * An attacker must gain unauthorized read access to the user's local file system where `$XDG_DATA_HOME` directory is located. This could be achieved through various means, such as malware, physical access, or exploitation of other vulnerabilities on the user's system.

* Source Code Analysis:
    1. **File: /code/app/googleapi.py, Function: `save_credentials`**:
       ```python
       def save_credentials(self, credentials: str):
           """Save credentials to selected user config directory."""
           config_dir = f"{xdg_data_home()}/gtasks-md/{self.user}"

           with open(f"{config_dir}/{CREDENTIALS_FILE}", "w+") as dest_file:
               dest_file.write(credentials)
       ```
       This function is responsible for saving the `credentials.json` file. It directly writes the provided credentials string to a file within the user's data directory. There is no security check, warning, or access control implemented in this function.

    2. **File: /code/app/__main__.py, Function: `auth`**:
       ```python
       def auth(service: GoogleApiService, file: str):
           with open(file, "r") as src_file:
               service.save_credentials(src_file.read())
       ```
       The `auth` function calls `save_credentials` after reading the credentials from the user-provided file. There is no user interaction to warn about the security implications at this point.

    3. **File: /code/README.md, Section: `auth`**:
       The documentation guides the user on how to obtain the `credentials.json` file from the Google Cloud Platform and how to use it with the `gtasks-md auth` command. However, it lacks any security warnings about protecting the `credentials.json` file after it's saved by the application.

* Security Test Case:
    1. **Setup:**
        a. Install `gtasks-md` on a test machine.
        b. Follow the instructions in `README.md` to create a `credentials.json` file for a test Google account.
        c. Execute the `gtasks-md auth ./credentials.json` command, providing the created `credentials.json` file. Ensure the command completes successfully.
    2. **Simulate Attacker Access:**
        a. On the test machine, navigate to the user's data directory: `$XDG_DATA_HOME/gtasks-md/default/` (or the user specified during `auth`).
        b. Locate the `credentials.json` file within this directory.
        c. Copy the `credentials.json` file to a separate attacker-controlled machine.
    3. **Attempt Unauthorized Access:**
        a. On the attacker machine, install `gtasks-md`.
        b. Execute the `gtasks-md auth ./credentials.json` command, providing the copied `credentials.json` file.
        c. Now, run `gtasks-md view`.
        d. **Verification:** Observe that the `gtasks-md view` command successfully retrieves and displays the task lists from the original user's Google account, demonstrating unauthorized access using the stolen `credentials.json` file.

This test case confirms that an attacker who gains access to the `credentials.json` file can successfully impersonate the original user and access their Google Tasks.