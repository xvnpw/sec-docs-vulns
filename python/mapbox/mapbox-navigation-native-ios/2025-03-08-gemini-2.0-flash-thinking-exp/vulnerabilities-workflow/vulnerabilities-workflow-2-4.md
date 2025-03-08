### Vulnerability List

- **Vulnerability Name:** Insecure Storage of Mapbox API Token in `.netrc`
- **Description:** The project documentation in `README.md` instructs users to store their Mapbox API token with `DOWNLOAD:READ` scope in a `.netrc` file. This file is typically located in the user's home directory (`~/.netrc`) and is intended to store login credentials for various network services. However, storing sensitive API tokens in plain text in `.netrc` is insecure. If an attacker gains unauthorized access to the user's file system, they can read the `.netrc` file and extract the Mapbox API token. This token can then be used to access Mapbox services under the victim's account, potentially leading to unauthorized usage, data breaches, or financial implications.
- **Impact:**
    - Unauthorized access to Mapbox services.
    - Potential financial impact due to unauthorized usage of Mapbox services linked to the compromised token.
    - Potential data breaches if the compromised token grants access to sensitive data within Mapbox services.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - None. The project documentation explicitly suggests this insecure method.
- **Missing Mitigations:**
    - **Remove the recommendation to use `.netrc`:** The documentation should be updated to strongly discourage the use of `.netrc` for storing API tokens.
    - **Suggest secure alternatives for token storage:** The documentation should recommend more secure methods for handling API tokens, such as:
        - Environment variables.
        - Dedicated secret management tools (e.g., keychain, password managers).
        - Securely configured configuration files with restricted file system permissions.
    - **Add a security warning in the documentation:** Include a clear and prominent warning in the `README.md` about the security risks associated with storing API tokens in `.netrc` and emphasize the importance of using secure token management practices.
- **Preconditions:**
    - The user follows the instructions in `README.md` and stores their Mapbox API token in a `.netrc` file.
    - An attacker gains unauthorized read access to the user's file system where the `.netrc` file is located (e.g., through malware, phishing, or insider threat).
- **Source Code Analysis:**
    - **File: `/code/README.md`**
        ```markdown
        ##### SPM, CocoaPods and Carthage
        Insert or append the following to `~/.netrc`

        ```bash
        machine api.mapbox.com
          login mapbox
          password <TOKEN WITH DOWNLOAD:READ SCOPE>
        ```
        - The `README.md` file contains explicit instructions to store the Mapbox API token in the `.netrc` file.
        - This instruction directly leads to the vulnerability by encouraging insecure storage of sensitive credentials.
        - There is no code within the project that mitigates this vulnerability, as it is a documentation issue. The scripts and test files do not interact with user's `.netrc` directly in a way that would expose or mitigate this vulnerability. The scripts like `test_spm.sh` and `release.sh` use `--netrc` option with `curl` command, which implicitly reads credentials from `.netrc` if configured, but this is for the project's internal tooling and not directly related to the user's API token security in their applications using this library.
- **Security Test Case:**
    1. **Setup:**
        - Create a `.netrc` file in your home directory (`~/.netrc`) if it doesn't exist.
        - Add the following lines to your `.netrc` file, replacing `<TOKEN WITH DOWNLOAD:READ SCOPE>` with a valid Mapbox API token that has the `DOWNLOAD:READ` scope:
          ```
          machine api.mapbox.com
            login mapbox
            password <YOUR_MAPBOX_DOWNLOAD_READ_TOKEN>
          ```
        - Set the file permissions of `.netrc` to be readable by the owner and group, but not by others (e.g., `chmod 640 ~/.netrc` or `chmod 600 ~/.netrc`). Note that even with restricted permissions, local privilege escalation or other attack vectors could still expose the file content.
    2. **Exploit:**
        - As an attacker (or simulating an attacker with local access to the system), attempt to read the content of the `.netrc` file. You can use the following command in the terminal:
          ```bash
          cat ~/.netrc
          ```
        - Observe the output. The Mapbox API token should be visible in plain text within the file content.
    3. **Verification:**
        - Copy the extracted Mapbox API token.
        - Use `curl` to make a request to the Mapbox Downloads API, attempting to download a resource that requires authentication with the `DOWNLOAD:READ` scope. Include the extracted token in the request. For example:
          ```bash
          curl -v -H "Authorization: Bearer <YOUR_EXTRACTED_MAPBOX_TOKEN>" "https://api.mapbox.com/downloads/v2/mobile-navigation-native/releases/ios/packages/206.1.0/MapboxNavigationNative.xcframework.zip"
          ```
        - If the download is successful (HTTP status code 200), it verifies that the extracted token is valid and can be used to access Mapbox services. This confirms the vulnerability: an attacker who gains access to the `.netrc` file can steal the Mapbox API token and use it for unauthorized access.