### Vulnerabilities Found

- **Vulnerability Name:** Insecure Storage of Mapbox `DOWNLOAD:READ` Token

    - **Description:**
        The project's `README.md` file instructs developers to store their Mapbox API token with `DOWNLOAD:READ` scope in the `~/.netrc` file to facilitate downloads via tools like `curl` and `carthage`. This `~/.netrc` file is typically located in the user's home directory (`~`).  If a developer, following these instructions, mistakenly includes or commits their entire home directory, or specifically the `~/.netrc` file, to a publicly accessible repository (e.g., on GitHub, GitLab, or Bitbucket), the Mapbox API token becomes publicly exposed. An attacker can then discover this exposed token by browsing the public repository. Alternatively, if an attacker gains unauthorized access to a developer's local machine (e.g., through malware, social engineering, or physical access), they could potentially read the `~/.netrc` file and extract the Mapbox API token. Once obtained, the attacker can use this token to authenticate with Mapbox services and access resources that are authorized under the `DOWNLOAD:READ` scope associated with the compromised token. This could potentially include downloading private datasets, accessing internal resources, or performing other actions allowed by the `DOWNLOAD:READ` permissions, depending on the specifics of the Mapbox account and token configuration.

    - **Impact:**
        Unauthorized access to Mapbox resources associated with the compromised token. With a `DOWNLOAD:READ` token, an attacker could potentially download private datasets, access internal resources meant only for the token owner, and possibly gain further insights into the developer's Mapbox account and related projects.  Potential misuse of Mapbox services associated with the compromised token can lead to unexpected usage charges, disruption of services, and data breaches if the token grants access to sensitive data within the Mapbox account. Reputational damage to the developer or organization associated with the compromised Mapbox account is also a potential impact.

    - **Vulnerability Rank:** High

    - **Currently implemented mitigations:**
        No mitigations are implemented within the project's code or documentation to prevent developers from committing their `~/.netrc` file or protect it from local access. The `README.md` provides instructions that, if followed without caution, can lead to this vulnerability. The project documentation explicitly instructs users to store the API token in the `~/.netrc` file. There are no warnings or alternative secure methods suggested within the provided files.

    - **Missing mitigations:**
        - **Strong Warning in README:** The `README.md` should include a clear and prominent warning against storing API tokens in `~/.netrc` and against committing the `.netrc` file to public version control systems. This warning should emphasize the risk of exposing the Mapbox API token and the potential consequences of unauthorized access. The documentation should be updated to strongly discourage the use of `.netrc` for storing API tokens.
        - **Alternative Secure Token Storage Guidance:** The documentation should suggest and promote more secure alternatives for storing and using API tokens, such as:
            - **Environment Variables:** Recommending the use of environment variables to store the token, which are less likely to be accidentally committed to repositories.
            - **Dedicated Secrets Management Tools:** Mentioning the use of dedicated secrets management tools or services (e.g., keychain, password managers) for more robust and secure handling of API keys, especially in team environments.
            - **Tool-Specific Configuration:** If possible, guide users on how to configure tools like `carthage` to use more secure methods for authentication instead of relying solely on `.netrc`.
            - **Securely configured configuration files with restricted file system permissions.**
        - **Token Scope Limitation Guidance:** Developers should be advised to create Mapbox API tokens with the minimal necessary scope (in this case, `DOWNLOAD:READ`) to limit the potential damage if the token is compromised. Broader scope tokens should be strongly discouraged for download purposes.
        - **Token Revocation Instructions:** Clear instructions on how to revoke and regenerate a Mapbox API token should be provided in the documentation, in case a token is suspected to be compromised.
        - **Remove the recommendation to use `.netrc`:** The documentation should be updated to strongly discourage the use of `.netrc` for storing API tokens.

    - **Preconditions:**
        1. Developer follows the `README` instructions to create a Mapbox token with `DOWNLOAD:READ` scope.
        2. Developer follows the `README` instructions to configure `~/.netrc` with the created token.
        3. Developer uses Git for version control and initializes a repository, *or* an attacker gains local access to the developer's machine.
        4. Developer mistakenly adds the `~/.netrc` file (or the user's home directory containing it) to the Git repository's tracked files and pushes to a public repository, *or* attacker gains read access to the developer's file system where the `.netrc` file is located (e.g., through malware, phishing, or insider threat).

    - **Source code analysis:**
        1. **README.md Instruction:** The vulnerability stems from the instruction in the `README.md` file:
        ```markdown
        Insert or append the following to `~/.netrc`

        ```bash
        machine api.mapbox.com
          login mapbox
          password <TOKEN WITH DOWNLOAD:READ SCOPE>
        ```
        This instruction guides developers to store their `DOWNLOAD:READ` token in a plain text file (`~/.netrc`) in their home directory. This instruction directly encourages developers to store their Mapbox API token in plain text within the `~/.netrc` file, which is a known insecure practice for sensitive credentials.
        2. **Test Scripts Usage of `--netrc`:** The test scripts, such as `test_carthage.sh` and `test_spm.sh`, utilize tools like `curl` and `carthage` with the `--netrc` option:
        ```bash
        carthage update --platform iOS --use-netrc --use-xcframeworks
        curl -s --retry 3 --netrc ${URL} --output ${XCFRAMEWORK_ZIP}
        ```
        The `--netrc` flag instructs these tools to read authentication credentials from the `~/.netrc` file. This mechanism is convenient for automated processes but inherently insecure if the `.netrc` file is not properly protected.
        3. **No Mitigation in Project Code:** The provided project files do not contain any code or scripts that attempt to mitigate the risk of insecure token storage. The vulnerability is purely due to the documented instructions and the reliance on `.netrc` for authentication in scripts.
        4. **File: `/code/README.md`**: The `README.md` file contains explicit instructions to store the Mapbox API token in the `.netrc` file. This instruction directly leads to the vulnerability by encouraging insecure storage of sensitive credentials. There is no code within the project that mitigates this vulnerability, as it is a documentation issue. The scripts and test files do not interact with user's `.netrc` directly in a way that would expose or mitigate this vulnerability. The scripts like `test_spm.sh` and `release.sh` use `--netrc` option with `curl` command, which implicitly reads credentials from `.netrc` if configured, but this is for the project's internal tooling and not directly related to the user's API token security in their applications using this library.
        5. **Visualization (Accidental Commit Scenario):**
        ```
        Developer -> README.md -> Instruction to modify ~/.netrc ----> Insecure Token Storage in ~/.netrc
            ^                                                                         |
            |                                                                         | Mistakenly Commit
            ---------------------------------------------------------------------------
                                                                         |
                                                                         v
        Public Repository <---- Attacker Accesses ---- ~/.netrc (Exposed Token)
            |
            v
        Attacker Uses Token ----> Mapbox API ----> Unauthorized Access to Resources
        ```
        6. **Visualization (Local Machine Access Scenario):**
        ```
        Developer's Machine --> Stores API Token in ~/.netrc (as instructed by README.md)
            ^
            | Potential Attack Vector: Machine Compromise (Malware, Physical Access)
            |
        Attacker --> Gains Access to ~/.netrc --> Extracts API Token
            |
        Attacker --> Uses API Token --> Unauthorized Access to Mapbox Account
        ```

    - **Security test case:**
        1. **Security Test Case 1 (Accidental Commit):**
            a. **Setup:**
                i. Create a new Mapbox account (or use an existing test account).
                ii. Generate a new Mapbox API token with the `DOWNLOAD:READ` scope enabled.
                iii. On your local development machine, follow the `README.md` instructions to configure `~/.netrc` to store this newly generated Mapbox token. Ensure the `~/.netrc` file is created in your home directory and contains the machine, login, and password entries as specified in the `README`.
                iv. Create a new, empty Git repository on a public platform like GitHub.
                v. Initialize a local Git repository in a new directory on your machine: `git init`.
            b. **Simulate Accidental Commit:**
                i. In your local Git repository, add the `~/.netrc` file to the staging area: `git add ~/.netrc`.  *(Note: In a real scenario, a developer might accidentally add their entire home directory or mistakenly include `~/.netrc` in a broader add command)*.
                ii. Commit the `~/.netrc` file to your local repository: `git commit -m "Accidentally committed .netrc file"`.
                iii. Connect your local repository to the public GitHub repository you created and push the commit: `git remote add origin <your-public-repo-url>`, `git push -u origin main`.
            c. **Attacker Exploitation:**
                i. As an attacker, access the public GitHub repository you created in step 1.b.
                ii. Browse the repository's file list and locate the `.netrc` file.
                iii. View the contents of the `.netrc` file. You should be able to see the Mapbox API token in plain text.
                iv. Copy the Mapbox API token.
                v. Use `curl` to attempt to download a resource from Mapbox that requires `DOWNLOAD:READ` scope. For example, try to access a tileset or other downloadable resource. Replace `<YOUR_EXPOSED_TOKEN>` with the token you extracted and `<RESOURCE_URL>` with a valid Mapbox resource URL that requires `DOWNLOAD:READ` permissions.
                ```bash
                curl --netrc -v -o test_download.zip "https://api.mapbox.com/downloads/v2/mobile-navigation-native/releases/ios/packages/206.1.0/MapboxNavigationNative.xcframework.zip"
                ```
            d. **Verification:**
                i. If the `curl` command in step 1.c.v successfully downloads the resource without prompting for authentication or returning an authorization error, it confirms that the exposed token is valid and grants `DOWNLOAD:READ` access.
                ii. This successful download demonstrates that an attacker who gains access to the publicly committed `.netrc` file can indeed use the exposed Mapbox API token to gain unauthorized access to Mapbox resources, validating the vulnerability.

        2. **Security Test Case 2 (Local Machine Access):**
            a. **Setup:**
                i. Assume a developer has followed the `README.md` instructions and configured their `~/.netrc` file with a valid Mapbox API token as instructed.
                ii. For the purpose of this test case, we will simulate an attacker gaining access to this `.netrc` file. Create a temporary directory and within it, create a `.netrc` file mimicking the content instructed in the `README.md`, replacing `<TOKEN WITH DOWNLOAD:READ SCOPE>` with a real or test Mapbox API token that has `DOWNLOAD:READ` scope.
                ```bash
                mkdir test_netrc_exploit
                cd test_netrc_exploit
                echo "machine api.mapbox.com" >> .netrc
                echo "  login mapbox" >> .netrc
                echo "  password YOUR_MAPBOX_DOWNLOAD_READ_TOKEN" >> .netrc # Replace with your token
                ```
            b. **Exploit:**
                i. Use `curl` with the `--netrc` option to attempt to download a resource from `api.mapbox.com` that requires authentication.
                ```bash
                curl --netrc -v https://api.mapbox.com/downloads/v2/mobile-navigation-native/releases/ios/packages/some_version/MapboxNavigationNative.xcframework.zip
                ```
            c. **Verification:**
                i. Examine the output of the `curl` command. If the API token from `.netrc` is correctly used for authentication, and the server responds as if the request is authenticated, this confirms the vulnerability. Look for headers in the `curl -v` output indicating successful authentication and a success response from the server related to authentication. If the request is successful, this demonstrates that an attacker who gains access to the `.netrc` file containing the API token can indeed use that token to authenticate and access Mapbox resources, proving the vulnerability.