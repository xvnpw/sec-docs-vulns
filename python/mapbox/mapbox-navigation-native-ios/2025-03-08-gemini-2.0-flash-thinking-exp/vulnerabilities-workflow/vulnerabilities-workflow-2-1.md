- Vulnerability name: Insecure Storage of Mapbox `DOWNLOAD:READ` Token
- Description: The README.md file instructs developers to store their Mapbox API token with `DOWNLOAD:READ` scope in the `~/.netrc` file to facilitate downloads via tools like `curl` and `carthage`. This `~/.netrc` file is typically located in the user's home directory. If a developer, following these instructions, mistakenly includes or commits their entire home directory, or specifically the `~/.netrc` file, to a publicly accessible repository (e.g., on GitHub, GitLab, or Bitbucket), the Mapbox API token becomes publicly exposed. An attacker can then discover this exposed token by browsing the public repository. Once obtained, the attacker can use this token to authenticate with Mapbox services and access resources that are authorized under the `DOWNLOAD:READ` scope associated with the compromised token. This could potentially include downloading private datasets, accessing internal resources, or performing other actions allowed by the `DOWNLOAD:READ` permissions, depending on the specifics of the Mapbox account and token configuration.
- Impact: Unauthorized access to Mapbox resources associated with the compromised token. With a `DOWNLOAD:READ` token, an attacker could potentially download private datasets, access internal resources meant only for the token owner, and possibly gain further insights into the developer's Mapbox account and related projects. The severity of the impact depends on the specific permissions and resources accessible with the `DOWNLOAD:READ` token, but it generally represents a significant security risk due to potential data exposure and unauthorized access to services.
- Vulnerability rank: High
- Currently implemented mitigations: No mitigations are implemented within the project's code or documentation to prevent developers from committing their `~/.netrc` file. The README.md provides instructions that, if followed without caution, can lead to this vulnerability.
- Missing mitigations:
    - **Strong Warning in README:** The README.md should include a clear and prominent warning against committing the `~/.netrc` file to public version control systems. This warning should emphasize the risk of exposing the Mapbox API token and the potential consequences of unauthorized access.
    - **Alternative Secure Token Storage Guidance:** The documentation should suggest and promote more secure alternatives for storing and using API tokens, such as:
        - **Environment Variables:** Recommending the use of environment variables to store the token, which are less likely to be accidentally committed to repositories.
        - **Dedicated Secrets Management Tools:** Mentioning the use of dedicated secrets management tools or services for more robust and secure handling of API keys, especially in team environments.
        - **Tool-Specific Configuration:** If possible, guide users on how to configure tools like `carthage` to use more secure methods for authentication instead of relying solely on `.netrc`.
    - **Best Practices Documentation:** Expand the documentation to include a section on security best practices for handling API tokens, emphasizing the principle of least privilege and the importance of regularly rotating tokens.
- Preconditions:
    1. Developer follows the README instructions to create a Mapbox token with `DOWNLOAD:READ` scope.
    2. Developer follows the README instructions to configure `~/.netrc` with the created token.
    3. Developer uses Git for version control and initializes a repository.
    4. Developer mistakenly adds the `~/.netrc` file (or the user's home directory containing it) to the Git repository's tracked files.
    5. Developer commits and pushes the repository to a public hosting service like GitHub, GitLab, or Bitbucket.
    6. An attacker discovers the public repository and identifies the committed `~/.netrc` file.
- Source code analysis:
    1. **README.md Instruction:** The vulnerability stems from the instruction in the `README.md` file:
    ```markdown
    Insert or append the following to `~/.netrc`

    ```bash
    machine api.mapbox.com
      login mapbox
      password <TOKEN WITH DOWNLOAD:READ SCOPE>
    ```
    This instruction guides developers to store their `DOWNLOAD:READ` token in a plain text file (`~/.netrc`) in their home directory.
    2. **Test Scripts Usage of `--netrc`:** The test scripts, such as `test_carthage.sh` and `test_spm.sh`, utilize tools like `curl` and `carthage` with the `--netrc` option:
    ```bash
    carthage update --platform iOS --use-netrc --use-xcframeworks
    curl -s --retry 3 --netrc ${URL} --output ${XCFRAMEWORK_ZIP}
    ```
    The `--netrc` flag instructs these tools to read authentication credentials from the `~/.netrc` file. This mechanism is convenient for automated processes but inherently insecure if the `.netrc` file is not properly protected.
    3. **No Mitigation in Project Code:** The provided project files do not contain any code or scripts that attempt to mitigate the risk of insecure token storage. The vulnerability is purely due to the documented instructions and the reliance on `.netrc` for authentication in scripts.
    4. **Visualization:**
    ```
    Developer -> README.md -> Instruction to modify ~/.netrc ----> Insecure Token Storage in ~/.netrc
        ^                                                                     |
        |                                                                     | Mistakenly Commit
        -----------------------------------------------------------------------
                                                                     |
                                                                     v
    Public Repository <---- Attacker Accesses ---- ~/.netrc (Exposed Token)
        |
        v
    Attacker Uses Token ----> Mapbox API ----> Unauthorized Access to Resources
    ```
- Security test case:
    1. **Setup:**
        a. Create a new Mapbox account (or use an existing test account).
        b. Generate a new Mapbox API token with the `DOWNLOAD:READ` scope enabled.
        c. On your local development machine, follow the README.md instructions to configure `~/.netrc` to store this newly generated Mapbox token. Ensure the `~/.netrc` file is created in your home directory and contains the machine, login, and password entries as specified in the README.
        d. Create a new, empty Git repository on a public platform like GitHub.
        e. Initialize a local Git repository in a new directory on your machine: `git init`.
    2. **Simulate Accidental Commit:**
        a. In your local Git repository, add the `~/.netrc` file to the staging area: `git add ~/.netrc`.  *(Note: In a real scenario, a developer might accidentally add their entire home directory or mistakenly include `~/.netrc` in a broader add command)*.
        b. Commit the `~/.netrc` file to your local repository: `git commit -m "Accidentally committed .netrc file"`.
        c. Connect your local repository to the public GitHub repository you created and push the commit: `git remote add origin <your-public-repo-url>`, `git push -u origin main`.
    3. **Attacker Exploitation:**
        a. As an attacker, access the public GitHub repository you created in step 2.
        b. Browse the repository's file list and locate the `.netrc` file.
        c. View the contents of the `.netrc` file. You should be able to see the Mapbox API token in plain text.
        d. Copy the Mapbox API token.
        e. Use `curl` to attempt to download a resource from Mapbox that requires `DOWNLOAD:READ` scope. For example, try to access a tileset or other downloadable resource. Replace `<YOUR_EXPOSED_TOKEN>` with the token you extracted and `<RESOURCE_URL>` with a valid Mapbox resource URL that requires `DOWNLOAD:READ` permissions.
        ```bash
        curl --netrc -v -o test_download.zip "https://api.mapbox.com/downloads/v2/mobile-navigation-native/releases/ios/packages/206.1.0/MapboxNavigationNative.xcframework.zip"
        ```
        *(Note: The URL used in the test case is an example and might require adjustment based on available resources and API endpoints.)*
    4. **Verification:**
        a. If the `curl` command in step 3e successfully downloads the resource without prompting for authentication or returning an authorization error, it confirms that the exposed token is valid and grants `DOWNLOAD:READ` access.
        b. This successful download demonstrates that an attacker who gains access to the publicly committed `.netrc` file can indeed use the exposed Mapbox API token to gain unauthorized access to Mapbox resources, validating the vulnerability.