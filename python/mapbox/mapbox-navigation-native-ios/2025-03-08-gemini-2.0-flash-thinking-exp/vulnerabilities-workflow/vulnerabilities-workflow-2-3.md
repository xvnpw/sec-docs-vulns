- Vulnerability Name: Mapbox API Token Exposure via `~/.netrc` File

- Description:
  1. The project's `README.md` file instructs developers to store their Mapbox API token with `DOWNLOAD:READ` scope in the `~/.netrc` file to facilitate downloading the library.
  2. The `~/.netrc` file is typically stored in the user's home directory (`~`) and can be inadvertently exposed through various means.
  3. If an attacker gains unauthorized access to a developer's local machine, they could potentially read the `~/.netrc` file and extract the Mapbox API token.
  4. Alternatively, if a developer mistakenly commits the `~/.netrc` file to a version control system, the API token would be exposed to anyone with access to the repository, which could be public or private depending on the repository's settings.
  5. Once the attacker obtains the Mapbox API token, they can impersonate the developer and potentially access Mapbox services under the developer's account, subject to the token's permissions and Mapbox's access control policies.

- Impact:
  - Unauthorized access to the developer's Mapbox account.
  - Potential misuse of Mapbox services associated with the compromised token, potentially leading to:
    - Unexpected usage charges billed to the developer's account.
    - Disruption of services or resources linked to the Mapbox account.
    - Data breaches if the token grants access to sensitive data within the Mapbox account.
  - Reputational damage to the developer or organization associated with the compromised Mapbox account.

- Vulnerability Rank: Medium

- Currently Implemented Mitigations:
  - None. The project documentation explicitly instructs users to store the API token in the `~/.netrc` file. There are no warnings or alternative secure methods suggested within the provided files.

- Missing Mitigations:
  - **Security Warning in Documentation:** The `README.md` should include a strong warning about the security risks of storing API tokens in `~/.netrc` and the potential consequences of unauthorized access.
  - **Alternative Authentication Methods:** The documentation should explore and recommend more secure alternatives to storing API tokens in `~/.netrc`. This could include:
    - Using environment variables to store the token, which are less likely to be accidentally committed to version control.
    - Utilizing dedicated secret management tools or keychain services to store and retrieve API tokens securely.
  - **Token Scope Limitation Guidance:** Developers should be advised to create Mapbox API tokens with the minimal necessary scope (in this case, `DOWNLOAD:READ`) to limit the potential damage if the token is compromised. Broader scope tokens should be strongly discouraged for download purposes.
  - **Token Revocation Instructions:** Clear instructions on how to revoke and regenerate a Mapbox API token should be provided in the documentation, in case a token is suspected to be compromised.

- Preconditions:
  1. A developer follows the instructions in the `README.md` and stores their Mapbox API token in the `~/.netrc` file.
  2. An attacker gains unauthorized access to the developer's local machine (e.g., through malware, social engineering, or physical access).
  3. *OR* The developer mistakenly commits the `~/.netrc` file to a public or accessible version control repository.

- Source Code Analysis:
  - The vulnerability is introduced by the project's documentation, specifically the `README.md` file, rather than the source code itself.
  - The `README.md` file contains the following instruction:
    ```markdown
    ##### SPM, CocoaPods and Carthage
    Insert or append the following to `~/.netrc`

    ```bash
    machine api.mapbox.com
      login mapbox
      password <TOKEN WITH DOWNLOAD:READ SCOPE>
    ```
  - This instruction directly encourages developers to store their Mapbox API token in plain text within the `~/.netrc` file, which is a known insecure practice for sensitive credentials.
  - The provided scripts (`test_spm.sh`, `test_carthage.sh`, `release.sh`) use `curl --netrc`, indicating reliance on `.netrc` for authentication during the build and release processes, further reinforcing the documented method.
  - **Visualization:**
    ```
    Developer's Machine --> Stores API Token in ~/.netrc (as instructed by README.md)
        ^
        | Potential Attack Vectors:
        | 1. Machine Compromise (Malware, Physical Access)
        | 2. Accidental Commit to Version Control
        |
    Attacker --> Gains Access to ~/.netrc --> Extracts API Token
        |
    Attacker --> Uses API Token --> Unauthorized Access to Mapbox Account
    ```

- Security Test Case:
  1. **Setup:**
     - Assume a developer has followed the `README.md` instructions and configured their `~/.netrc` file with a valid Mapbox API token as instructed.
     - For the purpose of this test case, we will simulate an attacker gaining access to this `~/.netrc` file. In a real-world scenario, this would require compromising the developer's machine or accessing a repository where the file was mistakenly committed.
     - Create a temporary directory and within it, create a `.netrc` file mimicking the content instructed in the `README.md`, replacing `<TOKEN WITH DOWNLOAD:READ SCOPE>` with a real or test Mapbox API token that has `DOWNLOAD:READ` scope.
     ```bash
     mkdir test_netrc_exploit
     cd test_netrc_exploit
     echo "machine api.mapbox.com" >> .netrc
     echo "  login mapbox" >> .netrc
     echo "  password YOUR_MAPBOX_DOWNLOAD_READ_TOKEN" >> .netrc # Replace with your token
     ```
  2. **Exploit:**
     - Use `curl` with the `--netrc` option to attempt to download a resource from `api.mapbox.com` that requires authentication.  A suitable test endpoint could be a protected download endpoint if available, or a generic endpoint that would at least demonstrate authentication is being attempted. For this test, assuming there's a protected download endpoint for library versions, we can attempt to access it.  (Note: Specific protected download URLs are hypothetical here, replace with actual if available or a different authenticated endpoint).
     ```bash
     curl --netrc -v https://api.mapbox.com/downloads/v2/mobile-navigation-native/releases/ios/packages/some_version/MapboxNavigationNative.xcframework.zip
     ```
     - The `-v` option in `curl` will provide verbose output, showing the headers and details of the request and response, which is useful for verifying that authentication is being attempted using the `.netrc` file.
  3. **Verification:**
     - Examine the output of the `curl` command.
     - **Successful Exploit:** If the API token from `.netrc` is correctly used for authentication, and the server responds as if the request is authenticated (e.g., attempts to download the file, or returns a specific authenticated response even if the resource is not found), this confirms the vulnerability. Look for headers in the `curl -v` output indicating successful authentication (e.g., `Authorization` headers being sent, and a `200 OK` or other success response from the server related to authentication).
     - **Failed Exploit (Mitigation Present - which is not expected here):** If the request fails due to authentication errors (e.g., `401 Unauthorized`), it would suggest that `.netrc` authentication is not working as expected, or that the test endpoint does not rely on `.netrc` authentication in the way anticipated. However, given the documentation and scripts, this is not the expected outcome.

     - In the expected successful scenario, this test case demonstrates that an attacker who gains access to the `.netrc` file containing the API token can indeed use that token to authenticate and access Mapbox resources, proving the vulnerability.