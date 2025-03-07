### Vulnerability List

- Vulnerability Name: Configuration Injection leading to Malicious Artifact Download
- Description:
  1. An attacker gains write access to the repository hosting the GitHub Action.
  2. The attacker modifies the `.github/workflows/dotslash-config.json` file within the repository. This file configures how DotSlash files are generated.
  3. In the modified configuration file, the attacker manipulates the `regex` or `name` fields within the `outputs` and `platforms` sections. These fields are used to identify release artifacts.
  4. The attacker crafts these modified `regex` or `name` values to point to a malicious artifact. This malicious artifact could be hosted within the same GitHub release (perhaps uploaded by a compromised account) or, if the HTTP provider is enabled, even an external malicious URL.
  5. When the `dotslash-publish-release` GitHub Action is triggered (e.g., after a successful release workflow), it reads and processes the attacker's modified configuration file.
  6. Based on this malicious configuration, the action generates a DotSlash file. This DotSlash file now contains instructions to download and execute the malicious artifact instead of the intended legitimate one.
  7. Users who subsequently download and execute this compromised DotSlash file will unknowingly download and run the malicious artifact, believing it to be the legitimate release artifact.
- Impact:
  Users who rely on the generated DotSlash files to download release artifacts will be tricked into downloading and executing malware. This can lead to:
    - System compromise of the user's machine.
    - Data theft from the user's machine.
    - Further propagation of malware.
    - Reputational damage to the project hosting the vulnerable GitHub Action.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
  - None. The project currently lacks specific mitigations within the code to prevent this vulnerability. The security relies entirely on the security of the repository's write access controls provided by GitHub.
- Missing Mitigations:
  - Input validation and sanitization of the `regex` and `name` fields within the configuration file (`dotslash-config.json`). While full sanitization might be complex due to the legitimate use cases of regex, implementing checks to prevent obvious malicious patterns or external URLs (if HTTP provider is used) could add a layer of defense. However, this might limit the flexibility of the action.
  - Stronger emphasis in the documentation on the critical importance of securing write access to the repository. The documentation should explicitly warn users about the risks of unauthorized modifications to the configuration file and the potential for malicious artifact distribution.
  - Consider adding integrity checks for the configuration file itself, although this might be complex to implement within a GitHub Action context without significantly increasing complexity for users.
- Preconditions:
  - An attacker must gain write access to the repository where the `dotslash-publish-release` GitHub Action is used. This could be achieved through compromised credentials, insider threat, or vulnerabilities in repository access controls.
  - The repository must be actively using the `dotslash-publish-release` GitHub Action to generate DotSlash files for releases.
  - Users must be downloading and executing the generated DotSlash files to obtain release artifacts.
- Source Code Analysis:
  - The vulnerability stems from the `process_config.py` script, which is the core logic of the GitHub Action.
  - `action.yml` defines the action's inputs, including `config`, which specifies the path to the configuration file (`dotslash-config.json`).
  - `process_config.py` reads the configuration file using `get_config()` and `json.load()`.
  - The `map_platforms()` function processes the `platforms` section of the configuration.
  - Inside `map_platforms()`, the script retrieves the `name` or `regex` values directly from the parsed JSON configuration (`platform_config.get("name")`, `platform_config.get("regex")`).
  - These values are then used to match assets in the GitHub release (`name_to_asset.items()`). There is no validation or sanitization applied to the `name` or `regex` values from the configuration file before they are used to select release artifacts.
  - The `generate_manifest_file()` function then creates the DotSlash file content based on the selected assets and configuration, directly incorporating the potentially attacker-controlled artifact information into the generated DotSlash file.
  - **Visualization:**
    ```
    .github/workflows/dotslash-config.json (Attacker Controlled Content) --> process_config.py (Reads Config) --> map_platforms() (Uses 'name'/'regex' from config without validation) --> generate_manifest_file() (Generates malicious DotSlash file) --> DotSlash File (Points to malicious artifact) --> User (Downloads & Executes Malicious Artifact)
    ```
- Security Test Case:
  1. **Setup:**
     - Create a public GitHub repository and set up the `dotslash-publish-release` GitHub Action as described in the `README.md`.
     - Create a GitHub release in the repository with at least two distinct artifacts (e.g., `artifact-benign-v1.0.tar.gz` and `artifact-malicious-v1.0.tar.gz`). For a safe test, `artifact-malicious-v1.0.tar.gz` can be a benign file renamed.
     - Configure `.github/workflows/dotslash-config.json` to initially point to `artifact-benign-v1.0.tar.gz` using either `regex` or `name`.
     - Ensure the `dotslash` workflow in `.github/workflows/dotslash.yml` is set up to trigger after the release workflow and uses the configured `dotslash-config.json`.
  2. **Exploit:**
     - Obtain write access to the test repository (e.g., as a collaborator).
     - Modify the `.github/workflows/dotslash-config.json` file.
     - Change the `regex` or `name` value within the configuration to now target `artifact-malicious-v1.0.tar.gz` instead of `artifact-benign-v1.0.tar.gz`.
     - Commit and push the modified `.github/workflows/dotslash-config.json` file to the repository.
  3. **Trigger Action:**
     - Trigger the `dotslash` workflow. This can be done by re-running the workflow that publishes the release artifacts or, if possible, manually triggering the `dotslash` workflow.
  4. **Verification:**
     - Once the `dotslash` workflow completes successfully, download the generated DotSlash file from the GitHub release.
     - Inspect the contents of the downloaded DotSlash file (it's a JSON file within a shell script wrapper).
     - Verify that the `providers` section within the DotSlash file now points to `artifact-malicious-v1.0.tar.gz` (or the malicious artifact you configured) instead of the original benign artifact. This confirms that the configuration injection was successful and the DotSlash file now points to the attacker's chosen artifact.
     - **Further Verification (Optional, proceed with caution in a controlled environment):** If you created a truly malicious `artifact-malicious-v1.0.tar.gz` (e.g., containing code to execute), executing the generated DotSlash file would then download and run this malicious artifact, demonstrating the full impact of the vulnerability. For safety during testing, stick to verifying the configuration change in the DotSlash file content.