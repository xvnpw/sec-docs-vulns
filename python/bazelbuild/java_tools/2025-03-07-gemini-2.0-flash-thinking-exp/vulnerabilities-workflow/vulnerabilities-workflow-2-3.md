- Vulnerability Name: Insufficient Integrity Verification of Release Artifacts
- Description:
  - An attacker could compromise the release infrastructure or gain access to release publishing credentials.
  - The attacker replaces legitimate `java_tools` release artifacts on the releases page and mirror (bazel-mirror GCP bucket) with malicious versions.
  - The attacker updates the `sha256` checksums provided in the release notes and potentially in the `rules_java` repository to match the malicious artifacts.
  - Unsuspecting users follow the instructions in `README.md` or release notes and copy the `http_archive` definitions into their `WORKSPACE` file, potentially without independently verifying the checksums.
  - Bazel downloads the malicious `java_tools` artifacts during project setup.
  - When users build their Bazel projects, the malicious `java_tools` are used, potentially leading to code execution or other malicious activities within the user's build environment.
- Impact:
  - Supply chain compromise.
  - Users' Bazel builds are executed using malicious tools.
  - Potential for arbitrary code execution within the build environment.
  - Potential for malicious modifications of build outputs.
  - Potential for data exfiltration from the build environment.
  - Compromise of developer machines.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
  - Checksums (SHA256) for release artifacts are provided in:
    - Release notes on the GitHub releases page.
    - `java_tools_repos()` function in `rules_java/java/repositories.bzl`.
  - The release process relies on Buildkite pipelines and Google Cloud Platform (GCP) for building and hosting artifacts, which inherently provides some level of infrastructure security. However, specific security measures for these systems are not detailed in the provided files.
- Missing Mitigations:
  - **Explicit User Guidance on Independent Verification:** The documentation does not strongly emphasize the importance of users independently verifying the checksums of downloaded `java_tools` artifacts before integration. Clear and prominent warnings should be added to `README.md`, release notes, and any user-facing documentation, instructing users to verify checksums using trusted tools and sources, separate from the release notes themselves.
  - **Automated Checksum Verification Tools:** Providing scripts or tools that automate the process of verifying artifact checksums against a trusted, independent source would significantly improve user security. This could be a Bazel plugin or a standalone script.
  - **Artifact Signing:** Digitally signing release artifacts would provide a stronger mechanism for verifying the integrity and authenticity of the releases. Users could then verify the signature using a trusted public key, ensuring that the artifacts have not been tampered with and originate from a legitimate source.
- Preconditions:
  - The attacker must successfully compromise the release infrastructure or gain access to release publishing credentials to replace the official artifacts and update the checksums.
  - Users must rely solely on the checksums provided in the release notes or `rules_java` repository without performing independent verification.
- Source Code Analysis:
  - **`README.md`, `docs/release.md`, `docs/release-automated.md`**: These documentation files describe the release process and instruct users to integrate `java_tools` by using `http_archive` with provided URLs and SHA256 checksums.
    - The example in `README.md` shows:
      ```markdown
      To use a specific java_tools release in your Bazel project please add the `http_archive` definitions in your WORKSPACE file.
      ...
      ```
    - The release documentation guides users to copy these definitions, including checksums, but lacks explicit warnings about the critical need for independent verification.
  - **`scripts/release.py`**: This script is used by release managers to generate release notes and download release files for local use during the release process. It does not play a role in user-side verification and does not introduce or mitigate this vulnerability.
  - **Absence of User-Side Verification Mechanisms**: The project lacks any tooling or automated processes to assist users in independently verifying the integrity of downloaded `java_tools` artifacts. The reliance is solely on users manually copying and trusting the provided checksums, which are susceptible to manipulation if the release infrastructure is compromised.
- Security Test Case:
  1. **Attacker Simulation (Artifact Manipulation):**
     - Choose a specific `java_tools` release version (e.g., v13.1).
     - Download the official `java_tools` zip file for Linux (e.g., `java_tools_linux-v13.1.zip`) from the release page or mirror.
     - Create a malicious version of `java_tools_linux-v13.1.zip`. This malicious version could contain a simple program that prints a warning message to `stderr` during Bazel execution.
     - Calculate the SHA256 checksum of this malicious zip file.
     - **Simulate Compromise:**  For testing purposes, instead of actually compromising the release infrastructure, locally replace the legitimate `java_tools_linux-v13.1.zip` with the malicious `java_tools_linux-v13.1.zip` in a local directory that will act as a fake mirror. Also, prepare a fake release notes snippet with the *updated* checksum for the malicious file.
  2. **Victim Project Setup:**
     - Create a new Bazel project with a simple Java target.
     - In the project's `WORKSPACE` file, define `http_archive` for `remote_java_tools_linux`.
       - Modify the `urls` attribute to point to your local directory containing the *malicious* `java_tools_linux-v13.1.zip`.
       - **Crucially, use the *updated* SHA256 checksum** that you calculated for the malicious zip file, as if the attacker has updated the checksum in the release notes.
       - Do *not* implement any independent checksum verification mechanism in the `WORKSPACE` file or build scripts.
  3. **Build Execution:**
     - Run `bazel build //...` within the victim project.
  4. **Vulnerability Verification:**
     - Observe the output of the Bazel build process.
     - If the malicious code within the replaced `java_tools_linux-v13.1.zip` is executed (e.g., the warning message to `stderr` is printed), it confirms that the user's build process is now using the malicious tools because they trusted the provided (but compromised) checksum without independent verification. This demonstrates the vulnerability.