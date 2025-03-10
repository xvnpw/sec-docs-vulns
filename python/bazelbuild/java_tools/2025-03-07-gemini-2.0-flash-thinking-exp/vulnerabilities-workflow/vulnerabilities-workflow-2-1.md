- Vulnerability Name: Unverified Download of Release Artifacts in `release.py`
- Description: The `release.py` script downloads release artifacts using `wget` from URLs specified in a JSON file provided as a command-line argument `--artifacts`. This JSON file is expected to be generated by an upstream release process (`create_java_tools_release.sh` and related pipelines). If this upstream process is compromised, a malicious actor could modify the JSON file to inject malicious URLs for the `mirror_url` fields. When a user, even a trusted release manager, executes `release.py` with this compromised JSON, the script will blindly download artifacts from the attacker-controlled malicious URLs. These downloaded malicious artifacts could then replace legitimate `java_tools` components in the release process, potentially leading to supply chain attacks and arbitrary code execution on developer machines when they use the compromised `java_tools` in their Bazel builds.
- Impact: Arbitrary code execution on developer machines. By using a compromised `java_tools` release, malicious Java code embedded within the tools could be executed during a Bazel build, allowing an attacker to gain control over the developer's environment. This can lead to data theft, further propagation of malware, or disruption of development workflows.
- Vulnerability Rank: High
- Currently Implemented Mitigations: None. The provided files do not show any implemented mitigations in the `release.py` script or the documented release process to verify the integrity or source of the download URLs before downloading release artifacts. The security relies entirely on the assumption that the upstream processes generating the artifacts JSON are always secure and cannot be compromised.
- Missing Mitigations:
    - **URL Verification:** The `release.py` script should verify that the `mirror_url` belongs to a trusted domain (e.g., `mirror.bazel.build`). This can be implemented by parsing the URL and checking the hostname against a whitelist of trusted domains.
    - **Integrity Check:** The script should verify the integrity of downloaded files by comparing the SHA256 checksum of the downloaded file against the expected `sha` value provided in the artifacts JSON. This should be done immediately after downloading each artifact and before further processing or release.
    - **Secure Artifacts JSON Generation:** Hardening the security of the upstream pipeline and scripts (`create_java_tools_release.sh`) that generate the artifacts JSON is crucial to prevent malicious injection of URLs at the source. This includes access control, input validation, and integrity checks within the pipeline itself.
- Preconditions:
    - An attacker must successfully compromise the upstream release process responsible for generating the artifacts JSON file. This could involve compromising the `create_java_tools_release.sh` script, the pipeline execution environment, or any system involved in generating the JSON output.
    - A release manager or another user with access to execute `release.py` must run the script with the compromised artifacts JSON file using the `--artifacts` argument.
- Source Code Analysis:
    ```python
    def download_file(mirror_url):
      wget.download(mirror_url , '.')
    ```
    The `download_file` function within `release.py` directly utilizes the `wget.download()` function to download files based on the provided `mirror_url`. Critically, there is no validation, sanitization, or integrity checking performed on the `mirror_url` before initiating the download. The `mirror_url` is taken directly from the `artifacts` JSON, which is parsed from the `--artifacts` command-line argument.

    ```python
    def main():
      parser = argparse.ArgumentParser()
      parser.add_argument(
          '--artifacts',
          required=True,
          dest='artifacts',
          help='Output from create_java_tools_release.sh')
      opts = parser.parse_args()

      artifacts = json.loads(opts.artifacts)["artifacts"]

      relnotes = "To use this java_tools release, add to your WORKSPACE file the definitions: \n```py"
      for platform in artifacts:
        relnotes += generate_release_info(platform, artifacts[platform])
        download_file(artifacts[platform]["mirror_url"])
    ```
    The `main` function parses the `--artifacts` argument as JSON and iterates through the `artifacts` dictionary. For each platform, it extracts the `mirror_url` and passes it directly to the `download_file` function.  There is no check to ensure the `mirror_url` is safe or from a trusted source, nor is there any subsequent verification of the downloaded file's integrity. This direct and unverified download process opens the door for a malicious actor to inject a harmful URL and compromise the downloaded artifacts.

- Security Test Case:
    1. **Setup Malicious Server:** Configure a simple HTTP server (e.g., using Python's `http.server` or `netcat`) on your local machine or a controlled network. This server will host a malicious replacement `java_tools` zip file. This zip file should contain a harmless payload for testing, such as a simple Java class that prints a message to standard output or creates a file in a temporary directory (e.g., `/tmp/pwned_test`). Obtain the URL for this malicious zip file (e.g., `http://localhost:8000/malicious_java_tools.zip`).
    2. **Craft Malicious Artifacts JSON:** Create a JSON file (e.g., `malicious_artifacts.json`) that simulates the expected output from `create_java_tools_release.sh`. Within this JSON, locate the `mirror_url` for one of the platforms (e.g., `java_tools_linux`). Replace the legitimate `mirror_url` value with the malicious URL you set up in step 1 (`http://localhost:8000/malicious_java_tools.zip`).  For the `sha` value, you can use a dummy string for this test, as the script does not use it for verification before download. The `github_url` can also be a dummy value. Ensure the JSON structure is otherwise valid and matches the expected format. Example structure:
        ```json
        {
          "artifacts": {
            "java_tools_linux": {
              "mirror_url": "http://localhost:8000/malicious_java_tools.zip",
              "sha": "dummy_sha",
              "github_url": "https://dummy.github.com/url"
            },
            "java_tools_windows": {
              "mirror_url": "https://mirror.bazel.build/bazel_java_tools/releases/java/vXX.XX/java_tools_windows-vXX.XX.zip",
              "sha": "valid_sha_windows",
              "github_url": "https://github.com/bazelbuild/java_tools/releases/download/java_vXX.XX/java_tools_windows-vXX.XX.zip"
            },
            // ... other platforms with legitimate mirror_urls ...
          }
        }
        ```
    3. **Execute `release.py` with Malicious JSON:** Run the `release.py` script, providing the path to your crafted `malicious_artifacts.json` file using the `--artifacts` argument:
        ```bash
        python /code/scripts/release.py --artifacts "$(cat malicious_artifacts.json)"
        ```
    4. **Verify Malicious Download:** After executing the script, check the current directory. You should find a file named `malicious_java_tools.zip` (or whatever the filename is from your malicious URL), which has been downloaded from your malicious server, replacing the expected legitimate artifact for `java_tools_linux`.
    5. **Verify Payload Execution (If Applicable):** If your malicious zip contained an executable payload or script designed to run upon extraction or usage, attempt to trigger that execution manually (this step depends on the nature of the payload and is for further confirmation). For example, if you placed a Java class that creates `/tmp/pwned_test`, check for the existence of this file.
    6. **Cleanup:** Delete the downloaded `malicious_java_tools.zip` file and any test files created by the payload (e.g., `/tmp/pwned_test`). Stop your malicious HTTP server.

This test case demonstrates that `release.py` will download artifacts from attacker-specified URLs without verification, confirming the vulnerability.