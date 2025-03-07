- Vulnerability Name: Command Injection in release.sh via version_tag parameter

- Description:
  1. The `release.sh` script is used to automate the release process.
  2. The script takes `version_tag` as a command-line argument.
  3. The `version_tag` argument is used in the `gh release create` command without proper sanitization:
  ```bash
  gh release create $version_tag ./dist/$whl_file --generate-notes --draft --prerelease
  ```
  4. An attacker can inject malicious code into the `version_tag` parameter.
  5. When the script executes `gh release create $version_tag ...`, the injected code will be executed as part of the command.

- Impact:
  - An attacker could achieve arbitrary command execution on the system where the `release.sh` script is executed.
  - If the script is run in an automated CI/CD pipeline with elevated privileges, the attacker could potentially compromise the entire build and release process, leading to supply chain attacks.
  - Injected commands could lead to unauthorized access to resources, data exfiltration, or modification of the release artifacts.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
  - None. The script directly uses the user-supplied `version_tag` in a shell command without any sanitization or validation.

- Missing Mitigations:
  - Input sanitization and validation for the `version_tag` parameter.
  - Use parameterized commands or shell command builder functions to avoid direct string interpolation of user-provided values into shell commands.
  - Implement security checks in the CI/CD pipeline to prevent execution of untrusted scripts or validate script parameters.

- Preconditions:
  - The attacker needs to be able to influence the `version_tag` parameter passed to the `release.sh` script. This could happen if the release process is triggered by an external event or if the attacker can modify the script execution environment.
  - The `gh` CLI tool must be installed and configured in the environment where the script is executed.

- Source Code Analysis:
  1. File: `/code/scripts/release.sh`
  2. The script accepts `version_tag` as the second argument:
  ```bash
  version_tag=$2
  ```
  3. The `version_tag` variable is directly used in the `gh release create` command:
  ```bash
  gh release create $version_tag ./dist/$whl_file --generate-notes --draft --prerelease
  ```
  4. No sanitization or validation is performed on the `version_tag` before it is used in the command.
  5. An attacker can inject malicious commands by providing a crafted `version_tag` value, e.g., `v0.2.3-alpha && malicious_command`.

- Security Test Case:
  1.  Assume an attacker can control the `version_tag` parameter when executing `release.sh`.
  2.  Prepare a malicious `version_tag` value to inject a command, for example: `v0.2.3-alpha && echo "Vulnerable" > /tmp/vulnerable`.
  3.  Execute the `release.sh` script with the malicious `version_tag`:
      ```bash
      ./scripts/release.sh 0.2.3 'v0.2.3-alpha && echo "Vulnerable" > /tmp/vulnerable'
      ```
  4.  After execution, check if the file `/tmp/vulnerable` exists and contains the word "Vulnerable".
  5.  If the file is created, it confirms that the command injection vulnerability is present, and arbitrary commands could be executed.
  6.  For a safer test case that doesn't create files, you can use a time-based command, e.g., `v0.2.3-alpha && sleep 10`. Observe if the script execution time increases by 10 seconds.
  7.  A more benign test could be to inject a command that prints environment variables, e.g., `v0.2.3-alpha && env > /tmp/env.txt`. Then examine `/tmp/env.txt`.