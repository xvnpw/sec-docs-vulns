## Vulnerability List

### Vulnerability 1: Command Injection via `scan-args` input in `osv-scanner-action` and `osv-reporter-action`

* Description:
    1. The `osv-scanner-action` and `osv-reporter-action` GitHub Actions define an `scan-args` input that allows users to pass arguments to the underlying `osv-scanner` tool.
    2. This `scan-args` input is directly passed to the `osv-scanner` command executed within a Docker container without proper sanitization or validation.
    3. An attacker can inject arbitrary shell commands by crafting malicious arguments within the `scan-args` input. For example, an attacker could inject arguments like `--version ; touch /tmp/pwned` or similar commands.
    4. When the GitHub Action executes, the injected commands will be executed by the shell within the Docker container, leading to command injection.

* Impact:
    - Successful command injection allows an attacker to execute arbitrary commands within the GitHub Actions runner environment.
    - This can lead to various malicious activities, including:
        - **Data exfiltration:** Attackers could steal sensitive information, such as environment variables, source code, or build artifacts.
        - **Code modification:** Attackers could modify the repository's code, introduce backdoors, or sabotage the build process.
        - **Denial of Service:** Attackers could disrupt the CI/CD pipeline or the GitHub Actions runner environment.
        - **Lateral movement:** In a more complex scenario, attackers might be able to leverage compromised runners to access other resources within the GitHub organization or connected infrastructure.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - None. The `action.yml` files for `osv-scanner-action` and `osv-reporter-action` directly pass the `scan-args` input to the Docker container's entrypoint without any sanitization or validation.

* Missing Mitigations:
    - **Input Sanitization:** Implement robust input sanitization and validation for the `scan-args` input. This could involve:
        - **Allowlisting:** Define a strict allowlist of permitted arguments for `osv-scanner`.
        - **Argument parsing and validation:** Parse the `scan-args` input and validate each argument against expected patterns and values.
        - **Shell escaping:** If direct shell command execution is unavoidable, properly escape all special characters in the user-provided arguments to prevent command injection.
    - **Principle of Least Privilege:**  Ensure the Docker container and the `osv-scanner` tool run with the minimum necessary privileges to limit the impact of potential command injection vulnerabilities.
    - **Documentation:** Clearly document the security risks associated with the `scan-args` input and advise users on best practices for providing secure arguments, or discourage the use of user-supplied arguments altogether if possible.

* Preconditions:
    - An attacker needs to be able to control the `scan-args` input of the `osv-scanner-action` or `osv-reporter-action`.
    - This is typically achievable by:
        - Directly modifying the workflow YAML file in a pull request.
        - Indirectly controlling the input through workflow parameters or repository variables if the workflow is designed to accept user-controlled input for `scan-args`.

* Source Code Analysis:
    - **File: `/code/osv-scanner-action/action.yml`**
        ```yaml
        runs:
          using: "docker"
          image: "docker://ghcr.io/google/osv-scanner-action:v2.0.0-beta2"
          args:
            - ${{ inputs.scan-args }}
        ```
        The `args` section directly uses `${{ inputs.scan-args }}`. This input is taken directly from the workflow configuration and passed as command-line arguments to the `osv-scanner` executable within the Docker container.

    - **File: `/code/osv-reporter-action/action.yml`**
        ```yaml
        runs:
          using: "docker"
          image: "docker://ghcr.io/google/osv-scanner-action:v2.0.0-beta2"
          entrypoint: /root/osv-reporter
          args:
            - "${{ inputs.scan-args }}"
        ```
        Similarly, the `args` section here uses `"${{ inputs.scan-args }}"`.  The double quotes might seem like escaping, but in YAML and GitHub Actions context, they primarily serve for string formatting and do not provide sufficient protection against command injection in this scenario. The input is still directly interpreted as shell arguments.

* Security Test Case:
    1. Create a public GitHub repository.
    2. Create a workflow file (e.g., `.github/workflows/command-injection-test.yml`) with the following content, using `osv-scanner-action`:
        ```yaml
        name: Command Injection Test
        on: workflow_dispatch
        jobs:
          scan:
            runs-on: ubuntu-latest
            steps:
              - name: Checkout code
                uses: actions/checkout@v3
              - name: Run OSV Scanner with command injection
                uses: google/osv-scanner-action/osv-scanner-action@v2.0.0-beta2
                with:
                  scan-args: '--version ; touch /tmp/pwned-osv-scanner-action'
              - name: Check for successful command injection (osv-scanner-action)
                run: |
                  if [ -f /tmp/pwned-osv-scanner-action ]; then
                    echo "Command injection in osv-scanner-action successful!"
                    exit 0
                  else
                    echo "Command injection in osv-scanner-action failed."
                    exit 1
                  fi
        ```
    3. Commit and push this workflow to the repository.
    4. Manually trigger the workflow from the "Actions" tab in your GitHub repository.
    5. After the workflow completes, check the output of the "Check for successful command injection (osv-scanner-action)" step. If it prints "Command injection in osv-scanner-action successful!", then the vulnerability is confirmed for `osv-scanner-action`.
    6. Repeat steps 2-5, but replace `osv-scanner-action` with `osv-reporter-action` in the `uses` field and change the `scan-args` value and the file name in the `touch` command (e.g., `--version ; touch /tmp/pwned-osv-reporter-action`) and the check step accordingly to test `osv-reporter-action`.
    7. If both tests are successful, it confirms that both `osv-scanner-action` and `osv-reporter-action` are vulnerable to command injection through the `scan-args` input.