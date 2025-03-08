## Vulnerability List

### Vulnerability 1: Bypass of OSV-Scanner through `scan-args` Manipulation

* Description:
    1. An attacker creates a pull request to the repository.
    2. In the pull request, the attacker modifies the workflow file (e.g., `.github/workflows/osv-scanner-unified-workflow.yml`).
    3. The attacker changes the `scan-args` input to the `osv-scanner-action` to exclude directories or files containing vulnerable dependencies. For example, they could set `scan-args` to `--no-recursive` or specify a limited set of directories that do not include the vulnerable dependencies using `--exclude`.
    4. The pull request is merged without careful review of the workflow changes.
    5. The OSV-Scanner action runs with the modified `scan-args`, effectively skipping the scan of the vulnerable dependencies.
    6. The vulnerability is not detected, and the vulnerable code is merged into the main branch and potentially deployed.

* Impact:
    Vulnerabilities in dependencies can be introduced and deployed without detection by the OSV-Scanner action. This can lead to various security risks depending on the nature of the vulnerabilities, such as data breaches, service disruption, or unauthorized access.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    None in the project files to prevent workflow modification. The primary mitigation relies on the project's code review process to detect and prevent malicious workflow changes.

* Missing Mitigations:
    - Workflow protection: Implementing GitHub's workflow protection feature to restrict modifications to workflow files by unauthorized users. This would prevent attackers from directly altering the `scan-args` within workflow definitions in pull requests unless they have specific permissions.
    - Documentation and warnings: Enhancing the documentation to explicitly warn users about the security implications of modifying `scan-args` and emphasize the importance of thoroughly reviewing any changes to workflow files, especially those altering scanner configurations.

* Preconditions:
    - The attacker has the ability to create pull requests to the repository.
    - Pull requests, particularly changes to workflow files, are not rigorously reviewed by repository maintainers.
    - The project utilizes the OSV-Scanner action and permits modifications to workflow files.

* Source Code Analysis:
    - File: `/code/osv-scanner-action/action.yml`
        ```yaml
        inputs:
          scan-args:
            description: "Arguments to osv-scanner, separated by new line"
            default: |-
              --recursive
              ./
        runs:
          using: "docker"
          image: "docker://ghcr.io/google/osv-scanner-action:v2.0.0-beta2"
          args:
            - ${{ inputs.scan-args }}
        ```
        The `scan-args` input is directly passed as arguments to the `osv-scanner` tool within the Docker container without any validation or sanitization. This allows users to control the arguments passed to the scanner.

    - File: `/code/.github/workflows/osv-scanner-reusable.yml`
        ```yaml
        jobs:
          osv-scan:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v3
              - name: Run OSV-Scanner
                uses: google/osv-scanner-action/osv-scanner-action@v2.0.0-beta2
                with:
                  scan-args: ${{ inputs.scan_args }} # Input is passed here
        ```
        This reusable workflow accepts `scan_args` as input and passes it to the `osv-scanner-action`.

    - File: `/code/.github/workflows/osv-scanner-unified-workflow.yml`
        ```yaml
        jobs:
          scan-scheduled:
            uses: google/osv-scanner-action/.github/workflows/osv-scanner-reusable.yml@main
            secrets: inherit
          scan-pr:
            uses: google/osv-scanner-action/.github/workflows/osv-scanner-reusable-pr.yml@main
            secrets: inherit
        ```
        The unified workflow by default does not set `scan-args`, inheriting the default arguments from `osv-scanner-action/action.yml`. However, an attacker can modify this file to add `scan-args` under the `with` section of the `uses` directive to alter the scanner's behavior.

* Security Test Case:
    1. Fork the repository to your GitHub account.
    2. In your forked repository, navigate to the workflow file `.github/workflows/osv-scanner-unified-workflow.yml`.
    3. Edit the file and modify the `scan-scheduled` job to include `scan-args` that exclude a directory. For example, if you have a directory named `vulnerable-dependencies` where you plan to place a vulnerable dependency, add the following under the `scan-scheduled` job's `uses` section:
        ```yaml
        with:
          scan_args: "--exclude vulnerable-dependencies"
        ```
    4. Commit these changes to a new branch in your forked repository (e.g., `bypass-scan-args`).
    5. Create a new directory named `vulnerable-dependencies` at the root of your forked repository.
    6. Inside the `vulnerable-dependencies` directory, add a file (e.g., `package-lock.json`, `requirements.txt`, `pom.xml` depending on the language you want to test) that declares a known vulnerable dependency. For example, if testing with npm, create `package-lock.json` with a vulnerable dependency.
    7. Create a pull request from your `bypass-scan-args` branch in your forked repository to the `main` branch of the original repository.
    8. Observe the GitHub Actions checks triggered by the pull request.
    9. Verify that the OSV-Scanner check passes successfully, or at least does not report the vulnerability introduced in the `vulnerable-dependencies` directory. This indicates the scanner was bypassed due to the modified `scan-args`.
    10. (Optional) If you have permissions, merge the pull request.
    11. Navigate to the "Security" tab of the repository and then to "Code scanning". Confirm that no vulnerability is reported related to the dependency you added in the `vulnerable-dependencies` directory. This further validates the bypass.

### Vulnerability 2: Command Injection via `scan-args` input in `osv-scanner-action` and `osv-reporter-action`

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