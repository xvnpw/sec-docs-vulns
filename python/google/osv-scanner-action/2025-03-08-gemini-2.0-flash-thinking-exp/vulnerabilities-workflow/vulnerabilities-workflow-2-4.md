### Vulnerability List:

- Vulnerability Name: Command Injection via `scan-args` input

- Description:
  - The GitHub Action `osv-scanner-action` and `osv-reporter-action` take user-provided arguments via the `scan-args` input.
  - This `scan-args` input is directly passed as command-line arguments to the `osv-scanner` or `osv-reporter` commands executed within the Docker container.
  - If a malicious user provides crafted input within `scan-args` that includes command injection payloads, these payloads will be executed by the shell within the Docker container.
  - For example, an attacker could set `scan-args` to `-- -v $(whoami)` or similar command injection attempts. When the action executes the `osv-scanner` command with these arguments, the injected command `$(whoami)` will be executed.

- Impact:
  - Successful command injection can lead to arbitrary code execution within the Docker container environment of the GitHub Action.
  - This can allow an attacker to:
    - Exfiltrate sensitive information from the CI/CD environment, such as secrets or source code.
    - Modify the source code repository.
    - Pivot to other parts of the CI/CD infrastructure.
    - Disrupt the CI/CD pipeline.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
  - None. The provided code directly passes the `scan-args` input to the underlying commands without any sanitization or validation.

- Missing Mitigations:
  - Input sanitization and validation for the `scan-args` input.
  - The action should sanitize or validate the `scan-args` input to remove or escape shell metacharacters and prevent command injection.
  - Consider using a safer method to pass arguments to the `osv-scanner` tool that avoids direct shell interpretation if possible, although command line arguments by nature are interpreted by the shell.
  - At a minimum, the action should document the security risks of using unsanitized inputs and recommend users to only use trusted inputs for `scan-args`.

- Preconditions:
  - An attacker needs to be able to control the `scan-args` input to the GitHub Action.
  - This can be achieved by:
    - Creating a pull request to a repository that uses this action and modifying the workflow file to include malicious `scan-args`.
    - Directly modifying the workflow file in a repository where the attacker has write access.
    - In case of scheduled scans, if the configuration is stored in the repository, an attacker with write access can modify it.

- Source Code Analysis:
  - **File: `/code/osv-scanner-action/action.yml`**
    ```yaml
    runs:
      using: "docker"
      image: "docker://ghcr.io/google/osv-scanner-action:v2.0.0-beta2"
      args:
        - ${{ inputs.scan-args }}
    ```
  - **File: `/code/osv-reporter-action/action.yml`**
    ```yaml
    runs:
      using: "docker"
      image: "docker://ghcr.io/google/osv-scanner-action:v2.0.0-beta2"
      entrypoint: /root/osv-reporter
      args:
        - "${{ inputs.scan-args }}"
    ```
  - In both `action.yml` files, the `inputs.scan-args` is directly used as part of the `args` for the Docker container execution.
  - GitHub Actions expressions like `${{ inputs.scan-args }}` are evaluated and their string representation is passed to the `docker run` command.
  - If `inputs.scan-args` contains shell command injection characters, these characters will be interpreted by the shell when the Docker container's entrypoint (either `osv-scanner` or `osv-reporter`) is executed.
  - There is no code in these YAML files that performs any kind of sanitization or escaping of the `inputs.scan-args` before passing it to the `args`.
  - This direct usage of user-controlled input as command arguments without sanitization is the root cause of the command injection vulnerability.

- Security Test Case:
  - Step 1: Create a fork of the `google/osv-scanner-action` repository (or use a test repository with the action configured).
  - Step 2: Modify the workflow file (e.g., `.github/workflows/osv-scanner-unified-workflow.yml`) in your fork to include a malicious `scan-args`. For example, in the `scan` job, add the following under the `with:` section:
    ```yaml
    with:
      scan-args: '-- -v $(whoami)'
    ```
  - Step 3: Commit and push this change to your forked repository.
  - Step 4: Trigger the workflow (e.g., by pushing a commit or creating a pull request).
  - Step 5: Examine the logs of the `scan` job in the Actions tab of your repository.
  - Step 6: If the command injection is successful, you will see the output of the `whoami` command in the logs, indicating that arbitrary code execution was achieved. You might see extra verbose output from `osv-scanner` due to `-v`, and then the output of `whoami`.