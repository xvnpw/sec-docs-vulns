## Vulnerability List

### YAML Injection leading to Workflow Command Injection

**Description:**
By providing specially crafted input during user prompts (e.g., when creating Azure resource names), an attacker can inject malicious YAML code into the generated GitHub Actions workflow file. This injected YAML code can then be interpreted by GitHub Actions as workflow commands, leading to the execution of arbitrary commands within the workflow run context.

**Impact:**
Arbitrary command execution in the user's GitHub Actions environment, potentially leading to compromise of their Azure environment, data exfiltration, or other malicious activities.

**Vulnerability Rank:**
Critical

**Currently implemented mitigations:**
None mentioned in the provided reasoning. The reasoning states that `prompt_not_empty` is used, which prevents empty input but does not sanitize against malicious characters.

**Missing mitigations:**
Input sanitization and escaping of user-provided values before placing them into YAML workflow templates. Specifically, values obtained from `prompt_not_empty` should be properly escaped to prevent YAML injection.

**Preconditions:**
An attacker needs to be able to trigger the workflow generation process and provide malicious input during user prompts, especially when prompted for resource names.

**Source code analysis:**
(Hypothetical, assuming Python/Node.js and template-based generation)
1. The extension uses templates (e.g., `DEPLOY_TO_AKS_TEMPLATE`) for GitHub Actions workflows.
2. Placeholders in these templates are replaced with values obtained from Azure CLI commands or user prompts using functions like `prompt_not_empty`.
3. The `prompt_not_empty` function likely takes a prompt message and returns user input without any sanitization or escaping.
4. This unsanitized user input is directly substituted into the YAML template.
5. If a user provides input containing YAML special characters and workflow commands (e.g., `rg-name\nsteps:\n- run: malicious command`), this will be injected into the generated YAML file.
6. When GitHub Actions parses and executes this workflow, the injected steps will be executed as part of the workflow run, leading to command execution.

**Security test case:**
1. Set up a test environment where you can run the Azure CLI extension and generate GitHub Actions workflows.
2. When prompted to provide a resource name (e.g., resource group name), enter a malicious YAML payload: `rg-name\nsteps:\n- run: echo 'Vulnerable!' > vulnerable.txt`.
3. Generate the GitHub Actions workflow using the extension with this malicious input.
4. Commit and push the generated workflow file to a GitHub repository.
5. Trigger a workflow run in the GitHub repository.
6. Check the workflow run logs and the repository files. If the file `vulnerable.txt` is created with the content 'Vulnerable!', it confirms that the injected YAML step was executed, demonstrating YAML Injection leading to Workflow Command Injection.