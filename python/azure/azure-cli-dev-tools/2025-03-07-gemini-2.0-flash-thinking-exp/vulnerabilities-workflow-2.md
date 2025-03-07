## Combined Vulnerability List

### Command Injection via Malicious `--cli` Path in `azdev setup`

* Description:
    1. An attacker crafts a malicious directory path or archive path containing a setup.py file with malicious code.
    2. The attacker tricks a developer into running the `azdev setup` command, providing the malicious path as the value for the `--cli` argument. For example: `azdev setup --cli "/tmp/malicious_cli_path"`.
    3. The `azdev setup` tool, within the `_install_cli` function in `/code/azdev/operations/setup.py`, uses the provided `--cli` path in a `pip install -e` command without proper sanitization.
    4. `pip install -e` executes the `setup.py` file found in the malicious path.
    5. The attacker's malicious code within the `setup.py` is executed on the developer's local machine.
* Impact:
    - **Critical**. Arbitrary code execution on the developer's machine. An attacker could gain full control of the developer's system, steal credentials, or modify source code.
* Vulnerability Rank: Critical
* Currently Implemented Mitigations:
    - None. The code directly uses user-provided paths in shell commands without sanitization.
* Missing Mitigations:
    - **Input Sanitization:** Sanitize the `cli_path` argument in `azdev setup` to ensure it does not contain any malicious code or attempt to execute commands outside of intended operations. Validate that the path points to a legitimate Azure CLI repository or a safe directory.
    - **Path Validation:** Implement checks to validate that the provided path is a valid directory and potentially verify the contents of `setup.py` before executing pip install in editable mode.
    - **User Warning:** Display a clear warning message to the developer before executing `pip install -e` from a user-provided path, emphasizing the security risks and advising caution.
* Preconditions:
    - The developer must run the `azdev setup` command and be tricked into providing a malicious path for the `--cli` argument.
* Source Code Analysis:
    - File: `/code/azdev/operations/setup.py`
    - Function: `_install_cli(cli_path, deps=None)`
    ```python
    def _install_cli(cli_path, deps=None):
        # ...
        if cli_path and cli_path != 'EDGE':
            # ...
            cli_src = os.path.join(cli_path, 'src')
            if deps == 'setup.py':
                # Resolve dependencies from setup.py files.
                # command modules have dependency on azure-cli-core so install this first
                pip_cmd(
                    "install -e {}".format(os.path.join(cli_src, 'azure-cli-telemetry')), # Vulnerable code
                    "Installing `azure-cli-telemetry`..."
                )
                pip_cmd(
                    "install -e {}".format(os.path.join(cli_src, 'azure-cli-core')), # Vulnerable code
                    "Installing `azure-cli-core`..."
                )

                # azure cli has dependencies on the above packages so install this one last
                pip_cmd(
                    "install -e {}".format(os.path.join(cli_src, 'azure-cli')), # Vulnerable code
                    "Installing `azure-cli`..."
                )

                pip_cmd(
                    "install -e {}".format(os.path.join(cli_src, 'azure-cli-testsdk')), # Vulnerable code
                    "Installing `azure-cli-testsdk`..."
                )
            else:
                # First install packages without dependencies,
                # then resolve dependencies from requirements.*.txt file.
                pip_cmd(
                    "install -e {} --no-deps".format(os.path.join(cli_src, 'azure-cli-telemetry')), # Vulnerable code
                    "Installing `azure-cli-telemetry`..."
                )
                pip_cmd(
                    "install -e {} --no-deps".format(os.path.join(cli_src, 'azure-cli-core')), # Vulnerable code
                    "Installing `azure-cli-core`..."
                )

                pip_cmd(
                    "install -e {} --no-deps".format(os.path.join(cli_src, 'azure-cli')), # Vulnerable code
                    "Installing `azure-cli`..."
                )

                # The dependencies of testsdk are not in requirements.txt as this package is not needed by the
                # azure-cli package for running commands.
                # Here we need to install with dependencies for azdev test.
                pip_cmd(
                    "install -e {}".format(os.path.join(cli_src, 'azure-cli-testsdk')), # Vulnerable code
                    "Installing `azure-cli-testsdk`..."
                )
                # ...
    ```
    - The code uses `pip_cmd("install -e {}".format(...))` which executes `pip install -e` with paths constructed using `cli_path` without any sanitization. This allows command injection if `cli_path` is malicious.
* Security Test Case:
    1. Create a directory named `malicious_cli_path` in `/tmp`.
    2. Inside `/tmp/malicious_cli_path`, create a directory structure `malicious_cli_path/src/azure-cli-telemetry`.
    3. Inside `/tmp/malicious_cli_path/src/azure-cli-telemetry`, create a file `setup.py` with the following content:
    ```python
    from setuptools import setup

    setup(
        name='azure-cli-telemetry',
        version='0.1.0',
        packages=['azure_cli_telemetry'],
        entry_points={
            'console_scripts': [
                'malicious-command=azure_cli_telemetry:malicious_function',
            ],
        },
    )

    import os
    import sys

    def malicious_function():
        # Malicious payload to create a file in /tmp directory
        open('/tmp/pwned.txt', 'a').close()
        print("PWNED")

    if __name__ == '__main__':
        malicious_function()
    ```
    4. Open a terminal and navigate to the root directory of the `azdev` project.
    5. Run the command: `azdev setup --cli /tmp/malicious_cli_path`
    6. After the command completes (or fails), check if the file `/tmp/pwned.txt` exists.
    7. If `/tmp/pwned.txt` exists, the vulnerability is confirmed. The "PWNED" message should also be printed to the console output during `azdev setup`.

### Command Injection via Malicious `--repo` Path in `azdev setup`

* Description:
    1. An attacker crafts a malicious directory path or archive path containing a setup.py file with malicious code.
    2. The attacker tricks a developer into running the `azdev setup` command, providing the malicious path as the value for the `--repo` argument. For example: `azdev setup --repo "/tmp/malicious_extension_repo"`.
    3. The `azdev setup` tool, within the `_install_extensions` function in `/code/azdev/operations/setup.py`, uses the provided `--repo` path in a `pip install -e` command without proper sanitization.
    4. `pip install -e` executes the `setup.py` file found in the malicious path.
    5. The attacker's malicious code within the `setup.py` is executed on the developer's local machine.
* Impact:
    - **Critical**. Arbitrary code execution on the developer's machine. An attacker could gain full control of the developer's system, steal credentials, or modify source code.
* Vulnerability Rank: Critical
* Currently Implemented Mitigations:
    - None. The code directly uses user-provided paths in shell commands without sanitization.
* Missing Mitigations:
    - **Input Sanitization:** Sanitize the `ext_repo_path` argument in `azdev setup` to ensure it does not contain any malicious code or attempt to execute commands outside of intended operations. Validate that the path points to a legitimate Azure CLI extensions repository or a safe directory.
    - **Path Validation:** Implement checks to validate that the provided path is a valid directory and potentially verify the contents of `setup.py` before executing pip install in editable mode.
    - **User Warning:** Display a clear warning message to the developer before executing `pip install -e` from a user-provided path, emphasizing the security risks and advising caution.
* Preconditions:
    - The developer must run the `azdev setup` command and be tricked into providing a malicious path for the `--repo` argument.
* Source Code Analysis:
    - File: `/code/azdev/operations/setup.py`
    - Function: `_install_extensions(ext_paths)`
    ```python
    def _install_extensions(ext_paths):
        # ...
        # install specified extensions
        for path in ext_paths or []:
            result = pip_cmd('install -e {}'.format(path), "Adding extension '{}'...".format(path)) # Vulnerable code
            if result.error:
                raise result.error  # pylint: disable=raising-bad-type
    ```
    - The code uses `pip_cmd("install -e {}".format(path))` which executes `pip install -e` with paths constructed using `ext_paths` without any sanitization. This allows command injection if `ext_paths` is malicious.
* Security Test Case:
    1. Create a directory named `malicious_extension_repo` in `/tmp`.
    2. Inside `/tmp/malicious_extension_repo`, create a file `setup.py` with the following content:
    ```python
    from setuptools import setup

    setup(
        name='malicious-extension',
        version='0.1.0',
        packages=['malicious_extension'],
        entry_points={
            'console_scripts': [
                'malicious-ext-command=malicious_extension:malicious_function',
            ],
        },
    )

    import os
    import sys

    def malicious_function():
        # Malicious payload to create a file in /tmp directory
        open('/tmp/pwned_ext.txt', 'a').close()
        print("PWNED EXT")

    if __name__ == '__main__':
        malicious_function()
    ```
    3. Open a terminal and navigate to the root directory of the `azdev` project.
    4. Run the command: `azdev setup --repo /tmp/malicious_extension_repo`
    5. After the command completes (or fails), check if the file `/tmp/pwned_ext.txt` exists.
    6. If `/tmp/pwned_ext.txt` exists, the vulnerability is confirmed. The "PWNED EXT" message should also be printed to the console output during `azdev setup`.

### Command Injection in `azdev cli create` and `azdev extension create`

* Description:
    1. An attacker can inject malicious code into the `azdev cli create <module-name>` or `azdev extension create <extension-name>` commands by crafting a module or extension name that includes shell commands.
    2. When `azdev` processes this maliciously crafted name, it uses it in string concatenation to construct shell commands without proper sanitization.
    3. This allows the attacker's injected commands to be executed on the developer's machine with the privileges of the user running `azdev`.
* Impact:
    - **Critical**. Arbitrary code execution on the developer's machine. This could lead to data exfiltration, installation of malware, or complete system compromise.
* Vulnerability Rank: Critical
* Currently Implemented Mitigations:
    - None. The code does not implement any sanitization or validation of module/extension names against command injection attacks.
* Missing Mitigations:
    - **Input Sanitization:** Sanitize the module or extension name input to remove or escape any characters that could be interpreted as shell commands. This should be done before incorporating the name into any shell command.
    - **Parameterized Commands:** Use parameterized commands or functions that avoid direct shell interpretation of user-provided strings. For example, when using `subprocess`, pass arguments as a list to prevent shell injection when possible.
    - **Input Validation:** Implement strict validation rules for module and extension names, allowing only alphanumeric characters and specific symbols (like hyphens or underscores) and rejecting any input containing potentially dangerous characters (like backticks, semicolons, pipes, etc.).
* Preconditions:
    - The attacker needs to convince a developer to use `azdev cli create` or `azdev extension create` with a maliciously crafted module or extension name.
    - The developer must have `azdev` installed and execute the command in their terminal.
* Source Code Analysis:
    1. File: `/code/azdev/operations/code_gen.py`
    2. Function: `_create_package(prefix, repo_path, is_ext, name='test', ...)`
    3. Vulnerable Code Snippet:
        ```python
        def _create_package(prefix, repo_path, is_ext, name='test', display_name=None, display_name_plural=None,
                            required_sdk=None, client_name=None, operation_name=None, sdk_property=None,
                            not_preview=False, local_sdk=None):
            ...
            package_name = '{}{}'.format(prefix, name.replace('_', '-')) if not is_ext else name
            new_package_path = os.path.join(repo_path, package_name)
            ...
            if is_ext:
                result = pip_cmd('install -e {}'.format(new_package_path), "Installing `{}{}`...".format(prefix, name)) # Potential command injection
                if result.error:
                    raise result.error
        ```
    4. Explanation:
        - The `_create_package` function constructs the path for the new module/extension using `os.path.join` and string formatting with the user-provided `name` (which becomes `package_name`).
        - This `new_package_path` is then directly embedded into the `pip install -e {}` command string passed to `pip_cmd`.
        - If the `name` variable, derived from user input, contains malicious shell commands, these commands could be executed during the `pip install` process.

    ```mermaid
    graph LR
        A[User Input (module_name/extension_name)] --> B(package_name = '{}{}'.format(prefix, name.replace('_', '-')) if not is_ext else name)
        B --> C(new_package_path = os.path.join(repo_path, package_name))
        C --> D(pip_cmd('install -e {}'.format(new_package_path), ...))
        D --> E(subprocess.run (Shell Command Injection))
        E --> F[System Command Execution]
    ```

* Security Test Case:
    1. Open a terminal with `azdev` installed.
    2. Execute the following command to create a malicious CLI module:
    ```bash
    azdev cli create "$(touch /tmp/pwned_cli_module_creation_$(date +%s))"
    ```
    3. Check if the file `/tmp/pwned_cli_module_creation_<timestamp>` was created. If the file exists, it indicates that the `touch` command injected through the module name was successfully executed.
    4. Execute the following command to create a malicious extension:
    ```bash
    azdev extension create "$(touch /tmp/pwned_extension_creation_$(date +%s))"
    ```
    5. Check if the file `/tmp/pwned_extension_creation_<timestamp>` was created. If the file exists, it indicates that the `touch` command injected through the extension name was successfully executed.