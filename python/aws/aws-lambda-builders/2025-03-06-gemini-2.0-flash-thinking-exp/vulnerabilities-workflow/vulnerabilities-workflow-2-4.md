### Vulnerability List:

- Vulnerability Name: Command Injection via Makefile Target

- Description:
    1. An attacker crafts a malicious Makefile.
    2. This Makefile contains a target definition where the target name is designed to inject commands. For example, a target like `build-HelloWorldFunction; malicious_command`.
    3. The attacker provides this malicious Makefile to be used as a custom workflow.
    4. When Lambda Builders executes the Makefile, it constructs the make command by directly embedding the `build_logical_id` (which corresponds to the function name and is attacker-influenced through Makefile target naming) into the command string without proper sanitization.
    5. This allows the attacker to inject arbitrary commands into the make command, which are then executed by the system.

- Impact:
    - **Critical**: Successful command injection allows arbitrary code execution on the system running Lambda Builders. An attacker could potentially gain full control of the build environment, steal credentials, modify build artifacts, or pivot to other systems.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - None. The code directly uses the `build_logical_id` in the make command without any input validation or sanitization.

- Missing Mitigations:
    - **Input Sanitization**: The `build_logical_id` should be sanitized to prevent command injection. This could involve validating the input against a strict allowlist of characters or encoding potentially harmful characters.
    - **Command Construction**: Instead of directly embedding the `build_logical_id` into the command string, use parameterized commands or shell escaping mechanisms provided by the subprocess library to prevent injection.

- Preconditions:
    1. The attacker needs to be able to provide a custom Makefile to be used by Lambda Builders. This is possible through the "Custom Workflows" feature of Lambda Builders.
    2. The attacker needs to be able to influence the target name in the Makefile, which is derived from the function's logical ID, to inject malicious commands.

- Source Code Analysis:
    1. File: `/code/aws_lambda_builders/workflows/custom_make/actions.py`
    2. Class: `CustomMakeAction`
    3. Method: `execute`
    4. Line:
    ```python
    self.subprocess_make.run(
        ["--makefile", self.manifest_path, "build-{logical_id}".format(logical_id=self.build_logical_id)],
        env=current_env,
        cwd=self.working_directory,
    )
    ```
    5. Analysis: The `build_logical_id` is directly formatted into the make command string. If `build_logical_id` contains malicious characters, they will be interpreted as part of the command, leading to command injection. For example, if `build_logical_id` is set to `HelloWorldFunction; rm -rf /tmp/*`, the executed command becomes `make --makefile <manifest_path> build-HelloWorldFunction; rm -rf /tmp/*`, which will execute the `rm -rf /tmp/*` command after the make target.

- Security Test Case:
    1. Create a malicious Makefile (e.g., `malicious_makefile`) with the following content:
    ```makefile
    build-HelloWorldFunction;touch /tmp/pwned:
        @echo "Malicious Makefile Executed"
    ```
    2. Create a dummy source file (e.g., `main.py`).
    ```python
    def lambda_handler(event, context):
        return "Hello from Lambda"
    ```
    3. Prepare the build request JSON, setting `manifest_path` to the malicious Makefile and `build_logical_id` to `HelloWorldFunction;touch /tmp/pwned`.
    ```json
    {
      "jsonrpc": "2.0",
      "method": "LambdaBuilder.build",
      "params": {
        "__protocol_version": "0.3",
        "capability": {
          "language": "provided",
          "dependency_manager": null,
          "application_framework": null
        },
        "source_dir": "/path/to/source_dir",  // Replace with actual path
        "artifacts_dir": "/path/to/artifacts_dir", // Replace with actual path
        "scratch_dir": "/path/to/scratch_dir", // Replace with actual path
        "manifest_path": "/path/to/malicious_makefile", // Replace with actual path to malicious_makefile
        "runtime": "provided",
        "optimizations": {},
        "options": {
          "build_logical_id": "HelloWorldFunction;touch /tmp/pwned"
        }
      },
      "id": 1
    }
    ```
    4. Execute `aws-lambda-builders` with the crafted JSON request.
    5. After execution, check if the file `/tmp/pwned` exists. If it does, the command injection is successful.