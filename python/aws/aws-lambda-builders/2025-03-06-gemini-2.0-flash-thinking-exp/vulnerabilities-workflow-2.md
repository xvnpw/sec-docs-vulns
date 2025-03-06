## Combined Vulnerability List

### Command Injection in Custom Makefile Workflow

- Description:
    1. An attacker can inject arbitrary commands into the system by exploiting the custom Makefile workflow in `aws-lambda-builders`. This can be achieved in two primary ways:
        - **Malicious Makefile Content:** The attacker crafts a malicious `Makefile` containing arbitrary commands within target definitions.
        - **Malicious Makefile Target Name:** The attacker crafts a malicious `Makefile` where the target name itself is designed to inject commands, leveraging the `build_logical_id` parameter.
    2. The user utilizes the `aws-lambda-builders` library with the custom Makefile workflow, specifying the path to the malicious `Makefile` as `manifest_path` and providing a `build_logical_id`. This can occur directly or indirectly, such as when using `sam build` with a `provided` runtime and a Makefile in the project.
    3. When `LambdaBuilder.build` is executed, the `CustomMakeWorkflow` is triggered, and subsequently, the `CustomMakeAction` is invoked.
    4. The `CustomMakeAction` executes the `make` command using `subprocess_make.run`.
    5. The `make` command is constructed using arguments directly derived from user-controlled inputs: the path to the `Makefile` (`self.manifest_path`) and the target name, which is dynamically generated using the `build_logical_id` (e.g., `build-{logical_id}`).
    6. Due to the lack of input sanitization, if the attacker controls the content of the Makefile or crafts a malicious `build_logical_id`, they can inject arbitrary commands. The `make` utility processes the malicious `Makefile` and executes the attacker-injected commands on the user's system.

- Impact:
    - **Arbitrary command execution** on the user's system or build environment running `aws-lambda-builders`.
    - **Full system compromise** is possible if the attacker crafts a sophisticated payload, potentially leading to complete control over the build machine.
    - **Confidentiality, Integrity, and Availability** of the user's system and potentially AWS credentials can be severely impacted, allowing for sensitive data exfiltration, malware installation, and disruption of services.
    - **Compromised Build Artifacts**: Malicious code can be injected into the Lambda function's deployment package.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - None. There is **no input validation or sanitization** implemented for the `Makefile` content, the `build_logical_id`, or any other inputs that are used to construct or execute the `make` command within the `aws-lambda-builders` project code. The execution of `make` is performed directly without any security measures to restrict its capabilities.

- Missing Mitigations:
    - **Input Sanitization**: Implement robust input validation and sanitization for the `build_logical_id` and the `Makefile` content to prevent the injection of malicious commands. This could involve allowlisting safe characters or encoding potentially harmful characters.
    - **Command Filtering/Sandboxing**: Restrict the commands that can be executed within the Makefile or, ideally, execute the `make` process within a sandboxed or isolated environment with heavily restricted privileges. This would limit the impact of command injection vulnerabilities by preventing access to sensitive system resources.
    - **Security Auditing**: Conduct regular security audits of the custom Makefile workflow functionality to identify and address potential vulnerabilities proactively.
    - **Principle of Least Privilege**: Avoid running the `make` process with elevated privileges. Ensure the process runs with the minimum necessary permissions to reduce the potential damage from command injection.
    - **User Warnings and Documentation**: Display a clear warning to users about the security risks of using custom Makefiles, especially from untrusted sources. Enhance documentation to emphasize the importance of reviewing and controlling the contents of Makefiles and best practices for secure dependency management.

- Preconditions:
    - The user must utilize the `aws-lambda-builders` library and choose the custom Makefile workflow for building Lambda functions, typically by using a `provided` runtime.
    - An attacker must be able to provide a malicious `Makefile` to the user, or compromise an existing `Makefile` within the user's project. This could be achieved by:
        - Convincing the user to download and use a compromised project or template.
        - Compromising the source code repository of a Lambda function project.
        - Supply chain attacks.
        - Social engineering.
    - The user must execute `aws-lambda-builders` with the malicious Makefile, either directly or indirectly via tools like `sam build`.

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
                            "build-{logical_id}".format(logical_id=self.build_logical_id), # VULNERABILITY
                        ],
                        env=current_env,
                        cwd=self.working_directory,
                    )
                except MakeExecutionError as ex:
                    raise ActionFailedError(str(ex))
        ```
        - **Vulnerable Code:** The `CustomMakeAction.execute` method in `aws_lambda_builders/workflows/custom_make/actions.py` is vulnerable.
        - **Unsanitized Input:** The code directly constructs the `make` command by embedding the `build_logical_id` into the target name without any sanitization. The `build_logical_id` is derived from user input via the `options` parameter, which can be controlled by an attacker.
        - **Command Construction:** The `make` command arguments are created using f-string formatting, directly inserting `self.manifest_path` (user-provided Makefile path) and `self.build_logical_id` (user-provided target name) into the command list.
        - **No Validation:** There is no input validation or sanitization performed on either `self.manifest_path` or `self.build_logical_id` before they are used in the `make` command.

    - File: `/code/aws_lambda_builders/workflows/custom_make/make.py`
        ```python
        class SubProcessMake(object):
            ...
            def run(self, args, env=None, cwd=None):
                ...
                invoke_make = [self.make_exe] + args
                ...
                p = self.osutils.popen(invoke_make, stdout=self.osutils.pipe, stderr=self.osutils.pipe, cwd=cwd, env=env) # VULNERABILITY
                ...
        ```
        - **Vulnerable Code:** The `SubProcessMake.run` method in `aws_lambda_builders/workflows/custom_make/make.py` is also vulnerable.
        - **Direct Execution:** The `SubProcessMake.run` method uses `self.osutils.popen` to execute the `make` command.
        - **Unsafe Execution:** The `popen` method directly executes the constructed command `invoke_make` without any sandboxing, command filtering, or input validation on the command arguments. This allows any commands injected through the Makefile or `build_logical_id` to be executed by the system shell.

- Security Test Case:
    **Test Case 1: Malicious Makefile Content Injection**
    1. Create a file named `malicious_makefile` with the following content:
        ```makefile
        build-test_function:
            touch /tmp/pwned_content_injection
        ```
    2. Create a temporary directory, e.g., `/tmp/test_vulnerability_content`.
    3. Save the `malicious_makefile` inside `/tmp/test_vulnerability_content`.
    4. Execute the following Python code:
        ```python
        import tempfile
        from aws_lambda_builders.builder import LambdaBuilder
        import os
        import shutil

        source_dir = "/tmp/test_vulnerability_content"
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
            if os.path.exists("/tmp/pwned_content_injection"):
                print("Vulnerability confirmed (Content Injection): /tmp/pwned_content_injection file created.")
                os.remove("/tmp/pwned_content_injection")
            else:
                print("Vulnerability check failed (Content Injection): /tmp/pwned_content_injection file not found.")

            shutil.rmtree(artifacts_dir)
            shutil.rmtree(scratch_dir)
            shutil.rmtree(source_dir)
        ```
    5. Run the Python script.
    6. Check the output. If "Vulnerability confirmed (Content Injection): /tmp/pwned_content_injection file created." is printed, the command injection vulnerability via malicious Makefile content is validated.

    **Test Case 2: Malicious Makefile Target Name Injection**
    1. Create a malicious Makefile (e.g., `malicious_makefile_target`) with the following content:
        ```makefile
        build-HelloWorldFunction;touch /tmp/pwned_target_injection::
            @echo "Malicious Makefile Executed"
        ```
    2. Create a temporary directory, e.g., `/tmp/test_vulnerability_target`.
    3. Save the `malicious_makefile_target` inside `/tmp/test_vulnerability_target`.
    4. Execute the following Python code:
        ```python
        import tempfile
        from aws_lambda_builders.builder import LambdaBuilder
        import os
        import shutil

        source_dir = "/tmp/test_vulnerability_target"
        artifacts_dir = tempfile.mkdtemp()
        scratch_dir = tempfile.mkdtemp()
        manifest_path = os.path.join(source_dir, "malicious_makefile_target")

        builder = LambdaBuilder(language="provided", dependency_manager=None, application_framework=None)

        try:
            builder.build(
                source_dir,
                artifacts_dir,
                scratch_dir,
                manifest_path,
                runtime="provided",
                options={"build_logical_id": "HelloWorldFunction;touch /tmp/pwned_target_injection"},
            )
        except Exception as e:
            print(f"Build failed as expected or encountered an error: {e}")
        finally:
            if os.path.exists("/tmp/pwned_target_injection"):
                print("Vulnerability confirmed (Target Injection): /tmp/pwned_target_injection file created.")
                os.remove("/tmp/pwned_target_injection")
            else:
                print("Vulnerability check failed (Target Injection): /tmp/pwned_target_injection file not found.")

            shutil.rmtree(artifacts_dir)
            shutil.rmtree(scratch_dir)
            shutil.rmtree(source_dir)
        ```
    5. Run the Python script.
    6. Check the output. If "Vulnerability confirmed (Target Injection): /tmp/pwned_target_injection file created." is printed, the command injection vulnerability via malicious Makefile target name is validated.

### Potential Code Injection in Dependency Management via Manifest Files

- Description:
    1. Several workflows within `aws-lambda-builders` rely on manifest files (e.g., `requirements.txt`, `package.json`, `pom.xml`, `build.gradle`, `Gemfile`, `*.csproj`, `Cargo.toml`, `go.mod`) to manage dependencies.
    2. These manifest files, while designed for dependency specification, can potentially be manipulated to execute arbitrary code during the dependency resolution process.
    3. Attack vectors vary depending on the package manager. Examples include:
        - **Python (pip/requirements.txt):** Specifying direct URLs to packages, potentially pointing to malicious packages hosted on compromised servers or attacker-controlled locations. Malicious packages can execute code during installation through `setup.py`.
        - **Node.js (npm/package.json):** Utilizing lifecycle scripts like `preinstall`, `postinstall`, which are automatically executed by `npm install` and can contain arbitrary commands. Similar mechanisms may exist in other package managers.
    4. If an attacker can influence the content of these manifest files (e.g., through repository compromise, supply chain attacks), they can inject malicious code that executes during the dependency installation phase of the build process.

- Impact:
    - **Arbitrary code execution** during the dependency resolution phase of the build process.
    - **Compromised Dependencies**: Malicious or backdoored dependencies can be introduced into the Lambda function's deployment package, potentially leading to runtime compromise of the Lambda function.
    - **Build Environment Compromise**: Similar to Makefile injection, the build environment can be compromised, enabling data exfiltration (secrets, environment variables, source code), persistent backdoors, or denial of service.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - **Limited Validation**: Some workflows may perform basic validation of manifest file syntax. However, this validation is unlikely to prevent sophisticated code injection attempts, particularly those leveraging package manager features.
    - **Dependency Download Integrity (Implicit)**: Package managers like `pip`, `npm`, `maven`, `gradle`, `bundler`, and `cargo` usually implement mechanisms to verify the integrity of downloaded packages from official repositories (e.g., checksums, signatures). This provides some protection against certain supply chain attacks but does not prevent all injection scenarios, especially those exploiting package manager features for code execution.

- Missing Mitigations:
    - **Manifest File Sanitization**: Implement robust parsing and validation of manifest files to detect and prevent potentially malicious entries. This includes detecting direct URLs, script execution directives, and other code injection vectors specific to each package manager's manifest format.
    - **Dependency Source Verification**: Enforce the use of trusted dependency sources (e.g., official package repositories). Implement mechanisms to verify the integrity and authenticity of downloaded packages, such as enforcing checksum/signature verification and potentially integrating with dependency scanning tools to detect known malicious packages.
    - **Sandboxed Dependency Resolution**: Isolate the dependency resolution process in a sandboxed or containerized environment with limited privileges to restrict the potential impact of malicious code execution during dependency installation. This would prevent malicious scripts from accessing sensitive system resources or exfiltrating data.
    - **User Warnings and Best Practices**: Improve documentation to explicitly warn users about the risks of using manifest files from untrusted sources or repositories. Recommend best practices for secure dependency management, such as using dependency lock files (e.g., `requirements.txt.lock`, `package-lock.json`), regularly auditing dependencies for vulnerabilities, and using private package repositories for better control over dependency sources.

- Preconditions:
    - The user must be using a runtime and workflow that relies on a manifest file for dependency management (Python, NodeJS, Java, Ruby, Dotnet, Rust, Go).
    - A manifest file (e.g., `requirements.txt`, `package.json`, `pom.xml`, `build.gradle`, `Gemfile`, `*.csproj`, `Cargo.toml`, `go.mod`) must be present in the source directory or provided as the manifest path.
    - An attacker must gain the ability to modify the manifest file. This can be achieved through similar means as described for Makefile injection: repository compromise, supply chain attacks, or social engineering.

- Source Code Analysis:
    - **PythonPipWorkflow Example:**
        - File: `/code/aws_lambda_builders/workflows/python_pip/workflow.py` and `/code/aws_lambda_builders/workflows/python_pip/packager.py`
        - Analysis: Review the parsing logic for `requirements.txt` in `PythonPipWorkflow`. Examine how `pip` is invoked in `PipRunner` and `DependencyBuilder`. Check for any sanitization of dependency specifications in `requirements.txt` to prevent code injection via URLs or other malicious entries. Specifically, analyze if direct URLs to packages are permitted and if there's any validation of these URLs or the packages downloaded from them.

    - **NodejsNpmWorkflow Example:**
        - File: `/code/aws_lambda_builders/workflows/nodejs_npm/actions.py` and `/code/aws_lambda_builders/workflows/nodejs_npm/npm.py`
        - Analysis: Examine the `NodejsNpmWorkflow` and `NpmPackager` for how `package.json` is processed and how `npm install` is executed. Investigate if the workflow parses and handles lifecycle scripts (`preinstall`, `postinstall`, etc.) defined in `package.json`. Determine if there are any safeguards to prevent execution of malicious scripts during the `npm install` process.

    - **General Analysis:** For each workflow relying on manifest files, the source code analysis should focus on:
        - How the manifest file is parsed and processed.
        - How the respective package manager is invoked (e.g., `pip`, `npm`, `mvn`, `gradle`, `bundle`, `dotnet`, `cargo`, `go`).
        - Whether there's any validation or sanitization of manifest file entries or package specifications.
        - If lifecycle scripts or similar code execution mechanisms are supported by the package manager and how they are handled within the workflow.

- Security Test Case:
    - **PythonPipWorkflow - Malicious Package URL Injection (Example):**
        1. Create a Python Lambda function project.
        2. Create a malicious Python package. This package should contain a `setup.py` script that executes arbitrary commands (e.g., creates a file in `/tmp`) during installation. Host this malicious package at a reachable URL (e.g., using a simple HTTP server).
        3. Modify the `requirements.txt` file in the Lambda project to include a direct URL to the malicious package:
            ```
            -e <URL_TO_MALICIOUS_PACKAGE>
            ```
        4. Run `sam build` or directly call Lambda Builders CLI to build the project.
        5. Monitor the build process for signs of malicious code execution (e.g., check if the file in `/tmp` was created).
        6. If malicious code execution is observed, it confirms the code injection vulnerability via `requirements.txt`.

    - **NodejsNpmWorkflow - Malicious `postinstall` Script Injection (Example):**
        1. Create a Node.js Lambda function project.
        2. Modify the `package.json` file to include a malicious `postinstall` script:
            ```json
            {
              "name": "test-lambda",
              "version": "1.0.0",
              "description": "",
              "main": "index.js",
              "scripts": {
                "postinstall": "touch /tmp/pwned_npm_postinstall"
              },
              "author": "",
              "license": "ISC"
            }
            ```
        3. Run `sam build` or directly call Lambda Builders CLI to build the project.
        4. After the build process completes, check if the file `/tmp/pwned_npm_postinstall` exists.
        5. If the file exists, it confirms that the malicious `postinstall` script was executed during `npm install`, demonstrating the code injection vulnerability via `package.json`.

No vulnerabilities found