- Vulnerability Name: Code Injection in Custom Make Builder via Makefile
  - Description:
    1. A threat actor with the ability to modify the `Makefile` within the source code repository or provide a malicious `Makefile` as part of a build process can inject arbitrary commands.
    2. When the Custom Make Builder workflow is invoked (e.g., via `sam build` with a 'provided' runtime and a Makefile), the `CustomMakeAction` executes the `make` command.
    3. The `make` command, as configured in the `CustomMakeAction`, directly uses the user-supplied `Makefile` without any validation or sanitization of its contents.
    4. The injected malicious code within the `Makefile` is executed by the `make` process during the build.
  - Impact: Arbitrary code execution on the build machine. This can lead to:
    - **Compromised Build Artifacts**: Malicious code can be injected into the Lambda function's deployment package.
    - **Data Exfiltration**: Secrets, environment variables, or source code can be exfiltrated from the build environment.
    - **Denial of Service**: The build process or the build machine itself can be disrupted or rendered unavailable.
  - Vulnerability Rank: Critical
  - Currently Implemented Mitigations: None. The Custom Make Builder workflow is explicitly designed to execute user-provided Makefiles, offering maximum flexibility for provided runtimes. No input validation or sandboxing is implemented for Makefiles.
  - Missing Mitigations:
    - **Input Sanitization/Validation**: Implement checks to analyze the Makefile for potentially malicious commands or patterns. However, due to the flexibility of Makefiles, complete sanitization is extremely difficult and may break legitimate use cases.
    - **Sandboxing/Isolation**: Execute the `make` process in a sandboxed or isolated environment with limited privileges to restrict the impact of malicious code execution. This would require significant changes to the current architecture.
    - **Documentation and User Awareness**: Enhance documentation to clearly warn users about the security risks associated with using the Custom Make Builder, especially when using Makefiles from untrusted sources. Emphasize the principle of least privilege and the importance of carefully reviewing and controlling the contents of Makefiles.
  - Preconditions:
    - The user must choose to use the 'provided' runtime and the Custom Make Builder workflow.
    - A `Makefile` must be present in the source directory or provided as the manifest path.
    - A threat actor must gain the ability to modify the `Makefile` (e.g., through compromising the source code repository, supply chain attack, or social engineering).
  - Source Code Analysis:
    - File: `/code/aws_lambda_builders/workflows/custom_make/actions.py`
    - Function: `CustomMakeAction.execute()`
    - Code Snippet:
      ```python
      self.subprocess_make.run(
          ["--makefile", self.manifest_path, f"build-{self.build_logical_id}"],
          env=current_env,
          cwd=self.working_directory,
      )
      ```
    - Analysis: The code directly invokes the `subprocess_make.run` method, passing the user-provided `manifest_path` (Makefile) and a dynamically constructed build target. No input validation or command sanitization is performed on the `Makefile` content before execution. The `env` parameter allows environment variables to be passed to the `make` process, which, while necessary for functionality, does not introduce a new vulnerability in this context, as the core issue is the execution of arbitrary Makefile content.
  - Security Test Case:
    1. Create a new directory named `test-custom-make-injection` and navigate into it.
    2. Create a file named `main.py` with the following content:
       ```python
       def lambda_handler(event, context):
           return "Hello from vulnerable lambda"
       ```
    3. Create a file named `Makefile` with the following content to inject a command that creates a file in `/tmp`:
       ```makefile
       build-HelloWorldFunction:
       	@echo "[VULNERABILITY-TEST] Malicious command executed"
       	@touch /tmp/pwned_lambda_builders
       	mkdir -p $(ARTIFACTS_DIR)
       	cp main.py $(ARTIFACTS_DIR)
       ```
    4. Create a dummy template file `template.yaml` (required by `sam build`) in the same directory:
       ```yaml
       Resources:
         HelloWorldFunction:
           Type: AWS::Serverless::Function
           Properties:
             Handler: main.lambda_handler
             Runtime: provided
             CodeUri: .
       ```
    5. Run `sam build --template template.yaml` from the `test-custom-make-injection` directory.
    6. After the build command completes, check if the file `/tmp/pwned_lambda_builders` exists.
    7. If the file `/tmp/pwned_lambda_builders` exists, it confirms that the malicious command injected via `Makefile` was executed during the build process, demonstrating the code injection vulnerability.

- Vulnerability Name: Potential Code Injection in Dependency Management via Manifest Files
  - Description:
    1. Several workflows (e.g., PythonPip, NodejsNpm, JavaMaven, JavaGradle, RubyBundler, DotnetCliPackage, RustCargo, GoMod) rely on manifest files (e.g., `requirements.txt`, `package.json`, `pom.xml`, `build.gradle`, `Gemfile`, `*.csproj`, `Cargo.toml`, `go.mod`) to resolve and install dependencies.
    2. These manifest files, while intended for specifying dependencies, can in some cases be manipulated to execute arbitrary code during the dependency resolution process.
    3. For example, in `requirements.txt` for `pip`, it's possible to specify direct URLs to packages, including those hosted on potentially compromised servers or pointing to malicious packages. In `package.json` for `npm`, `preinstall`, `postinstall` scripts can be defined and executed during `npm install`. Similar mechanisms might exist in other package managers.
    4. If a threat actor can influence the content of these manifest files, they might be able to inject malicious code that gets executed during the dependency installation phase of the build process.
  - Impact: Arbitrary code execution during the dependency resolution phase of the build process. This can lead to:
    - **Compromised Dependencies**: Malicious or backdoored dependencies can be introduced into the Lambda function's deployment package.
    - **Build Environment Compromise**: Similar to the Makefile vulnerability, the build environment can be compromised, leading to data exfiltration or denial of service.
  - Vulnerability Rank: High
  - Currently Implemented Mitigations:
    - **Limited Validation**: Some workflows might perform basic validation of manifest files to ensure they are in the expected format. However, this validation is unlikely to prevent sophisticated code injection attempts.
    - **Dependency Download Integrity (Implicit)**: Package managers like `pip`, `npm`, `maven`, `gradle`, `bundler`, and `cargo` usually verify checksums or signatures of downloaded packages from official repositories, which can mitigate some supply chain attacks, but not all.
  - Missing Mitigations:
    - **Manifest File Sanitization**: Implement more robust parsing and validation of manifest files to detect and prevent potentially malicious entries like direct URLs to packages, script execution directives, or other code injection vectors.
    - **Dependency Source Verification**: Enforce the use of trusted dependency sources (e.g., official package repositories) and implement mechanisms to verify the integrity and authenticity of downloaded packages (e.g., using checksums, signatures, or dependency scanning tools).
    - **Sandboxed Dependency Resolution**: Isolate the dependency resolution process in a sandboxed environment to limit the potential impact of malicious code execution during dependency installation.
    - **User Warnings**: Improve documentation to warn users about the risks of using manifest files from untrusted sources and to encourage best practices for dependency management, such as using dependency lock files and regularly auditing dependencies.
  - Preconditions:
    - The user must be using a runtime and workflow that relies on a manifest file for dependency management (Python, NodeJS, Java, Ruby, Dotnet, Rust, Go).
    - A manifest file (e.g., `requirements.txt`, `package.json`, `pom.xml`, `build.gradle`, `Gemfile`, `*.csproj`, `Cargo.toml`, `go.mod`) must be present in the source directory or provided as the manifest path.
    - A threat actor must gain the ability to modify the manifest file (e.g., through compromising the source code repository, supply chain attack, or social engineering).
  - Source Code Analysis:
    - The source code analysis would need to be performed for each workflow individually, examining how manifest files are parsed and processed. For example, for PythonPipWorkflow:
      - File: `/code/aws_lambda_builders/workflows/python_pip/workflow.py` and `/code/aws_lambda_builders/workflows/python_pip/packager.py`
      - Analysis: Examine how `requirements.txt` is parsed in `PythonPipWorkflow` and how `pip` is invoked in `PipRunner` and `DependencyBuilder`. Check if there's any sanitization of dependency specifications in `requirements.txt` to prevent code injection via URLs or other mechanisms. Similar analysis would be needed for other workflows and their respective manifest file parsing and dependency resolution logic. For example, examine `aws_lambda_builders/workflows/nodejs_npm/actions.py` and `aws_lambda_builders/workflows/nodejs_npm/npm.py` for NodeJS and NPM.
  - Security Test Case:
    - The security test case needs to be developed for each workflow and package manager separately, focusing on the specific code injection vectors relevant to each manifest file format. For example, for PythonPipWorkflow:
      1. Create a Python Lambda function project.
      2. Modify the `requirements.txt` file to include a malicious package from a URL that executes code during installation (e.g., a package with a malicious `setup.py` that runs arbitrary commands).
      3. Run `sam build` or directly call Lambda Builders CLI to build the project.
      4. Monitor the build process for signs of malicious code execution (e.g., unexpected file creation, network connections, or system modifications).
      5. If malicious code execution is observed, it confirms the code injection vulnerability via `requirements.txt`. Similar test cases would need to be crafted for other manifest file types and workflows, targeting package-manager-specific injection techniques.