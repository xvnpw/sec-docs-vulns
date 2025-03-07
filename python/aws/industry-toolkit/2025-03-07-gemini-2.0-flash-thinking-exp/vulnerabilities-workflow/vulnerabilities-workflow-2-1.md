### Vulnerability List

- Vulnerability Name: **Unsanitized OpenAPI Specification URL leading to potential Code Injection**
- Description:
    1. An attacker crafts a malicious OpenAPI specification document.
    2. The attacker hosts this malicious OpenAPI specification at a publicly accessible URL.
    3. The attacker creates a `service.json` configuration file for the Industry Toolkit.
    4. In the `service.json` file, the attacker provides the URL of the malicious OpenAPI specification in the `service.openapi.model` field.
    5. The attacker uses the Industry Toolkit to create a new service, providing the crafted `service.json` as input.
    6. The Industry Toolkit's Lambda function, `IndustryToolkitStack-industrytoolkitbootstrapper-...`, retrieves the OpenAPI specification from the attacker-controlled URL.
    7. The Lambda function then passes this URL to the OpenAPI Generator CLI tool to generate service code.
    8. If the OpenAPI Generator CLI or the code generation process is vulnerable to malicious OpenAPI specifications (e.g., through command injection, arbitrary file write, or other vulnerabilities triggered by specific OpenAPI constructs), the attacker's malicious payload can be executed during the code generation phase within the CodeBuild environment.
    9. This can lead to unauthorized code execution, potentially compromising the generated service code, build pipeline, and potentially the underlying infrastructure.
- Impact:
    - **High/Critical**: Successful exploitation can lead to arbitrary code execution within the CodeBuild environment. This could allow the attacker to:
        - Inject malicious code into the generated service codebase.
        - Steal secrets and credentials managed by the CodeBuild environment.
        - Modify the CI/CD pipeline to introduce backdoors or further compromise deployments.
        - Potentially gain access to other AWS resources accessible by the CodeBuild role.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None: The current implementation directly passes the provided OpenAPI specification URL to the OpenAPI Generator CLI without any sanitization or validation.
- Missing Mitigations:
    - **Input Validation and Sanitization**: Implement validation and sanitization of the OpenAPI specification URL to ensure it points to a trusted and expected location. Consider:
        - URL whitelisting: Allow only URLs from trusted domains or known OpenAPI specification repositories.
        - Content validation: Before passing the URL to OpenAPI Generator CLI, download and parse the OpenAPI specification to validate its structure and content against a strict schema. Check for potentially malicious or unexpected constructs within the OpenAPI specification itself.
    - **Secure Code Generation Environment**: Harden the CodeBuild environment to limit the impact of potential code injection vulnerabilities. Consider:
        - Running CodeBuild in a more isolated environment with restricted network access and minimal permissions.
        - Implementing file system integrity monitoring within the CodeBuild environment to detect unauthorized modifications.
- Preconditions:
    - The attacker needs to be able to provide a `service.json` configuration to the Industry Toolkit, typically by invoking the API Gateway endpoint of the deployed Industry Toolkit.
    - The attacker needs to host a malicious OpenAPI specification at a publicly accessible URL.
- Source Code Analysis:
    - File: `/code/toolkit-service-lambda/codegen/open_api_codegen.py`
    ```python
    import subprocess
    import os

    from codegen.codegen import Codegen


    class OpenApiCodegen(Codegen):
        def generate_project(self, project_id: str, service_info: str):
            service_type = service_info["type"]
            model_location = service_info["openapi"]["model"] # [CRITICAL]: OpenAPI model URL is taken directly from service_info without validation

            config = service_info["openapi"].get("config", {})

            app_dir = f"/tmp/{project_id}/app"
            os.makedirs(app_dir, exist_ok=True)

            model_dir = f"/tmp/{project_id}/model"
            os.makedirs(model_dir, exist_ok=True)

            model_filename = os.path.basename(model_location)

            command = [
                "java",
                "-jar",
                "/opt/openapi-generator-cli.jar",
                "generate",
                "-i", model_location, # [CRITICAL]: Malicious URL is directly passed as input to openapi-generator-cli
                "-g", service_type,
                "-o", app_dir,
                "--additional-properties", ",".join(f"{k}={v}" for k, v in config.items())
            ]

            try:
                subprocess.run(command, check=True, capture_output=True, text=True) # [CRITICAL]: subprocess.run executes the command with potentially malicious URL
                print(f"Project generated successfully at {app_dir}")
            except subprocess.CalledProcessError as e:
                print(f"Failed to generate project: {e}")
                raise RuntimeError(f"Error running OpenAPI Generator: {e.stderr}")
    ```
    - The code in `OpenApiCodegen.generate_project` directly retrieves the `model` URL from the `service_info` dictionary without any validation or sanitization.
    - This `model_location` is then directly used as the `-i` parameter in the `openapi-generator-cli generate` command executed via `subprocess.run`.
    - This allows an attacker to supply a malicious URL, which, if processed by a vulnerable OpenAPI Generator CLI, can lead to code injection or other vulnerabilities.

- Security Test Case:
    1. **Prepare Malicious OpenAPI Spec:** Create a file named `malicious-openapi.yaml` with the following content. This example attempts to create a file `/tmp/pwned` in the CodeBuild environment during code generation.
    ```yaml
    openapi: 3.0.0
    info:
      title: Malicious API
      version: 1.0.0
    servers:
      - url: http://example.com
    paths:
      /pwned:
        get:
          summary: Triggers malicious command
          operationId: pwnedOperation
          x-codegen-post-process-file: "os.system('touch /tmp/pwned')" # [MALICIOUS]: Attempts to execute system command
          responses:
            '200':
              description: Success
    ```
    2. **Host Malicious Spec:** Host `malicious-openapi.yaml` at a publicly accessible URL, for example, using a simple HTTP server or a service like GitHub Gist raw content URL. Let's assume the URL is `https://example.com/malicious-openapi.yaml`.
    3. **Create `service.json`:** Create a file named `service.json` with the following content, replacing `<your_github_repo_uri>` and `<your_github_pat_secret_key>` with your GitHub repository details and the secret key you configured in Secrets Manager.
    ```json
    {
      "service": {
        "type": "spring",
        "name": "malicious-service",
        "description": "Service with malicious OpenAPI spec",
        "openapi": {
          "model": "https://example.com/malicious-openapi.yaml", # [MALICIOUS]: Points to the malicious OpenAPI spec URL
          "config": {
            "basePackage": "com.example.malicious",
            "groupId": "com.example.malicious",
            "artifactId": "malicious-service"
          }
        }
      },
      "scm": {
        "github": {
          "repo": "<your_github_repo_uri>",
          "secretKey": "<your_github_pat_secret_key>",
          "email": "none@none.com",
          "name": "Attacker"
        }
      },
      "iac": {
        "cloudformation": {
          "vpc": "<your_vpc_id>",
          "subnets": "<your_subnet_id-1>,<your_subnet_id-2>"
        }
      }
    }
    ```
    4. **Deploy Industry Toolkit:** If you haven't already, deploy the Industry Toolkit stack using CDK:
    ```bash
    cd tools/industry-toolkit
    cdk deploy
    ```
    5. **Invoke Lambda Function:** Invoke the `IndustryToolkitStack-industrytoolkitbootstrapper-...` Lambda function using the AWS CLI, providing the `service.json` file as payload. Replace `IndustryToolkitStack-industrytoolkitbootstrapper-...` with the actual Lambda function name from your CloudFormation stack outputs.
    ```bash
    aws lambda invoke \
          --function-name <IndustryToolkitStack-industrytoolkitbootstrapper-FunctionName> \
          --payload file://service.json \
          --cli-binary-format raw-in-base64-out \
          /dev/stdout
    ```
    6. **Check CodeBuild Logs:** After invoking the Lambda function, a CodeBuild project should be triggered. Go to the AWS CodeBuild console, find the relevant build project (likely named `malicious-service-pipeline-build`), and examine the build logs, specifically the 'build' phase.
    7. **Verify Exploitation:** In the CodeBuild logs, check if there is any indication that the command `touch /tmp/pwned` was executed. You might need to add logging or commands in the `buildspec.yaml` (e.g., `ls -l /tmp/pwned`) to explicitly verify the file creation. If the file `/tmp/pwned` is created in the CodeBuild environment, it confirms that the malicious payload from the OpenAPI specification was executed, demonstrating the code injection vulnerability.

This test case demonstrates how a malicious OpenAPI specification URL can be used to inject code into the code generation process, highlighting the critical vulnerability due to the lack of sanitization of the OpenAPI specification URL.