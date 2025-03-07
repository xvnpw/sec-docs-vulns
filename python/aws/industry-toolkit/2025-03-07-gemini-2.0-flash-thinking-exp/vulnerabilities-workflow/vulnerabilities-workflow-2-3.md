### Vulnerability List

- Vulnerability Name: Command Injection in OpenAPI Generator CLI via `additional-properties`
- Description:
    - An attacker can inject malicious commands into the `service.json` payload by manipulating the `config` section within the `openapi` or `openapi-gen` definition.
    - This `config` section is intended to pass additional configuration properties to the OpenAPI Generator CLI tool.
    - The `Industry Toolkit` uses `openapi-generator-cli` to generate server-side code based on OpenAPI specifications.
    - The values from the `config` are passed to the `--additional-properties` flag of the `openapi-generator-cli` command without proper sanitization.
    - When the Service Bootstrapper Lambda function processes the `service.json`, it constructs a command to execute `openapi-generator-cli` using these unsanitized `additional-properties`.
    - By crafting a malicious `service.json` with a specially crafted `config` value, an attacker can inject arbitrary commands that will be executed by the `openapi-generator-cli` process within the CodeBuild environment.
    - This can lead to arbitrary code execution within the CodeBuild environment, potentially compromising the AWS account.
- Impact:
    - **High Impact:** An attacker can gain arbitrary code execution within the AWS CodeBuild environment.
    - This could allow the attacker to:
        - Steal AWS credentials used by the CodeBuild service.
        - Modify the generated code to include backdoors or malware.
        - Access and modify other AWS resources accessible by the CodeBuild role.
        - Disrupt the CI/CD pipeline and the service creation process.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None. The code directly passes the `config` values to the `openapi-generator-cli` command without any sanitization or validation.
- Missing Mitigations:
    - **Input Sanitization:** Sanitize or validate the values provided in the `config` section of the `service.json` before passing them to the `openapi-generator-cli`.
    - **Restrict `additional-properties` Usage:** Avoid using `--additional-properties` or carefully control which properties are allowed and how they are used in the code generation process. Consider using a safer mechanism to pass configuration to the generator.
    - **Principle of Least Privilege:** Ensure the CodeBuild role has the minimum necessary permissions to perform its tasks, limiting the impact of potential command injection.
- Preconditions:
    - An attacker needs to be able to invoke the API endpoint that triggers the Service Bootstrapper Lambda function. This API is publicly accessible as part of the deployed Industry Toolkit.
    - The attacker needs to understand the structure of the `service.json` payload and the role of the `config` section.
- Source Code Analysis:
    - **File: `/code/toolkit-service-lambda/codegen/open_api_codegen.py` and `/code/toolkit-service-lambda/codegen/open_api_genai_codegen.py`**
        - Both `OpenApiCodegen` and `OpenApiGenAiCodegen` classes in `generate_project` function construct the command to execute `openapi-generator-cli`.
        - They retrieve the `config` dictionary from `service_info["openapi"].get("config", {})` or `service_info["openapi-gen"].get("config", {})`.
        - The code then iterates through the `config` dictionary and formats it as a comma-separated string for `--additional-properties` flag: `",".join(f"{k}={v}" for k, v in config.items())`.
        - This string is directly embedded into the `openapi-generator-cli generate` command within `subprocess.run()`.
        - **Vulnerable Code Snippet (from both files):**
        ```python
        command = [
            "java",
            "-jar",
            "/opt/openapi-generator-cli.jar",
            "generate",
            "-i", model_location,
            "-g", service_type,
            "-o", app_dir,
            "--additional-properties", ",".join(f"{k}={v}" for k, v in config.items()) # Vulnerability: Unsanitized input
        ]
        subprocess.run(command, check=True, capture_output=True, text=True)
        ```
        - **Visualization of Data Flow:**
        ```
        service.json (config section) -->  lambda_handler (handler.py) --> process_service_creation (handler.py) -->
        OpenApiCodegen/OpenApiGenAiCodegen.generate_project --> subprocess.run (with unsanitized config in --additional-properties)
        --> openapi-generator-cli (command injection) --> CodeBuild Environment Compromise
        ```
- Security Test Case:
    1. **Prerequisites:**
        - Deploy the Industry Toolkit stack using CDK.
        - Obtain the API Gateway endpoint URL from the stack output (`IndustryToolkitApiEndpoint95A31E07`).
    2. **Craft Malicious `service.json` Payload:**
        - Create a `service.json` file with a malicious `config` section in the `openapi` definition.
        - Inject a command within one of the `config` values that will be executed by the shell when `openapi-generator-cli` processes the `--additional-properties`.
        - Example `service.json` payload:
        ```json
        {
          "service": {
            "type": "spring",
            "name": "malicious-service",
            "description": "Malicious Service to test command injection",
            "openapi": {
              "model": "https://raw.githubusercontent.com/aws-samples/industry-reference-models/refs/heads/main/domains/retail/models/cart/model/cart.openapi.yaml",
              "config": {
                "basePackage": "com.example.malicious",
                "modelPackage": "com.example.malicious.model",
                "apiPackage": "com.example.malicious.api",
                "invokerPackage": "com.example.malicious.configuration",
                "groupId": "com.example.malicious",
                "artifactId": "malicious-service",
                "exploit": "$(touch /tmp/pwned)"  // Malicious command injection attempt
              }
            }
          },
          "scm": {
            "github": {
              "repo": "https://github.com/user/repo", // Replace with a dummy repo URL
              "secretKey": "my-key",
              "email": "none@none.com",
              "name": "Robot"
            }
          },
          "iac": {
            "cloudformation": {
              "vpc": "vpc-xxxxxxxx", // Replace with a valid VPC ID
              "subnets": "subnet-xxxxxxx,subnet-xxxxxxx" // Replace with valid subnet IDs
            }
          }
        }
        ```
    3. **Invoke the API Endpoint:**
        - Use `curl` or `aws apigateway invoke-endpoint` to send a POST request to the API Gateway endpoint with the malicious `service.json` payload.
        ```bash
        curl -X POST -H "Content-Type: application/json" -d @service.json <API_GATEWAY_ENDPOINT>/services
        ```
        - Replace `<API_GATEWAY_ENDPOINT>` with the actual API Gateway endpoint URL from the stack output.
    4. **Check for Command Execution in CodeBuild:**
        - Monitor the AWS CodeBuild logs for the project triggered by the API call.
        - In the CodeBuild logs, look for evidence that the injected command `touch /tmp/pwned` was executed. You might need to adjust the injected command to something that leaves a more visible trace in the logs or output.
        - Alternatively, check if the file `/tmp/pwned` was created within the CodeBuild environment (though direct filesystem access might be limited). A safer approach is to use commands that output to stdout/stderr which will be captured in CodeBuild logs, e.g., `$(whoami)` or `$(ls -al /tmp)`.
    5. **Expected Result:**
        - The CodeBuild logs should show that the injected command was executed as part of the `openapi-generator-cli` command execution.
        - This confirms the command injection vulnerability.

This vulnerability allows for arbitrary command execution in the CodeBuild environment, posing a significant security risk. Immediate mitigation is strongly recommended by sanitizing or validating the `config` input before passing it to `openapi-generator-cli`.