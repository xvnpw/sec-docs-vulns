- Vulnerability Name: Code Injection in BatchCompute scala_script and Python code

- Description:
    1. An attacker can inject arbitrary code into the `scala_script` parameter of the `BatchCompute` definition or the inline Python code of `BatchCompute`.
    2. This injection point is within the `create_data` API when defining `compute_targets`.
    3. When the RheocerOS application activates and processes data through the node with the vulnerable `BatchCompute` definition, the injected code will be executed within the AWS Glue or Lambda environment.
    4. An attacker could potentially manipulate data, access AWS resources within the application's AWS account, or compromise the integrity of the AI/ML workflows.

- Impact:
    - Critical. Successful code injection allows for arbitrary code execution within the AWS environment managed by RheocerOS.
    - This can lead to data breaches, unauthorized access to AWS resources, and disruption of AI/ML workflows.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - None. The code examples in `README.md` directly use user-provided strings as `scala_script` and inline Python code without any sanitization or validation.

- Missing Mitigations:
    - Input sanitization and validation for `scala_script` and inline Python code within `BatchCompute` definitions to prevent code injection.
    - Consider using parameterized queries or prepared statements if applicable to the compute targets to further reduce injection risks.
    - Implement a secure coding review process to identify and eliminate code injection vulnerabilities.

- Preconditions:
    - An attacker needs to be able to influence the `scala_script` or inline Python code parameters within a `BatchCompute` definition.
    - In the provided examples, this influence is implicitly assumed to be through direct modification of the application code, which in a real-world scenario would translate to a threat actor gaining unauthorized access to the development or deployment pipeline of the RheocerOS application.

- Source Code Analysis:
    1. File: `/code/README.md`
    2. Look for `BatchCompute` examples, specifically those using `scala_script` and inline Python code.
    3. Example 1, Example 3, and Example 4 demonstrate the usage of `BatchCompute` with user-supplied code.
    4. Example from README.md:
    ```python
    tpdex = app.create_data(id="tpdex",
                            inputs=[...],
                            compute_targets=[
                              BatchCompute(
                                scala_script("""
                                          pdex
                                            .filter( ... )
                                            .select( ... )
                                            .distinct()
                                               """
                                         ),
                            ...
                          )
                        ])
    ```
    5. The `scala_script("""...""")` and the inline Python code in other examples are directly passed to the `BatchCompute` constructor.
    6. The framework takes this string and executes it within AWS Glue or Lambda without any sanitization.
    7. This direct execution of user-provided code is the code injection vulnerability.
    8. Visualization:
        ```
        User Input (scala_script string) --> BatchCompute Constructor --> AWS Glue/Lambda Execution (vulnerable)
                                             ^
                                             | No Sanitization/Validation
        ```

- Security Test Case:
    1. Create a RheocerOS application similar to Example 1 in `README.md`.
    2. Modify the `scala_script` parameter in the `BatchCompute` definition to include malicious code, for example:
    ```python
    scala_script("""
        // Malicious code injection to list files in the container
        import scala.sys.process._
        "ls -al /tmp/".!

        pdex
            .filter( ... )
            .select( ... )
            .distinct()
            """
        )
    ```
    3. Activate the RheocerOS application: `app.activate()`.
    4. Trigger the execution of the vulnerable node, for example using `app.process(timer_signal_daily['2021-09-20'], target_route_id=tpdex)`.
    5. Check the AWS Glue job logs (CloudWatch Logs for the Glue job run associated with `tpdex` node).
    6. Verify that the output of the `ls -al /tmp/` command (or other injected malicious code) is present in the logs, confirming code injection.
    7. For Python code injection, a similar test case can be created by modifying the inline Python code within a `BatchCompute` definition and checking AWS Lambda logs.