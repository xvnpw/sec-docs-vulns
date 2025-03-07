- Vulnerability Name: Code Injection in `@register_after_restore` Hook Function
- Description:
    - A developer uses the `@register_after_restore` decorator from the `snapshot-restore-py` library to register a hook function that executes after a Lambda function is restored from a snapshot.
    - Inside this `@register_after_restore` hook function, the developer processes input from the Lambda event without proper sanitization or validation.
    - An attacker can craft a malicious Lambda event containing code or commands.
    - When the Lambda function is invoked with this malicious event and restored from a snapshot, the `@register_after_restore` hook function processes the event data.
    - If the hook function directly executes the untrusted data from the event (e.g., using `eval()`, `exec()`, or similar unsafe functions), the attacker's code or commands will be executed within the Lambda execution environment.
- Impact:
    - Arbitrary code execution within the AWS Lambda environment.
    - Potential data exfiltration or modification.
    - Compromise of the Lambda function's role and permissions, potentially leading to further access to AWS resources.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None in the `snapshot-restore-py` library itself. The library provides the hook registration mechanism but does not enforce secure coding practices within user-defined hook functions.
- Missing Mitigations:
    - **Documentation Enhancement:** The documentation should explicitly warn against processing untrusted input within `@register_after_restore` hook functions and recommend secure coding practices, such as input validation, sanitization, and avoiding dynamic code execution.
    - **Example Hardening:** Examples should demonstrate secure ways to handle event data within hook functions, emphasizing the importance of not directly executing untrusted input.
- Preconditions:
    - The developer must use the `snapshot-restore-py` library and register an `@register_after_restore` hook function.
    - The `@register_after_restore` hook function must process input from the Lambda event.
    - The hook function must contain a code injection vulnerability, such as using `eval()` or `exec()` on untrusted event data.
    - SnapStart must be enabled for the Lambda function.
- Source Code Analysis:
    - The `snapshot_restore_py.py` file provides decorators and functions (`register_after_restore`) to register functions to be executed after Lambda restore.
    - The relevant code snippet from `snapshot_restore_py.py` is:
    ```python
    _after_restore_registry: list[Callable[..., Any]] = []

    def register_after_restore(func: Callable[..., Any], *args: Any, **kwargs: Any) -> Callable[..., Any]:
        _after_restore_registry.append((func, args, kwargs))
        return func
    ```
    - The `register_after_restore` function simply adds the user-provided function `func` and its arguments to the `_after_restore_registry`.
    - The `snapshot-restore-py` library itself does not execute the registered functions or process any event data.
    - **Vulnerability Location**: The vulnerability is not in `snapshot-restore-py` itself, but in the *user-implemented* `@register_after_restore` hook function within the Lambda handler code.
    - **Attack Vector**: An attacker exploits a vulnerable `@register_after_restore` hook by providing malicious input in the Lambda event. When the Lambda is restored and the hook executes, the malicious input is processed by the vulnerable hook function, leading to code injection.
    - **Visualization**:
        1. Developer uses `@register_after_restore` to register `vulnerable_hook`.
        2. `vulnerable_hook` is designed to process `event` data.
        3. Attacker sends malicious `event` to Lambda.
        4. Lambda is restored from snapshot.
        5. `vulnerable_hook` executes *after restore*.
        6. `vulnerable_hook` processes malicious `event` data *unsafely*.
        7. Arbitrary code execution occurs due to vulnerability in `vulnerable_hook`.

- Security Test Case:
    1. **Setup Vulnerable Lambda Function:**
        - Create a Lambda function and enable SnapStart.
        - Include `snapshot-restore-py` in the Lambda function (though it's pre-installed in runtime, for local testing, include it in dependencies).
        - Define a vulnerable `@register_after_restore` hook in the Lambda function code (e.g., `lambda_handler.py`):
        ```python
        from snapshot_restore_py import register_after_restore
        import os

        @register_after_restore
        def vulnerable_hook(event):
            unsafe_command = event['command']
            os.system(unsafe_command) # Vulnerable code: Using os.system with unsanitized input

        def lambda_handler(event, context):
            return {
                'statusCode': 200,
                'body': 'Hello from Lambda!'
            }
        ```
    2. **Deploy Lambda Function**.
    3. **Craft Malicious Event:**
        - Create a Lambda invocation event with a malicious command in the `command` field:
        ```json
        {
          "command": "whoami > /tmp/pwned.txt"
        }
        ```
    4. **Invoke Lambda Function with Malicious Event:**
        - Invoke the deployed Lambda function with the crafted malicious event.
        - Ensure the Lambda function is restored from a snapshot (invoke it after the first invocation that creates a snapshot).
    5. **Verify Code Execution:**
        - After invocation, check the `/tmp` directory within the Lambda execution environment (e.g., by adding code to the `lambda_handler` to read and return the contents of `/tmp/pwned.txt` in a subsequent invocation, or by checking Lambda logs if commands write to logs).
        - If the vulnerability is successfully exploited, the file `/tmp/pwned.txt` should exist and contain the output of the `whoami` command, confirming arbitrary command execution.
    6. **Expected Result:** The test should demonstrate that by providing a malicious event, an attacker can execute arbitrary commands within the Lambda environment via the vulnerable `@register_after_restore` hook.