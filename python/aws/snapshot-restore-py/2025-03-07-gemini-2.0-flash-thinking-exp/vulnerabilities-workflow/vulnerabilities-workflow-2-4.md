### Vulnerability List:

- Vulnerability name: Unrestricted Hook Registration leading to Arbitrary Code Execution
- Description:
    1. An attacker compromises the AWS Lambda function's deployment package or source code.
    2. The attacker modifies the Lambda function's code to import the `snapshot_restore_py` library.
    3. The attacker crafts a malicious Python function containing arbitrary code to be executed.
    4. The attacker uses `register_before_snapshot` or `register_after_restore` functions from the `snapshot_restore_py` library to register their malicious function as a runtime hook. This can be done either using the function calls directly or via decorators.
    5. When a snapshot is taken or restored for the Lambda function, the AWS Lambda runtime environment will retrieve the registered hooks using `get_before_snapshot` or `get_after_restore` functions from the `snapshot_restore_py` library.
    6. The Lambda runtime environment will then execute all registered hook functions, including the attacker's malicious function.
    7. The attacker's arbitrary code is executed within the Lambda execution environment during the SnapStart lifecycle event (before snapshot or after restore).
- Impact:
    - Arbitrary code execution within the AWS Lambda environment.
    - Potential data exfiltration, modification, or deletion.
    - Privilege escalation within the Lambda execution environment.
    - Service disruption or denial of service.
    - Compromise of other AWS resources accessible by the Lambda function's execution role.
- Vulnerability rank: Critical
- Currently implemented mitigations:
    - None. The library itself does not implement any input validation, sanitization, or authorization mechanisms to restrict the functions that can be registered as hooks. It blindly registers and returns any callable provided by the user.
- Missing mitigations:
    - Input validation: The library should validate the type and potentially the source of the functions being registered as hooks. For example, it could restrict registration to functions defined within specific modules or namespaces.
    - Sandboxing or isolation: If possible, the execution of hook functions could be sandboxed or isolated to limit the impact of malicious code. However, this might be complex to implement within the Python Lambda runtime environment.
    - Principle of least privilege:  Users should be strongly advised to adhere to the principle of least privilege when configuring their Lambda functions and execution roles to minimize the potential impact of arbitrary code execution.
    - Documentation: While not a direct mitigation, clear documentation emphasizing the security implications of registering hooks and best practices for secure hook implementation is crucial. This includes warning against registering untrusted or dynamically generated functions.
- Preconditions:
    - The attacker must have the ability to modify the AWS Lambda function's code. This could be achieved through various means, such as:
        - Compromising the CI/CD pipeline used to deploy the Lambda function.
        - Obtaining access to the source code repository and pushing malicious changes.
        - Directly modifying the Lambda function's deployment package if access controls are weak.
    - The Lambda function must be configured to use SnapStart and import and use the `snapshot_restore_py` library.
- Source code analysis:
    1. The `snapshot_restore_py.py` file defines two lists: `_before_snapshot_registry` and `_after_restore_registry`. These lists are used to store registered hook functions for 'before snapshot' and 'after restore' events respectively.
    ```python
    _before_snapshot_registry: list[Callable[..., Any]] = []
    _after_restore_registry: list[Callable[..., Any]] = []
    ```
    2. The `register_before_snapshot` and `register_after_restore` functions are responsible for adding functions to these registries. These functions accept a callable `func` and optional `*args` and `**kwargs`. They append a tuple `(func, args, kwargs)` to the corresponding registry list.
    ```python
    def register_before_snapshot(func: Callable[..., Any], *args: Any, **kwargs: Any) -> Callable[..., Any]:
        _before_snapshot_registry.append((func, args, kwargs))
        return func

    def register_after_restore(func: Callable[..., Any], *args: Any, **kwargs: Any) -> Callable[..., Any]:
        _after_restore_registry.append((func, args, kwargs))
        return func
    ```
    3. The `get_before_snapshot` and `get_after_restore` functions simply return the entire registry lists.
    ```python
    def get_before_snapshot() -> list[Callable[..., Any]]:
        return _before_snapshot_registry

    def get_after_restore() -> list[Callable[..., Any]]:
        return _after_restore_registry
    ```
    4. There is no validation or sanitization in the `register_before_snapshot` and `register_after_restore` functions. Any callable passed to these functions will be registered.
    5. When the Lambda runtime executes the hooks, it will retrieve these lists using `get_before_snapshot` or `get_after_restore` and execute each function in the list. If an attacker registers a malicious function, it will be executed without any checks.

- Security test case:
    1. Create a new AWS Lambda function in Python and enable SnapStart for it.
    2. Include the `snapshot_restore_py` library in your deployment package (for local testing, as it's pre-installed in the runtime).
    3. Modify the `lambda_function.py` to include the following malicious hook registration:
    ```python
    from snapshot_restore_py import register_before_snapshot
    import os

    def malicious_code():
        # Example malicious action: create a file in /tmp directory
        open("/tmp/pwned.txt", "w").write("You have been PWNED!")
        print("Malicious code executed!")

    register_before_snapshot(malicious_code)

    def lambda_handler(event, context):
        return {
            'statusCode': 200,
            'body': 'Hello from Lambda!'
        }
    ```
    4. Deploy this Lambda function.
    5. Invoke the Lambda function once to ensure it's initialized and a snapshot is taken upon subsequent invocations.
    6. Invoke the Lambda function again. This invocation will likely be a 'restore' from a snapshot (depending on AWS Lambda SnapStart behavior, it might take a few invocations for restore to occur).
    7. Check the Lambda function's execution logs in CloudWatch Logs. You should see the "Malicious code executed!" message printed in the logs, confirming the execution of the malicious hook.
    8. Additionally, you can check if the file `/tmp/pwned.txt` was created within the Lambda execution environment (though direct file system access might be limited in Lambda, the execution of arbitrary code is confirmed by the logs).
    9. This test case demonstrates that arbitrary Python code can be injected and executed during the SnapStart lifecycle by registering a malicious function as a hook using `snapshot_restore_py`.