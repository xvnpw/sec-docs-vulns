### Vulnerability List:

- **Vulnerability Name:** Unsafe use of `eval()` in filter callbacks

- **Description:**
    1. A user can create a Bowler query that includes a filter defined as a string.
    2. The `Query.filter()` method in `bowler/query.py` compiles this string using `compile(filter_callback, "<string>", "eval")`.
    3. When the query is executed, this compiled code is evaluated using `eval(code)` within the `callback` function in `bowler/query.py`.
    4. If a malicious user crafts a Bowler script that includes a filter string containing malicious Python code, this code will be executed with the permissions of the user running the Bowler script.

- **Impact:**
    - **High:** Arbitrary code execution. An attacker can execute any Python code on the machine running the Bowler script. This could lead to data exfiltration, system compromise, or other malicious activities.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - None. The code directly uses `eval()` on user-provided strings without any sanitization or sandboxing.

- **Missing Mitigations:**
    - **Input Sanitization:**  The filter string input should be strictly validated to ensure it does not contain potentially harmful code. However, sanitizing `eval()` input is extremely difficult and error-prone.
    - **Sandboxing/Restricted Execution Environment:** Execute the `eval()` call within a sandboxed or restricted environment with limited permissions. This would prevent malicious code from accessing sensitive resources or performing harmful actions.
    - **Discourage String-based Filters:** The documentation and API should strongly discourage the use of string-based filters and encourage users to use function callbacks instead, as these are easier to inspect and control.
    - **Static Analysis:** Implement static analysis tools to scan Bowler scripts for potentially unsafe `eval()` usage and warn users.

- **Preconditions:**
    1. The attacker needs to trick a user into running a malicious Bowler script.
    2. The malicious Bowler script must use the `Query.filter()` method with a string argument containing malicious Python code.

- **Source Code Analysis:**
    1. **File:** `/code/bowler/query.py`
    2. **Method:** `Query.filter(self, filter_callback: Union[str, Filter]) -> "Query"`
    3. **Code Snippet:**
    ```python
    def filter(self, filter_callback: Union[str, Filter]) -> "Query":
        if isinstance(filter_callback, str):
            code = compile(filter_callback, "<string>", "eval")

            def callback(node: Node, capture: Capture, filename: Filename) -> bool:
                return bool(eval(code))  # noqa: developer tool

        filter_callback = cast(Filter, filter_callback)
        self.current.filters.append(filter_callback)
        return self
    ```
    4. **Step-by-step vulnerability trigger:**
        - The `Query.filter()` method checks if `filter_callback` is a string.
        - If it is a string, it compiles it using `compile(filter_callback, "<string>", "eval")`. The compilation context is set to `'eval'`, indicating that the code is intended for evaluation.
        - A new `callback` function is defined, which, when executed, will `eval(code)`. This means the compiled code is executed using the `eval()` function.
        - The malicious code embedded in the `filter_callback` string will be executed when this `callback` function is invoked during query execution.

- **Security Test Case:**
    1. **Create a malicious Bowler script (e.g., `malicious_script.py`):**
    ```python
    from bowler import Query
    import os

    malicious_code = """
    import os
    os.system('touch /tmp/pwned')
    """

    Query('.') \
        .select_root() \
        .filter(malicious_code) \
        .write() # or .diff() or any other action
    ```
    2. **Run the malicious script:**
    ```bash
    bowler run malicious_script.py -- .
    ```
    3. **Verify the impact:**
        - After running the script, check if the file `/tmp/pwned` has been created. If it exists, it demonstrates that the `os.system('touch /tmp/pwned')` command within the filter string was executed, confirming arbitrary code execution.
        - In a real attack scenario, the malicious code could be far more harmful than simply creating a file.

- **Vulnerability Name:** Unsafe use of `exec()` in modifier callbacks

- **Description:**
    1. A user can create a Bowler query that includes a modifier defined as a string.
    2. The `Query.modify()` method in `bowler/query.py` compiles this string using `compile(callback, "<string>", "exec")`.
    3. When the query is executed, this compiled code is executed using `exec(code)` within the `callback` function in `bowler/query.py`.
    4. If a malicious user crafts a Bowler script that includes a modifier string containing malicious Python code, this code will be executed with the permissions of the user running the Bowler script.

- **Impact:**
    - **Critical:** Arbitrary code execution. An attacker can execute any Python code on the machine running the Bowler script. This could lead to complete system compromise, data breaches, or denial of service.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - None. The code directly uses `exec()` on user-provided strings without any sanitization or sandboxing.

- **Missing Mitigations:**
    - **Input Sanitization:** The modifier string input should be strictly validated. However, sanitizing `exec()` input is nearly impossible to do reliably.
    - **Sandboxing/Restricted Execution Environment:** Execute the `exec()` call within a heavily sandboxed environment. This is complex but essential for mitigating the risk.
    - **Discourage String-based Modifiers:** Strongly discourage string-based modifiers in documentation and API. Promote function callbacks as the secure alternative.
    - **Static Analysis:** Implement static analysis to detect and warn about `exec()` usage in Bowler scripts.

- **Preconditions:**
    1. The attacker needs to trick a user into running a malicious Bowler script.
    2. The malicious Bowler script must use the `Query.modify()` method with a string argument containing malicious Python code.

- **Source Code Analysis:**
    1. **File:** `/code/bowler/query.py`
    2. **Method:** `Query.modify(self, callback: Union[str, Callback]) -> "Query"`
    3. **Code Snippet:**
    ```python
    def modify(self, callback: Union[str, Callback]) -> "Query":
        if isinstance(callback, str):
            code = compile(callback, "<string>", "exec")

            def callback(node: Node, capture: Capture, filename: Filename) -> None:
                exec(code)

        callback = cast(Callback, callback)
        self.current.callbacks.append(callback)
        return self
    ```
    4. **Step-by-step vulnerability trigger:**
        - The `Query.modify()` method checks if `callback` is a string.
        - If it is a string, it compiles it using `compile(callback, "<string>", "exec")`. The compilation context is set to `'exec'`, indicating the code is meant for execution of statements.
        - A new `callback` function is defined, which, when executed, will `exec(code)`. This executes the compiled code.
        - Malicious Python code within the `callback` string will be executed when this `callback` function is invoked during query execution.

- **Security Test Case:**
    1. **Create a malicious Bowler script (e.g., `malicious_script_exec.py`):**
    ```python
    from bowler import Query
    import os

    malicious_code = """
    import os
    os.system('rm -rf /tmp/important_files') # DANGER: Do not run this on a production system!
    """

    Query('.') \
        .select_root() \
        .modify(malicious_code) \
        .write() # or .diff() or any other action
    ```
    **WARNING:** The example code in `malicious_code` is highly destructive (`rm -rf /tmp/important_files`). **Do not run this test script on a system with important data in `/tmp/important_files` or any critical system.** Modify the malicious code to a less harmful command (like `touch /tmp/exec_pwned`) for testing purposes.

    2. **Run the malicious script:**
    ```bash
    bowler run malicious_script_exec.py -- .
    ```
    3. **Verify the impact:**
        - **If you used `touch /tmp/exec_pwned` for testing:** Check if the file `/tmp/exec_pwned` has been created. Its existence confirms arbitrary code execution via `exec()`.
        - **If you were testing the destructive example (at your own risk and on a non-production system!):** Verify if the directory `/tmp/important_files` (or whatever path you used) has been recursively deleted. This would demonstrate the critical impact of arbitrary code execution.