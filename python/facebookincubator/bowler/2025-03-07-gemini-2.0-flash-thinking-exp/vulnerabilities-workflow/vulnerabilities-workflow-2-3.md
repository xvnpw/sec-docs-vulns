### Vulnerability List

- Vulnerability Name: Code Injection via String-based Filters and Modifiers

- Description:
    Bowler allows users to define filters and modifiers as strings, which are then evaluated using `eval()` or `exec()` respectively. An attacker could craft a malicious refactoring script that injects arbitrary Python code through these string-based filters or modifiers.
    Steps to trigger:
    1. An attacker crafts a Bowler refactoring script.
    2. In this script, the attacker uses the `.filter()` or `.modify()` methods of the `Query` object, providing a string containing malicious Python code instead of a function.
    3. When the Bowler tool executes this script, it compiles and evaluates/executes the malicious string within the context of the refactoring process.
    4. This allows the attacker to execute arbitrary Python code on the system running Bowler, potentially leading to unauthorized access, data breaches, or other malicious activities.

- Impact:
    Successful code injection can lead to arbitrary code execution on the machine running the Bowler tool. This could allow an attacker to:
    - Gain unauthorized access to the system.
    - Steal sensitive data.
    - Modify or delete files.
    - Install malware.
    - Pivot to other systems in the network.
    The impact is highly dependent on the privileges of the user running the Bowler tool and the environment it operates in.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - None. The code explicitly uses `eval()` and `exec()` on user-provided strings in `bowler/query.py` for filter and modifier functionalities.

- Missing Mitigations:
    - **Avoid using `eval()` and `exec()` for string-based filters and modifiers**: The most effective mitigation is to remove the functionality of accepting strings for filters and modifiers altogether or find a safer alternative.
    - **Input validation and sanitization**: If string-based filters and modifiers are to be supported, implement strict input validation and sanitization to prevent the injection of malicious code. However, this is complex and error-prone for arbitrary Python code.
    - **Principle of least privilege**: Advise users to run Bowler with the minimum necessary privileges to limit the impact of potential code injection vulnerabilities.
    - **Security warnings in documentation**: Clearly document the security risks associated with using string-based filters and modifiers and strongly discourage their use, recommending function-based filters and modifiers instead.

- Preconditions:
    - The attacker needs to be able to provide a Bowler refactoring script to be executed by the Bowler tool. This could be achieved if the attacker can:
        - Convince a user to run a malicious script.
        - Compromise a system or workflow that automatically runs Bowler scripts.

- Source Code Analysis:
    1. **File:** `/code/bowler/query.py`
    2. **Method:** `Query.filter(self, filter_callback: Union[str, Filter])`
    3. **Code:**
       ```python
       if isinstance(filter_callback, str):
           code = compile(filter_callback, "<string>", "eval")

           def callback(node: Node, capture: Capture, filename: Filename) -> bool:
               return bool(eval(code))  # noqa: developer tool
       ```
       - This code block checks if `filter_callback` is a string.
       - If it is a string, it compiles the string into Python code using `compile(filter_callback, "<string>", "eval")`. The mode is set to `eval`, meaning it's intended to evaluate an expression.
       - It then defines a new `callback` function that, when called, executes the compiled code using `eval(code)`.
       - **Vulnerability:** The `eval(code)` call executes arbitrary Python code provided as a string. If the string `filter_callback` is controlled by an attacker, they can inject and execute any Python code.

    4. **Method:** `Query.modify(self, callback: Union[str, Callback])`
    5. **Code:**
       ```python
       if isinstance(callback, str):
           code = compile(callback, "<string>", "exec")

           def callback(node: Node, capture: Capture, filename: Filename) -> None:
               exec(code)
       ```
       - This code block is similar to the `filter` method, but it handles modifiers.
       - It checks if `callback` is a string.
       - If it is a string, it compiles the string into Python code using `compile(callback, "<string>", "exec")`. The mode is set to `exec`, meaning it's intended to execute statements.
       - It then defines a new `callback` function that, when called, executes the compiled code using `exec(code)`.
       - **Vulnerability:** The `exec(code)` call executes arbitrary Python code provided as a string. If the string `callback` is controlled by an attacker, they can inject and execute any Python code. `exec` is even more dangerous than `eval` as it can execute full statements, including import statements and system calls.

- Security Test Case:
    1. **Create a malicious Bowler script (e.g., `malicious_codemod.py`):**
       ```python
       from bowler import Query
       import os

       malicious_code_filter = """
       import os
       os.system('touch /tmp/bowler_pwned') # Malicious command to create a file
       True
       """

       (
           Query('.')
           .select_root()
           .filter(malicious_code_filter)
           .write() # or .diff() or .idiff() or .execute()
       )
       ```
    2. **Run the malicious script using Bowler:**
       ```bash
       bowler run malicious_codemod.py .
       ```
       (Assuming you are in a directory where you can write files, and Bowler is installed and in your PATH.)
    3. **Verify code execution:**
       - After running the command, check if the file `/tmp/bowler_pwned` has been created.
       - If the file exists, it confirms that the injected code (`os.system('touch /tmp/bowler_pwned')`) was executed successfully through the string-based filter.

This test case demonstrates how an attacker can inject and execute arbitrary code using string-based filters in Bowler, confirming the code injection vulnerability.