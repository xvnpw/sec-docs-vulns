- vulnerability name: Arbitrary Code Execution via String-based Filter/Modifier Callbacks
- description:
  - Bowler allows users to define filters and modifiers as strings, which are then evaluated using `eval()` for filters and `exec()` for modifiers.
  - An attacker can craft a malicious Python file that, when processed by Bowler, includes a Bowler query with a string-based filter or modifier.
  - This malicious string can contain arbitrary Python code.
  - When Bowler executes the query on the target code base, it will compile and execute the attacker-controlled string using `eval()` or `exec()` within the Bowler process.
  - This leads to arbitrary code execution in the context of the Bowler application.
- impact:
  - Arbitrary code execution on the machine running Bowler.
  - An attacker can gain full control over the system, steal sensitive data, install malware, or perform other malicious actions.
- vulnerability rank: critical
- currently implemented mitigations:
  - None. The feature itself is the vulnerability.
- missing mitigations:
  - Remove the ability to define filters and modifiers as strings.
  - If string-based callbacks are absolutely necessary, implement a secure sandbox or restrict the execution environment to prevent arbitrary code execution. However, removing the feature is the most secure approach.
- preconditions:
  - The attacker needs to provide a malicious Python file that contains a Bowler query using string-based filters or modifiers.
  - The victim needs to execute Bowler on this malicious file.
- source code analysis:
  - File: `/code/bowler/query.py`
  - Method: `filter(self, filter_callback: Union[str, Filter])`
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
  - The `filter` method in `Query` class takes `filter_callback` as an argument which can be a string.
  - If `filter_callback` is a string, it's compiled using `compile(filter_callback, "<string>", "eval")`.
  - Then a callback function is created which executes `eval(code)`.
  - Similarly, in `modify(self, callback: Union[str, Callback])` method:
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
  - The `modify` method in `Query` class takes `callback` as an argument which can be a string.
  - If `callback` is a string, it's compiled using `compile(callback, "<string>", "exec")`.
  - Then a callback function is created which executes `exec(code)`.
  - In both cases, user-provided strings are executed as Python code, leading to potential arbitrary code execution.
- security test case:
  - Step 1: Create a malicious Python file named `malicious_codemod.py` with the following content:
    ```python
    from bowler import Query
    import os

    def main():
        malicious_filter = 'os.system("touch /tmp/pwned") or True'
        Query(['.']).select_root().filter(malicious_filter).write()

    if __name__ == '__main__':
        main()
    ```
    This script defines a Bowler query with a string-based filter that executes the command `touch /tmp/pwned`. The `or True` is added to make the filter always return True and not interfere with Bowler's logic.
  - Step 2: Run Bowler with the malicious script, targeting any Python file (or even an empty directory):
    ```bash
    bowler run malicious_codemod.py -- .
    ```
  - Step 3: Check if the file `/tmp/pwned` has been created.
    ```bash
    ls /tmp/pwned
    ```
    If the file `/tmp/pwned` exists, it confirms that the arbitrary code within the string-based filter was executed by Bowler.
    - Expected result: The file `/tmp/pwned` should be created, demonstrating arbitrary code execution.