- Vulnerability Name: Code Injection via String-based Filter/Modifier Callbacks
- Description:
  - Bowler allows users to define filters and modifiers as strings, which are then evaluated using `eval()` for filters and `exec()` for modifiers.
  - An attacker can craft a malicious Bowler script or provide a malicious configuration that includes a Bowler query with a string-based filter or modifier containing arbitrary Python code.
  - When Bowler executes the query on the target code base, it will compile and execute the attacker-controlled string using `eval()` within the `filter()` method or `exec()` within the `modify()` method in `bowler/query.py`.
  - This leads to arbitrary code execution in the context of the Bowler application, allowing the attacker to run any Python code with the privileges of the user running Bowler.
- Impact:
  - Critical: Arbitrary code execution on the machine running Bowler.
  - An attacker can gain full control over the system, steal sensitive data, modify or delete files, install malware, pivot to other systems in the network, or perform other malicious actions. The impact is highly dependent on the privileges of the user running the Bowler tool and the environment it operates in.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
  - None. The code directly uses `eval()` and `exec()` on user-provided strings in `bowler/query.py` for filter and modifier functionalities without any sanitization or sandboxing. The feature itself is the vulnerability.
- Missing Mitigations:
  - Remove the ability to define filters and modifiers as strings. This is the most secure approach.
  - If string-based callbacks are absolutely necessary, implement a secure sandbox or restrict the execution environment to prevent arbitrary code execution. However, sanitizing `eval()` and `exec()` input is extremely difficult and error-prone, making removal the recommended mitigation.
  - Discourage string-based filters and modifiers in documentation and API, and strongly recommend using function callbacks instead, as they are easier to inspect and control.
  - Implement static analysis tools to scan Bowler scripts for potentially unsafe `eval()` and `exec()` usage and warn users.
  - Advise users to run Bowler with the minimum necessary privileges to limit the impact of potential code injection vulnerabilities (Principle of least privilege).
- Preconditions:
  - The attacker needs to provide a malicious Bowler script or configuration that contains a Bowler query using string-based filters or modifiers with malicious Python code.
  - The victim needs to execute Bowler using this malicious script or configuration. This could be achieved if the attacker can:
    - Convince a user to run a malicious script.
    - Compromise a system or workflow that automatically runs Bowler scripts.
    - Trick a user into using queries with malicious strings through malicious code examples or refactoring rule sets.
    - Compromise a user's development environment to inject malicious strings into their Bowler scripts.
- Source Code Analysis:
  - File: `/code/bowler/query.py`
  - Methods: `filter(self, filter_callback: Union[str, Filter])` and `modify(self, callback: Union[str, Callback])`
  - **Filter Method Analysis:**
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
    - The `filter` method checks if `filter_callback` is a string.
    - If it's a string, it compiles it using `compile(filter_callback, "<string>", "eval")`, setting the compilation context to `'eval'` for expression evaluation.
    - A callback function is created that executes `eval(code)`, directly evaluating the user-provided string as Python code.
    - **Vulnerability:** `eval(code)` executes arbitrary Python code from the `filter_callback` string.
  - **Modifier Method Analysis:**
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
    - The `modify` method checks if `callback` is a string.
    - If it's a string, it compiles it using `compile(callback, "<string>", "exec")`, setting the compilation context to `'exec'` for statement execution.
    - A callback function is created that executes `exec(code)`, directly executing the user-provided string as Python code.
    - **Vulnerability:** `exec(code)` executes arbitrary Python code from the `callback` string. `exec` is more dangerous than `eval` as it can execute full statements.
- Security Test Case:
  - **Filter Vulnerability Test:**
    - Step 1: Create a Python file named `malicious_filter_codemod.py`:
      ```python
      from bowler import Query

      def main():
          malicious_filter = 'os.system("touch /tmp/bowler_filter_pwned") or True'
          Query(['.']).select_root().filter(malicious_filter).write()

      if __name__ == '__main__':
          import os
          main()
      ```
    - Step 2: Run Bowler with the malicious script:
      ```bash
      bowler run malicious_filter_codemod.py -- .
      ```
    - Step 3: Verify the impact:
      ```bash
      ls /tmp/bowler_filter_pwned
      ```
      - Expected result: The file `/tmp/bowler_filter_pwned` should exist, demonstrating arbitrary code execution via `eval()` in `filter()`.
  - **Modifier Vulnerability Test:**
    - Step 1: Create a Python file named `malicious_modifier_codemod.py`:
      ```python
      from bowler import Query

      def main():
          malicious_modifier = 'os.system("touch /tmp/bowler_modifier_pwned")'
          Query(['.']).select_root().modify(malicious_modifier).write()

      if __name__ == '__main__':
          import os
          main()
      ```
    - Step 2: Run Bowler with the malicious script:
      ```bash
      bowler run malicious_modifier_codemod.py -- .
      ```
    - Step 3: Verify the impact:
      ```bash
      ls /tmp/bowler_modifier_pwned
      ```
      - Expected result: The file `/tmp/bowler_modifier_pwned` should exist, demonstrating arbitrary code execution via `exec()` in `modify()`.

- Vulnerability Name: Code Injection via `bowler do` Command
- Description:
  - The `bowler do` command allows users to execute arbitrary Bowler queries directly from the command line.
  - An attacker can craft a malicious Python code string that, when passed as the query argument to `bowler do`, will be executed by the `eval()` function in `bowler/main.py`.
  - By tricking a user into executing a `bowler do` command with a malicious query, an attacker can achieve arbitrary code execution on the user's machine.
- Impact:
  - Critical: Arbitrary code execution. An attacker can gain full control over the user's system, steal sensitive information, modify files, or install malware.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
  - None. The code directly uses `eval()` on user-provided input without any sanitization or validation in the `do` command.
- Missing Mitigations:
  - Avoid using `eval()` to execute user-provided code in the `bowler do` command.
  - Remove the `bowler do` command or restrict its functionality to prevent arbitrary code execution.
  - Input validation and sanitization of the query string are insufficient and difficult to implement securely for `eval()`.
- Preconditions:
  - The attacker needs to convince a Bowler user to execute the `bowler do` command with a malicious query string. This could be achieved through social engineering, phishing, or by distributing malicious refactoring rules that instruct the user to run a specific `bowler do` command.
- Source Code Analysis:
  - File: `/code/bowler/main.py`
  - Method: `do(interactive: bool, query: str, paths: List[str])`
  - ```python
    @main.command()
    @click.option("-i", "--interactive", is_flag=True)
    @click.argument("query", required=False)
    @click.argument("paths", type=click.Path(exists=True), nargs=-1, required=False)
    def do(interactive: bool, query: str, paths: List[str]) -> None:
        """Execute a query or enter interactive mode."""
        # ...
        if not query or query == "-":
            # ... interactive mode ...
        else:
            code = compile(query, "<console>", "eval")
            result = eval(code)  # noqa eval() - developer tool, hopefully they're not dumb
            # ... process result ...
    ```
  - The `do` command takes a `query` argument from the user.
  - It compiles this `query` string using `compile(query, "<console>", "eval")` and then executes it using `eval(code)`.
  - **Vulnerability:** Direct use of `eval()` on user-provided input `query` allows arbitrary Python code execution.
- Security Test Case:
  - Step 1: Open a terminal.
  - Step 2: Execute the following command:
    ```bash
    bowler do "__import__('os').system('echo BowlerDoVulnerabilityFound!')"
    ```
  - Step 3: Verify the impact: Observe that "BowlerDoVulnerabilityFound!" is printed in the terminal, demonstrating arbitrary command execution.
  - Step 4: Execute a more impactful test to create a file:
    ```bash
    bowler do "__import__('os').system('touch /tmp/bowler_do_pwned')"
    ```
  - Step 5: Verify the impact:
    ```bash
    ls /tmp/bowler_do_pwned
    ```
    - Expected result: The file `/tmp/bowler_do_pwned` should exist, confirming arbitrary command execution via `bowler do`.

- Vulnerability Name: Code Execution via `bowler run` Command with Malicious Codemod
- Description:
  - The `bowler run` command is intended to execute codemod scripts provided by users.
  - However, Bowler directly imports and executes the script provided as the `codemod` argument without any security checks.
  - If an attacker can trick a user into running `bowler run` with a malicious codemod script, they can execute arbitrary code on the user's system.
- Impact:
  - High: Arbitrary code execution. While running user-provided scripts is the intended functionality, the risk arises from running untrusted scripts, which is a common user mistake. An attacker can gain full system control.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
  - None. The code imports and executes the script without any security checks in the `run` command.
- Missing Mitigations:
  - Clearly document the security risks of running untrusted codemod scripts in the documentation.
  - Implement warnings when `bowler run` is used, especially if the script is not from a trusted source.
  - Consider adding options to run codemods in a more restricted environment, although this might be complex to implement effectively. Education and clear warnings are the most practical mitigations.
- Preconditions:
  - The attacker needs to distribute a malicious Python script (codemod) and trick a Bowler user into downloading and executing it using `bowler run`. This can be achieved by hosting the script on a website, sending it via email, or including it in a seemingly benign package.
- Source Code Analysis:
  - File: `/code/bowler/main.py`
  - Method: `run(interactive: bool, codemod: str, paths: List[str])`
  - ```python
    @main.command()
    @click.option("-i", "--interactive", is_flag=True)
    @click.argument("codemod", required=True)
    @click.argument("paths", type=click.Path(exists=True), nargs=-1, required=False)
    def run(interactive: bool, codemod: str, paths: List[str]) -> None:
        """Run a codemod on the given paths."""
        # ...
        path = Path(codemod)
        if path.exists():
            if path.is_dir():
                raise click.ClickException("running directories not supported")

            spec = importlib.util.spec_from_file_location(  # type: ignore
                path.name, path
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)  # type: ignore

        else:
            module = importlib.import_module(codemod)

        main = getattr(module, "main", None)
        if main is not None:
            main()
    ```
  - The `run` command takes a `codemod` argument, which is the path to a Python script or module.
  - It uses `importlib` to dynamically import and execute the script using `spec.loader.exec_module(module)`.
  - **Vulnerability:** Direct execution of user-provided Python scripts without any security checks allows arbitrary code execution.
- Security Test Case:
  - Step 1: Create a malicious Python script named `malicious_codemod_run.py`:
    ```python
    import os

    def main():
        os.system('echo BowlerRunVulnerabilityFound!')
        os.system('touch /tmp/bowler_run_pwned')

    if __name__ == "__main__":
        main()
    ```
  - Step 2: Open a terminal and navigate to the directory containing `malicious_codemod_run.py`.
  - Step 3: Execute the following command:
    ```bash
    bowler run malicious_codemod_run.py
    ```
  - Step 4: Verify the impact: Observe that "BowlerRunVulnerabilityFound!" is printed in the terminal.
  - Step 5: Verify the impact:
    ```bash
    ls /tmp/bowler_run_pwned
    ```
    - Expected result: The file `/tmp/bowler_run_pwned` should exist, confirming arbitrary command execution via `bowler run` with a malicious codemod.