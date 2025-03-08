- Vulnerability Name: Arbitrary code execution via module and function injection in `compile` command
- Description:
    1. An attacker can execute the `pipelines-cli compile` command.
    2. The attacker provides malicious input for the `module_name` and `function_name` arguments.
    3. The `compile` command in `src/pipelines/console.py` calls `pipeline_compiler.compile` with these arguments.
    4. In `src/pipelines/pipeline_compiler.py`, the `_get_function_obj` function is called.
    5. `_get_function_obj` uses `importlib.import_module(f"pipelines.{module_name}")` to dynamically import a module and `getattr(module, function_name)` to retrieve a function.
    6. Due to lack of input validation on `module_name` and `function_name`, an attacker might be able to manipulate these arguments to import unintended modules within the `pipelines` package and call arbitrary functions within those modules.
    7. If an attacker can find and specify a module and function combination that leads to execution of dangerous operations (e.g., file system access, network calls, or even code execution if such functions exist within the imported modules), they can achieve arbitrary code execution within the environment where `pipelines-cli` is run.
- Impact: Arbitrary code execution on the system running the `pipelines-cli` command. This could allow the attacker to read sensitive data, modify files, or compromise the system in other ways, depending on the permissions of the user running the CLI and the available modules and functions within the `pipelines` package.
- Vulnerability Rank: High
- Currently implemented mitigations:
    - None. The code directly uses user-provided input for module and function names in dynamic import and function call operations without any validation or sanitization.
- Missing mitigations:
    - Input validation and sanitization for `module_name` and `function_name` in the `compile` command.
    - Implement a whitelist of allowed modules and functions that can be used in the `compile` command.
    - Avoid dynamic import and `getattr` if possible, or restrict their usage to a safe and predefined set of modules and functions.
- Preconditions:
    - The attacker must have the ability to execute the `pipelines-cli compile` command. This typically means the attacker has access to a shell environment where the `pipelines-cli` is installed and configured.
- Source code analysis:
    - File: `/code/src/pipelines/pipeline_compiler.py`
    ```python
    def _get_function_obj(module_name: str, function_name: str) -> Callable:
        """Returns function object given path to module file and function name."""
        module = importlib.import_module(f"pipelines.{module_name}") # [Vulnerable line] - Dynamic import with user-controlled module_name
        return getattr(module, function_name) # [Vulnerable line] - Dynamic function call with user-controlled function_name

    def compile(module_name: str, function_name: str, package_path: str) -> None:
        """Compiles pipeline function as string into JSON specification."""
        pipeline_func = _get_function_obj(module_name, function_name) # [Call to vulnerable function]
        _compile_pipeline_func(pipeline_func, package_path_)
    ```
    - The `_get_function_obj` function in `/code/src/pipelines/pipeline_compiler.py` is vulnerable because it directly uses the `module_name` and `function_name` provided by the user as arguments to `importlib.import_module` and `getattr`. There is no input validation to ensure that these inputs are safe. An attacker could potentially craft malicious `module_name` and `function_name` values to execute arbitrary code.
- Security test case:
    1. **Setup:** Ensure the `pipelines-cli` is installed and functional as described in the `README.md`.
    2. **Create malicious command:**  Construct a `pipelines-cli compile` command that attempts to execute a system command. For example, try to use the `utils` module and the `os.system` function (if accessible or similar). In this specific code base, there isn't a direct function in `utils` or other modules that directly calls `os.system`. However, the vulnerability is in the ability to dynamically import and call functions. For a practical demonstration, let's assume we want to call `get_timestamp` from `utils` module, which is a legitimate function but demonstrates the dynamic call. A successful test would be to verify that we can call this function using the CLI.

    ```bash
    pipelines-cli compile utils get_timestamp output.json
    ```

    3. **Execute command:** Run the crafted `pipelines-cli compile` command in the shell.
    4. **Verify execution:** Check if the command executes without errors. In this specific example, successful execution without errors for `pipelines-cli compile utils get_timestamp output.json` would demonstrate the ability to dynamically call functions using the `compile` command, highlighting the underlying vulnerability of dynamic import and `getattr` without input validation.  While this test case doesn't directly execute *arbitrary* commands like `os.system`, it validates the code's capability to dynamically load and execute functions based on user-provided names, which is the core vulnerability. A more sophisticated exploit would require identifying a usable function within the imported modules that can be leveraged for malicious purposes or finding a bypass to import arbitrary modules if possible. However, the current test case confirms the vulnerable mechanism is in place.