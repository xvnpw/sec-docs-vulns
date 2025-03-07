* Vulnerability name: LaTeX Injection in String Constants
* Description:
    1. An attacker crafts a Python function that includes a string constant containing malicious LaTeX commands.
    2. The attacker uses `latexify` library to convert this Python function into a LaTeX expression.
    3. `latexify` processes the function and directly includes the string constant from the Python code into the generated LaTeX output without sufficient sanitization.
    4. When the generated LaTeX code is processed by a LaTeX processor (like pdflatex), the malicious LaTeX commands within the string constant are executed.
* Impact:
    - High: Arbitrary LaTeX code execution. Depending on the LaTeX processor and its configuration, this could lead to:
        - File system access: Creating, modifying, or deleting files if the LaTeX processor has write permissions.
        - Command execution: Executing arbitrary shell commands if `\write18` or similar functionality is enabled in the LaTeX processor.
        - Information disclosure: Including sensitive data from the server's environment into the generated document if environment variables or accessible files are read.
* Vulnerability rank: High
* Currently implemented mitigations:
    - None: The code does not implement any explicit sanitization or escaping of string constants to prevent LaTeX injection.
* Missing mitigations:
    - Input sanitization: Implement sanitization of string constants to escape or remove LaTeX special characters and commands that could be part of an injection attack.
    - Context-aware escaping: Apply escaping based on the context where user-provided strings are inserted into the LaTeX document. For string constants, more aggressive escaping might be needed.
    - Sandboxing or secure LaTeX processing: If possible, process generated LaTeX in a sandboxed environment to limit the impact of potential injection attacks.
* Preconditions:
    - The attacker needs to be able to provide arbitrary Python code to the `latexify` library. This is typically the case if `latexify` is used in a web application or service where users can input Python snippets to be latexified.
* Source code analysis:
    1. `src/latexify/codegen/expression_codegen.py`: The `ExpressionCodegen` class is responsible for converting Python expressions into LaTeX.
    2. `src/latexify/codegen/expression_codegen.py visit_Constant(self, node: ast.Constant) / visit_Str(self, node: ast.Str) / visit_Bytes(self, node: ast.Bytes)`: These methods handle constant values, including strings.
    3. `src/latexify/codegen/codegen_utils.py convert_constant(value: Any)`: This function is called to convert constant values to LaTeX strings. For string constants, it wraps the string in `\textrm{}`.
    4. Vulnerability: The `convert_constant` function in `src/latexify/codegen/codegen_utils.py` only wraps string constants in `\textrm{}`. It does not perform any sanitization or escaping of LaTeX special characters or commands within the string itself. This allows an attacker to embed malicious LaTeX commands within a Python string, which will be directly included in the generated LaTeX output.

    ```python
    File: /code/src/latexify/codegen/codegen_utils.py
    Content:
    ...
    if isinstance(value, str):
        return r'\textrm{"' + value + '"}'
    ...
    ```

    Visualization:

    User Input (Python Code with Malicious String) --> `latexify` Parser --> AST --> `ExpressionCodegen` --> `convert_constant` (No Sanitization) --> LaTeX Output (Malicious LaTeX Code Included) --> LaTeX Processor (Malicious Code Execution)

* Security test case:
    1. Create a Python function with a string constant containing LaTeX injection code:

    ```python
    import latexify

    @latexify.function
    def vulnerable_function():
        return "Malicious LaTeX: \\immediate\\write18{touch /tmp/latexify_pwned} vulnerable"

    print(vulnerable_function)
    ```

    2. Run this Python code. `latexify` will generate LaTeX code that includes the malicious command `\immediate\write18{touch /tmp/latexify_pwned}` within the string.

    ```latex
    f() = \textrm{"Malicious LaTeX: \immediate\write18{touch /tmp/latexify_pwned} vulnerable"}
    ```

    3. Copy the generated LaTeX output and process it with a LaTeX processor that has `\write18` enabled (this is often disabled by default in restricted environments, but might be enabled in local setups or older configurations). For example, use `pdflatex` on the command line:

    ```bash
    pdflatex vulnerable.tex
    ```

    where `vulnerable.tex` contains:

    ```latex
    \documentclass{article}
    \begin{document}
    $$ f() = \textrm{"Malicious LaTeX: \immediate\write18{touch /tmp/latexify_pwned} vulnerable"} $$
    \end{document}
    ```

    4. After processing, check if the file `/tmp/latexify_pwned` has been created. If it exists, it indicates successful execution of the injected LaTeX command, proving the vulnerability.