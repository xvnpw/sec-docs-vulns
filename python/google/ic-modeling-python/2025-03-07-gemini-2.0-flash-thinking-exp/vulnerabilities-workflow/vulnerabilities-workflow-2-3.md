### Vulnerability List

- Vulnerability Name: Unvalidated Local Parameter Values Leading to SystemVerilog Syntax Errors
- Description:
    1. An attacker crafts a malicious hardware description file or input that, when processed by a tool built upon `ic-modeling-python`, leads to the creation of a `LocalParam` model with an invalid or malicious `value`.
    2. This invalid `value` is not validated by the `ic-modeling-python` library.
    3. The `localparam_declaration_tokenizer` in `/code/imp/system_verilog/writers/parameter_tokenizer.py` takes this unvalidated `value` and creates a `Literal` token directly from it.
    4. The `SystemVerilogWriter` and `Formatter` then process this `Literal` token and include it verbatim in the generated SystemVerilog code.
    5. When a downstream SystemVerilog tool (simulator, synthesizer, etc.) attempts to parse or process this generated code, it encounters a syntax error or exhibits unexpected behavior due to the invalid literal.
- Impact: Generated SystemVerilog code can contain syntax errors, causing failures in downstream SystemVerilog tools. This can disrupt the design and verification flow, and in some cases, might lead to tools behaving in unexpected ways when encountering invalid input.
- Vulnerability Rank: medium
- Currently Implemented Mitigations: None. The library does not perform any validation or sanitization of parameter values.
- Missing Mitigations: Implement input validation for parameter and localparam values to ensure they conform to valid SystemVerilog literal syntax or sanitize/escape special characters before creating `Literal` tokens.
- Preconditions: A tool built on top of `ic-modeling-python` must allow external input to influence the values assigned to `LocalParam` or `Parameter` models.
- Source Code Analysis:
    1. In `/code/imp/system_verilog/models/parameters.py`, the `LocalParam` class takes a `value` argument in its constructor. This value is stored without any validation.
    ```python
    class LocalParam(component.Component):
      """Local parameters"""
      def __init__(self, name, dtype, value, comment=None):
        super().__init__()
        self.name = name
        self.dtype = dtype
        self.value = value # Value is stored without validation
        self.comment = comment
    ```
    2. In `/code/imp/system_verilog/writers/parameter_tokenizer.py`, the `localparam_declaration_tokenizer` function retrieves `target.localparam.value` and creates a `Literal(value)` token.
    ```python
    @tokenizer_for(parameters.LocalParamDeclaration)
    def localparam_declaration_tokenizer(target: parameters.LocalParamDeclaration, tokenize):
      identifiers = [tokens.Identifier(name) for name in target.names]
      yield from Keyword('localparam') + SP()
      yield from tokenize(target.localparam.dtype) + SP()
      yield from tokens.CommaSeperated(identifiers, tokenize)
      if value := target.localparam.value:
        yield from SP() + Symbol("=") + SP() + Literal(value) # Literal token is created directly from value
      yield from Symbol(";") + CR()
    ```
    3. In `/code/imp/base/writers/tokens.py`, the `Literal` token simply stores the provided `value` as is, without any sanitization or escaping.
    ```python
    class Literal(Token):
      """Used to denote literal values."""
      def __init__(self, value):
        super().__init__(value) # Value is stored without sanitization
    ```
    4. In `/code/imp/base/writers/formatter.py`, the `Formatter` converts the `Literal` token's `value` to a string and appends it to the output.
    ```python
    @Formatter.handle.register
    def handle_token(self, token: Token):
      value = str(token.value) # Value is converted to string and added to output
      self.add_word(value)
    ```
- Security Test Case:
    1. Create a Python test script (e.g., `test_localparam_injection.py`).
    2. Import necessary modules:
    ```python
    from imp.system_verilog.models import modules
    from imp.system_verilog.models import datatypes
    from imp.system_verilog.writers import systemverilog_writer
    ```
    3. Instantiate a `SystemVerilogWriter`.
    ```python
    writer = systemverilog_writer.SystemVerilogWriter()
    ```
    4. Create a `Module` object.
    ```python
    module = modules.Module(module_name="injection_test")
    ```
    5. Create a `LocalParam` with a malicious value containing a backtick, which is not a valid character in a simple integer literal in SystemVerilog and can cause syntax errors.
    ```python
    malicious_value = "`bad`value"
    module.localparam(name="p1", dtype=datatypes.IntType(), value=malicious_value)
    ```
    6. Generate SystemVerilog code for this module.
    ```python
    generated_code = writer.get_text_for(module)
    ```
    7. Print the generated SystemVerilog code and inspect it.
    ```python
    print(generated_code)
    ```
    **Expected Output Inspection:** The generated code will contain the invalid literal directly in the SystemVerilog output, like this:
    ```systemverilog
    module injection_test(
    );

      localparam int p1 = "`bad`value";
    endmodule
    ```
    8. Save the generated code to a `.sv` file (e.g., `injection_test.sv`).
    9. Attempt to compile this generated SystemVerilog file using a SystemVerilog compiler (like `iverilog`).
    ```bash
    iverilog injection_test.sv
    ```
    10. Verify that the SystemVerilog compiler reports a syntax error related to the invalid literal value "`bad`value". `iverilog` will report error like: `injection_test.sv:3: syntax error`. This confirms that the invalid value injected through `LocalParam` leads to syntax errors in downstream tools.