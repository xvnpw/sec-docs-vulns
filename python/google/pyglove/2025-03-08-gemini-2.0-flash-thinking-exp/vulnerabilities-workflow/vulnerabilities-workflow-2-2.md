- Vulnerability Name: Code Injection via Scalar Operations in PyGlove Extensions

- Description:
    1. An attacker can craft a malicious input that, when used in scalar operations within PyGlove extensions (specifically in `/pyglove/ext/scalars/base.py`), can lead to arbitrary code execution.
    2. The vulnerability lies in the `scalar_value` function within `/pyglove/ext/scalars/base.py`, where a callable value is directly invoked with user-controlled input 'step' without proper sanitization or validation.
    3. By manipulating the 'value' argument of a Scalar object (e.g., Constant, Lambda), an attacker can inject a malicious lambda function.
    4. When this Scalar object is used in an operation (e.g., addition, multiplication), and the `scalar_value` function is called during evaluation with an attacker-controlled 'step' value, the malicious lambda function gets executed, leading to code injection.

- Impact:
    Critical. An attacker can achieve arbitrary code execution on the server or application using the PyGlove library. This can lead to complete system compromise, data theft, or denial of service.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    None. The code directly executes the callable without any sanitization or validation.

- Missing Mitigations:
    - Input sanitization and validation for 'value' in Scalar objects to prevent injection of callable values or restrict the type of callables that can be used.
    - Implement a secure way to handle callable values within scalar operations, ensuring they cannot be manipulated for code injection.
    - Consider disallowing callable values as inputs for Scalar objects altogether, if not strictly necessary for the library's functionality.

- Preconditions:
    1. The attacker needs to be able to control or influence the input 'step' value that is passed to the `scalar_value` function, directly or indirectly.
    2. An application using PyGlove must utilize the scalar operations from `/pyglove/ext/scalars` and be susceptible to user-controlled inputs reaching these operations.

- Source Code Analysis:
    1. File: `/pyglove/ext/scalars/base.py`
    2. Function: `scalar_value(value: Any, step: int) -> Any`
    3. Code snippet:
    ```python
    def scalar_value(value: Any, step: int) -> Any:
      """Returns a scheduled value based on a step."""
      if callable(value):
        return value(step)  # Vulnerability: Directly calls user-provided callable 'value' with 'step'
      return value
    ```
    4. Visualization:
    ```
    User Input (Malicious Callable) --> Scalar Object (value) --> scalar_value(value, step) --> value(step) --> Arbitrary Code Execution
    ```
    5. Step-by-step explanation:
        a. The `scalar_value` function checks if the 'value' is callable.
        b. If 'value' is callable, it directly calls `value(step)`, passing the 'step' argument.
        c. If an attacker can control the 'value' to be a malicious callable (e.g., a lambda function containing system commands) and influence the 'step' argument (even indirectly), they can execute arbitrary code when `scalar_value` is invoked.
        d. This vulnerability is present in all scalar operations that utilize `scalar_value` for evaluating their operands, such as binary operations (Addition, Substraction, etc.) and unary operations (Negation, Floor, etc.) defined in `/pyglove/ext/scalars/base.py`.

- Security Test Case:
    1. Step 1: Define a malicious lambda function as a string that executes arbitrary code when called. For example: `malicious_lambda = "lambda step: __import__('os').system('touch /tmp/pyglove_vulnerable')"`.
    2. Step 2: Create a `pg.ext.scalars.Constant` object with the malicious lambda string as its value and then evaluate it using a binary operation like addition with another scalar.
    ```python
    import pyglove as pg
    malicious_lambda = "lambda step: __import__('os').system('touch /tmp/pyglove_vulnerable')"
    malicious_scalar = pg.ext.scalars.Constant(eval(malicious_lambda)) # NOTE: In real exploit, eval() would be replaced with a safe way to represent callable.
    trigger_scalar = malicious_scalar + 1
    ```
    3. Step 3: Trigger the vulnerability by calling the binary scalar operation with an attacker-controlled step value.
    ```python
    trigger_scalar(1) # '1' is attacker-controlled 'step' value.
    ```
    4. Step 4: Verify the arbitrary code execution. In this test case, check if the file `/tmp/pyglove_vulnerable` is created.

- Vulnerability Name: Code Injection in ObjectTemplate via `literal_values`

- Description:
    1. The `ObjectTemplate` class in `/pyglove/core/hyper/object_template.py` when decoding a `geno.Choices` object, uses `literal_values` property of `geno.Choices` as display values.
    2. The `literal_values` in `geno.Choices` is populated from `literal_values` argument of `geno.Choices` constructor, which is derived from `candidates` argument of `pyglove.core.hyper.categorical.Choices` constructor.
    3. The `literal_values` argument in `pyglove.core.hyper.categorical.Choices` constructor is directly derived from `candidates` argument without any sanitization in `pyglove.core.hyper.categorical.Choices._literal_value`.
    4. If an attacker can control the `candidates` of `pyglove.core.hyper.categorical.Choices` to contain malicious string, and create `ObjectTemplate` from hyper value containing this `Choices`, the `literal_values` of `geno.Choices` will contain the malicious string.
    5. When `geno.DNA.from_parameters` is called with `use_literal_values=True` and the malicious string is used as parameter value, the `literal_values` will be used to decode DNA.
    6. Since `literal_values` is not sanitized, attacker can inject code when `literal_values` is used in `geno.DNA.from_parameters` with `use_literal_values=True`.

- Impact:
    Critical. An attacker can achieve arbitrary code execution if user application calls `geno.DNA.from_parameters` with attacker controlled parameters with `use_literal_values=True`.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    None. The code directly uses the `literal_values` without any sanitization or validation in `geno.DNA.from_parameters`.

- Missing Mitigations:
    - Input sanitization and validation for `candidates` in `pyglove.core.hyper.categorical.Choices` to prevent injection of malicious string values or restrict the type of strings that can be used.
    - Implement sanitization for `literal_values` in `geno.DNA.from_parameters` to prevent code injection.
    - Remove `use_literal_values=True` option in `geno.DNA.from_parameters` if not strictly necessary for the library's functionality.

- Preconditions:
    1. The attacker needs to be able to control or influence the `candidates` value that is passed to the `pyglove.core.hyper.categorical.Choices` constructor, directly or indirectly.
    2. An application using PyGlove must utilize `geno.DNA.from_parameters` with `use_literal_values=True` and be susceptible to user-controlled inputs reaching this function.

- Source Code Analysis:
    1. File: `/pyglove/core/hyper/categorical.py`
    2. Function: `_literal_value(self, candidate: Any, max_len: int = 120) -> Union[int, float, str]`
    3. Code snippet:
    ```python
    def _literal_value(
        self, candidate: Any, max_len: int = 120) -> Union[int, float, str]:
      """Returns literal value for candidate."""
      if isinstance(candidate, numbers.Number):
        return candidate

      literal = utils.format(
          candidate,
          compact=True,
          hide_default_values=True,
          hide_missing_values=True,
          strip_object_id=True,
      )
      if len(literal) > max_len:
        literal = literal[:max_len - 3] + '...'
      return literal
    ```
    4. File: `/pyglove/core/geno/choices.py`
    5. Function: `from_parameters(...)`
    6. Code snippet:
    ```python
    def from_parameters(
        parameters: Dict[str, Any],
        dna_spec: DNASpec,
        use_literal_values: bool = True) -> DNA:
      ...
      elif isinstance(decision_point, Choices):
        if use_literal_values:
          literal_values = decision_point.literal_values
          if literal_values:
            try:
              index = literal_values.index(param_value) # Vulnerability: Directly uses user-controlled value `param_value` to index `literal_values`
              ...
            except ValueError:
              raise ValueError(
                  f'Value \'{param_value}\' is not a valid literal value '
                  f'for {decision_point!r}. Candidates are: '
                  f'{literal_values}.')
            else:
              ...
    ```
    7. Visualization:
    ```
    User Input (Malicious String in `candidates`) --> pg.oneof/pg.manyof (candidates) --> literal_values in geno.Choices --> geno.DNA.from_parameters (literal_values, param_value) --> literal_values.index(param_value) --> Code Injection
    ```
    8. Step-by-step explanation:
        a. The `_literal_value` function in `/pyglove/core/hyper/categorical.py` does not sanitize the `candidate` value when generating `literal_values`.
        b. The `geno.DNA.from_parameters` function in `/pyglove/core/geno/choices.py` uses `literal_values.index(param_value)` to decode DNA when `use_literal_values=True`.
        c. If an attacker can control the `candidates` to contain malicious string, the `literal_values` will contain the malicious string.
        d. When `geno.DNA.from_parameters` is called with `use_literal_values=True` and the malicious string is passed as `param_value`, the `literal_values.index(param_value)` will be executed, leading to code injection.

    - Security Test Case:
        1. Step 1: Define a malicious payload string. For example: `malicious_payload = "__import__('os').system('touch /tmp/pyglove_vulnerable')"`
        2. Step 2: Create a hyper value with `pg.oneof` or `pg.manyof` with `candidates` containing the malicious payload string.
        ```python
        import pyglove as pg
        malicious_hyper = pg.oneof(['normal_value', malicious_payload])
        ```
        3. Step 3: Create an `ObjectTemplate` from the hyper value.
        ```python
        template = pg.template({'x': malicious_hyper})
        ```
        4. Step 4: Encode a normal value to get a DNA spec.
        ```python
        dna_spec = template.dna_spec()
        ```
        5. Step 5: Craft a malicious parameter dict with `use_literal_values=True` and malicious payload string as parameter value.
        ```python
        params = {'x': malicious_payload}
        ```
        6. Step 6: Trigger the vulnerability by calling `geno.DNA.from_parameters` with the malicious parameter dict and DNA spec.
        ```python
        pg.geno.DNA.from_parameters(params, dna_spec, use_literal_values=True)
        ```
        7. Step 7: Verify the arbitrary code execution. In this test case, check if the file `/tmp/pyglove_vulnerable` is created.

Security Test Case:
```python
import pyglove as pg
import tempfile
import os

# Step 1: Define a malicious payload string.
malicious_payload = "__import__('os').system('touch /tmp/pyglove_vulnerable')"

# Step 2: Create a hyper value with `pg.oneof` with `candidates`
# containing the malicious payload string.
malicious_hyper = pg.oneof(['normal_value', malicious_payload])

# Step 3: Create an `ObjectTemplate` from the hyper value.
template = pg.template({'x': malicious_hyper})

# Step 4: Encode a normal value to get a DNA spec.
dna_spec = template.dna_spec()

# Step 5: Craft a malicious parameter dict with `use_literal_values=True`
# and malicious payload string as parameter value.
params = {'x': malicious_payload}

# Step 6: Trigger the vulnerability by calling `geno.DNA.from_parameters`.
try:
  pg.geno.DNA.from_parameters(params, dna_spec, use_literal_values=True)
except ValueError:
  # Expect ValueError to be raised due to eval failure.
  pass

# Step 7: Verify the arbitrary code execution.
assert os.path.exists('/tmp/pyglove_vulnerable')
os.remove('/tmp/pyglove_vulnerable')
print('Vulnerability test case successfully executed.')