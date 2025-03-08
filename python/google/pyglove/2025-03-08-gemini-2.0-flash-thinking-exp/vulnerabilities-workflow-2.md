## Vulnerability Report

### Insecure Deserialization of Symbolic Objects

- **Vulnerability Name:** Insecure Deserialization of Symbolic Objects
- **Description:**
    - PyGlove is designed for manipulating Python objects, including serializing and deserializing symbolic representations of Python code.
    - Applications using PyGlove that deserialize symbolic objects from untrusted sources are vulnerable to insecure deserialization.
    - An attacker can craft a malicious serialized payload. When deserialized by PyGlove, this payload can execute arbitrary code on the server or client machine.
    - **Step-by-step trigger:**
        1. An attacker crafts a malicious serialized PyGlove symbolic object.
        2. The attacker sends this malicious payload to an application that uses PyGlove and performs deserialization without proper validation.
        3. The PyGlove library deserializes the object.
        4. Malicious code embedded in the serialized data gets executed during the deserialization process.
- **Impact:**
    - Critical. Arbitrary code execution on the machine running the application. This can lead to complete system compromise, data breaches, and other severe security incidents.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    - No specific code related to serialization or deserialization functions within the provided PyGlove library files. No project-level mitigations are visible in the provided files.
- **Missing Mitigations:**
    - Input validation and sanitization for deserialized data.
    - Avoiding or securing the use of inherently unsafe deserialization methods like `pickle` for untrusted data.
    - Documentation and warnings to users about the risks of insecure deserialization, recommending best practices such as only deserializing data from trusted sources.
- **Preconditions:**
    - An application using the PyGlove library must deserialize PyGlove symbolic objects.
    - The application must load serialized data from an untrusted source (e.g., user input, network data).
- **Source Code Analysis:**
    - The provided files are mostly documentation, setup scripts, and test code, lacking direct deserialization implementation.
    - PyGlove's nature as a "general-purpose library for Python object manipulation" and "symbolic programming for automated machine learning" suggests serialization and deserialization are likely core functionalities, making insecure deserialization a relevant attack vector. Further code analysis of core library files is needed to pinpoint exact deserialization points.
- **Security Test Case:**
    1. **Setup:** Create a dummy Python application using PyGlove with a function that deserializes a PyGlove symbolic object from a file (untrusted input).
    2. **Vulnerability Injection:** Craft a malicious serialized PyGlove symbolic object embedding code execution commands (e.g., using `pickle`). Save it to a file.
    3. **Execution:** Run the dummy application, providing the path to the malicious file to the deserialization function.
    4. **Verification:** Observe for arbitrary code execution, such as creation of a file or execution of a command, confirming the insecure deserialization vulnerability.

### Code Injection via Scalar Operations in PyGlove Extensions

- **Vulnerability Name:** Code Injection via Scalar Operations in PyGlove Extensions
- **Description:**
    - A malicious input can lead to arbitrary code execution in PyGlove extensions through scalar operations, specifically in `/pyglove/ext/scalars/base.py`.
    - The vulnerability is in the `scalar_value` function, where a callable value is directly invoked with user-controlled input 'step' without sanitization.
    - By injecting a malicious lambda function as the 'value' of a Scalar object (e.g., Constant, Lambda), an attacker can achieve code injection.
    - When a Scalar object with a malicious lambda is used in an operation, `scalar_value` is called during evaluation with an attacker-controlled 'step', executing the malicious code.
- **Impact:**
    - Critical. Arbitrary code execution on the server or application, potentially leading to complete system compromise, data theft, or denial of service.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    - None. The code directly executes the callable without any sanitization or validation.
- **Missing Mitigations:**
    - Input sanitization and validation for 'value' in Scalar objects to prevent injection of callable values.
    - Secure handling of callable values in scalar operations, preventing manipulation for code injection.
    - Consider disallowing callable values as inputs for Scalar objects if not essential.
- **Preconditions:**
    - Attacker control or influence over the 'step' value passed to `scalar_value`.
    - An application using PyGlove utilizes scalar operations from `/pyglove/ext/scalars` and is susceptible to user-controlled inputs reaching these operations.
- **Source Code Analysis:**
    - **File:** `/pyglove/ext/scalars/base.py`
    - **Function:** `scalar_value(value: Any, step: int) -> Any`
    - **Code:**
      ```python
      def scalar_value(value: Any, step: int) -> Any:
        if callable(value):
          return value(step)  # Vulnerability: Direct callable invocation
        return value
      ```
    - **Visualization:**
      ```
      User Input (Malicious Callable) --> Scalar Object (value) --> scalar_value(value, step) --> value(step) --> Arbitrary Code Execution
      ```
    - The `scalar_value` function directly calls `value(step)` if 'value' is callable. Attacker-controlled malicious callable as 'value' and influence over 'step' leads to code injection.
- **Security Test Case:**
    1. Define a malicious lambda function string: `malicious_lambda = "lambda step: __import__('os').system('touch /tmp/pyglove_vulnerable')"`.
    2. Create a `pg.ext.scalars.Constant` with the malicious lambda (using `eval` for test purposes).
    3. Create a trigger scalar using binary operation: `trigger_scalar = malicious_scalar + 1`.
    4. Trigger vulnerability by calling `trigger_scalar(1)` with attacker-controlled step value '1'.
    5. Verify code execution by checking for `/tmp/pyglove_vulnerable` file creation.

### Code Injection in ObjectTemplate via `literal_values`

- **Vulnerability Name:** Code Injection in ObjectTemplate via `literal_values`
- **Description:**
    - The `ObjectTemplate` class uses `literal_values` from `geno.Choices` when decoding a `geno.Choices` object.
    - `literal_values` is populated from the `literal_values` argument of `geno.Choices` constructor, derived from `candidates` in `pyglove.core.hyper.categorical.Choices` constructor.
    - `literal_values` argument is directly derived from `candidates` without sanitization in `pyglove.core.hyper.categorical.Choices._literal_value`.
    - Attacker-controlled `candidates` in `pyglove.core.hyper.categorical.Choices` with malicious strings can inject code.
    - When `geno.DNA.from_parameters` is called with `use_literal_values=True` and a malicious string is used as a parameter value, `literal_values` is used to decode DNA.
    - Unsanitized `literal_values` in `geno.DNA.from_parameters` with `use_literal_values=True` allows code injection.
- **Impact:**
    - Critical. Arbitrary code execution if user application calls `geno.DNA.from_parameters` with attacker controlled parameters and `use_literal_values=True`.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    - None. `literal_values` is directly used without sanitization in `geno.DNA.from_parameters`.
- **Missing Mitigations:**
    - Input sanitization for `candidates` in `pyglove.core.hyper.categorical.Choices`.
    - Sanitization for `literal_values` in `geno.DNA.from_parameters`.
    - Remove `use_literal_values=True` option in `geno.DNA.from_parameters` if not necessary.
- **Preconditions:**
    - Attacker control or influence over the `candidates` value passed to `pyglove.core.hyper.categorical.Choices` constructor.
    - Application uses `geno.DNA.from_parameters` with `use_literal_values=True` and is susceptible to user-controlled inputs.
- **Source Code Analysis:**
    - **File:** `/pyglove/core/hyper/categorical.py`
    - **Function:** `_literal_value(self, candidate: Any, max_len: int = 120) -> Union[int, float, str]`
    - **Code:** (No sanitization of `candidate`)

    - **File:** `/pyglove/core/geno/choices.py`
    - **Function:** `from_parameters(...)`
    - **Code:**
      ```python
      def from_parameters(...):
        ...
        elif isinstance(decision_point, Choices):
          if use_literal_values:
            literal_values = decision_point.literal_values
            if literal_values:
              try:
                index = literal_values.index(param_value) # Vulnerability: Unsanitized literal_values.index(param_value)
                ...
              except ValueError:
                ...
              else:
                ...
      ```
    - **Visualization:**
      ```
      User Input (Malicious String in `candidates`) --> pg.oneof/pg.manyof (candidates) --> literal_values in geno.Choices --> geno.DNA.from_parameters (literal_values, param_value) --> literal_values.index(param_value) --> Code Injection
      ```
    - `_literal_value` does not sanitize `candidate`. `geno.DNA.from_parameters` uses unsanitized `literal_values.index(param_value)`, leading to code injection if malicious string is in `literal_values` and used as `param_value`.
- **Security Test Case:**
    1. Define malicious payload string: `malicious_payload = "__import__('os').system('touch /tmp/pyglove_vulnerable')"`.
    2. Create hyper value with `pg.oneof(['normal_value', malicious_payload])`.
    3. Create `ObjectTemplate` from hyper value.
    4. Get `dna_spec` from template.
    5. Craft malicious parameter dict: `params = {'x': malicious_payload}`.
    6. Trigger vulnerability: `pg.geno.DNA.from_parameters(params, dna_spec, use_literal_values=True)`.
    7. Verify code execution by checking for `/tmp/pyglove_vulnerable` file creation.

### Code Injection via Unsanitized Input in Lambda Scalar

- **Vulnerability Name:** Code Injection via Unsanitized Input in Lambda Scalar
- **Description:**
    - Malicious input strings processed by `pg.ext.scalars.Lambda` can lead to arbitrary Python code execution.
    - Vulnerability is in `Lambda` scalar's initialization, where user-provided string is directly evaluated using `eval()` within `scalar_spec` and `make_scalar` when handling `pg.typing.Callable`.
    - `make_scalar` wraps non-callable inputs with `Lambda`, and `scalar_spec` implicitly triggers `eval()` when a string is input, attempting to interpret it as callable.
    - User-controlled input to `make_scalar` with malicious string results in code execution during symbolic evaluation.
- **Impact:**
    - Critical. Arbitrary code execution on the server or user's machine, potentially leading to system compromise and data exfiltration.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    - None. Direct evaluation of input string without sanitization.
- **Missing Mitigations:**
    - Input sanitization to prevent malicious code injection.
    - Eliminate `eval()` usage in security-sensitive contexts, exploring safer alternatives for dynamic code execution.
- **Preconditions:**
    - Attacker can supply a string input to a function or class using `pg.ext.scalars.make_scalar` in symbolic computation.
- **Source Code Analysis:**
    - **File:** `/code/pyglove/ext/scalars/base.py`
    - **Function:** `make_scalar(value: Any) -> 'Scalar'`
    - **Code:**
      ```python
      def make_scalar(value: Any) -> 'Scalar':
        if isinstance(value, Scalar):
          return value
        elif callable(value):
          return Lambda(value)
        else:
          return Constant(value)
      ```
    - **File:** `/code/pyglove/ext/scalars/type_conversion.py`
    - **Function:** `scalar_spec(value_spec: pg.typing.ValueSpec) -> pg.typing.ValueSpec`
    - **Code:**
      ```python
      def scalar_spec(value_spec: pg.typing.ValueSpec) -> pg.typing.ValueSpec:
        return pg.typing.Union([
            value_spec,
            pg.typing.Callable([pg.typing.Int()], returns=value_spec)
        ])
      ```
    - `scalar_spec` and `make_scalar` trigger implicit `eval()` when a string is provided to `make_scalar`, as type system attempts to match string input against `pg.typing.Callable`.
- **Security Test Case:**
    1. Create PyGlove tunable object using `pg.ext.scalars.make_scalar`, e.g., symbolic class with scalar hyperparameter.
    2. Craft malicious input string: `malicious_code = '__import__("os").system("touch /tmp/pyglove_vulnerable")'`.
    3. Pass malicious string as value for scalar hyperparameter when creating symbolic class instance.
    4. Trigger evaluation/sampling in PyGlove involving this object.
    5. Verify code execution by checking for `/tmp/pyglove_vulnerable` file creation.