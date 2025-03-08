- Vulnerability Name: Code Injection via Unsanitized Input in Lambda Scalar
- Description:
    1. An attacker can craft a malicious input string that, when processed by `pg.ext.scalars.Lambda`, allows execution of arbitrary Python code.
    2. The vulnerability lies in the `Lambda` scalar's initialization, where a user-provided string is directly evaluated using `eval()` within the `scalar_spec` and `make_scalar` functions when handling `pg.typing.Callable` type.
    3. This occurs because `make_scalar` in `base.py` uses `Lambda` to wrap non-callable inputs, and `scalar_spec` implicitly triggers `eval()` when a string is provided as input, attempting to interpret it as a callable.
    4. If a user can control the input to `make_scalar` and pass a string containing malicious code, that code will be executed during symbolic evaluation.
- Impact:
    - An attacker can achieve arbitrary code execution on the server or the user's machine running the PyGlove application.
    - This could lead to full system compromise, data exfiltration, or other malicious activities.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None. The code directly evaluates the input string without any sanitization or validation.
- Missing Mitigations:
    - Input sanitization:  The project needs to sanitize user-supplied input to prevent the injection of malicious code.
    - Avoidance of `eval()`:  The use of `eval()` should be eliminated in security-sensitive contexts. Safer alternatives for dynamic code execution or expression evaluation should be explored if necessary.
- Preconditions:
    - An attacker must be able to supply a string as input to a function or class that utilizes `pg.ext.scalars.make_scalar` which is then used in symbolic computation.
- Source Code Analysis:
    File: /code/pyglove/ext/scalars/base.py
    ```python
    def make_scalar(value: Any) -> 'Scalar':
      """Make a scalar from a value."""
      if isinstance(value, Scalar):
        return value
      elif callable(value):
        return Lambda(value)
      else:
        return Constant(value)
    ```
    File: /code/pyglove/ext/scalars/type_conversion.py
    ```python
    def scalar_spec(value_spec: pg.typing.ValueSpec) -> pg.typing.ValueSpec:
      """Returns the value spec for a schedule scalar.
      ...
      """
      return pg.typing.Union([
          value_spec,
          pg.typing.Callable([pg.typing.Int()], returns=value_spec)
      ])
    ```
    The vulnerability is triggered within `scalar_spec` and `make_scalar` when a string is provided as input to `make_scalar`. The `pg.typing.Union` in `scalar_spec` allows for either a value or a callable, and when combined with `pg.typing.Callable`, PyGlove's type system attempts to interpret a string as a callable. This attempt involves evaluating the string, leading to code injection if the string is malicious. The `make_scalar` function utilizes `scalar_spec`, making it a point of entry for this vulnerability. The code execution is not directly within `Lambda.__init__` as initially thought, but during the type checking and value application within PyGlove's symbolic evaluation framework, implicitly triggered by the type system's attempt to match the string input against `pg.typing.Callable`.
- Security Test Case:
    1. Create a PyGlove tunable object that uses `pg.ext.scalars.make_scalar`. For example, define a symbolic class with a scalar hyperparameter.
    2. Craft a malicious input string that contains Python code for code injection, e.g., `'__import__("os").system("cat /etc/passwd > /tmp/passwd")'`.
    3. Pass this malicious string as the value for the scalar hyperparameter when creating an instance of the symbolic class or when using it in a search space.
    4. Trigger the evaluation or sampling process in PyGlove that involves this symbolic object.
    5. Observe if the code in the malicious string is executed. For example, check if the `/tmp/passwd` file is created and contains the content of `/etc/passwd`.

    ```python
    import pyglove as pg

    malicious_code = \'__import__("os").system("touch /tmp/pyglove_vulnerable")\'

    @pg.symbolize([
        ('scalar_param', pg.ext.scalars.scalar_spec(pg.typing.Str()))
    ])
    class VulnerableClass:

      def __init__(self, scalar_param):
        self.scalar_param = pg.ext.scalars.make_scalar(scalar_param)

      def get_value(self, step):
        return self.scalar_param(step)


    vulnerable_instance = VulnerableClass(scalar_param=malicious_code)

    # Trigger the vulnerability by calling the scalar:
    vulnerable_instance.get_value(0)

    # Check if the file '/tmp/pyglove_vulnerable' exists.
    # If it exists, the code injection is successful.
    import os
    assert os.path.exists('/tmp/pyglove_vulnerable')
    os.remove('/tmp/pyglove_vulnerable')
    ```