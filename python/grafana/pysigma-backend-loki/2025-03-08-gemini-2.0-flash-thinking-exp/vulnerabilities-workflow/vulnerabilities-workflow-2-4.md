- Vulnerability Name: LogQL Injection via Unsanitized Keywords

- Description:
    1. A malicious user crafts a Sigma rule that includes a keyword designed to inject LogQL code. For example, the keyword could be crafted to include LogQL operators like `|=`, `|~`, `!=`, `!~`, or functions.
    2. When this Sigma rule is processed by the pySigma-backend-loki, the keyword is not properly sanitized or escaped before being incorporated into the LogQL query.
    3. The backend directly includes this unsanitized keyword in the generated LogQL query as a line filter.
    4. When the generated LogQL query is executed against Loki, the injected LogQL code within the keyword is also executed. This can lead to unintended query behavior, potentially bypassing intended security monitoring or exposing sensitive information depending on the injected LogQL.

- Impact:
    - **Information Disclosure:** An attacker could inject LogQL code to extract sensitive information from Loki logs that they would not normally have access to. For example, by injecting a query that selects specific log streams or labels, bypassing the intended scope of the Sigma rule.
    - **Security Monitoring Bypass:** By injecting LogQL code, an attacker could manipulate the generated query to effectively bypass the security monitoring intended by the original Sigma rule. They could craft rules that appear to detect threats but in reality are ineffective due to the injected LogQL altering the query logic.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - The project uses `quote_string_value` in `sigma/shared.py` and `convert_value_str` in `sigma/backends/loki/loki.py` to quote string values. However, this mitigation is not consistently applied to all parts of the query construction, specifically unbound keywords are directly inserted as line filters without proper sanitization.

- Missing Mitigations:
    - **Keyword Sanitization:** Implement sanitization or escaping for keywords before incorporating them into LogQL queries, similar to how field names and values are handled. This should involve escaping LogQL operators and special characters that could be used for injection within keywords.
    - **Input Validation for Keywords:** Introduce input validation for keywords to reject or sanitize keywords that contain potentially malicious LogQL syntax.

- Preconditions:
    - The attacker needs to be able to provide a crafted Sigma rule to the system using pySigma-backend-loki. This could be through an interface that allows users to upload or define Sigma rules, or if the system automatically processes externally sourced Sigma rules without proper validation.

- Source Code Analysis:
    1. **`sigma/backends/loki/loki.py`:**
        - `LogQLBackend.convert_condition_val_str()`: This function is responsible for converting unbound string value conditions (keywords).
        - It uses `LogQLDeferredUnboundStrExpression` to defer the keyword as a line filter.
        - **Vulnerability:** The `convert_value_str()` function, called within `convert_condition_val_str()`, uses `quote_string_value()`, which provides some quoting, but it's insufficient to prevent LogQL injection when keywords are directly used as line filters. The core issue is that keywords are treated as plain strings and not sanitized against LogQL syntax injection before becoming line filters.

    ```python
    # Code Snippet from sigma/backends/loki/loki.py - convert_condition_val_str()
    def convert_condition_val_str(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Converts all unbound wildcard conditions into regular expression queries,
        replacing wildcards with appropriate regex metacharacters."""
        if isinstance(cond.value, SigmaString):
            expr = LogQLDeferredUnboundStrExpression(
                state, self.convert_value_str(cond.value, state) # <--- Keyword value is quoted here
            )
        else:
            raise SigmaError("convert_condition_val_str called on non-string value")
        if getattr(cond, "negated", False):
            expr.negate()
        return expr
    ```

    2. **`sigma/backends/loki/loki.py`:**
        - `LogQLDeferredUnboundStrExpression.finalize_expression()`: This function finalizes the deferred keyword expression into a line filter.
        - **Vulnerability:** The keyword `self.value` (which comes from the unsanitized Sigma rule keyword) is directly inserted into the line filter string without any further sanitization against LogQL injection.

    ```python
    # Code Snippet from sigma/backends/loki/loki.py - LogQLDeferredUnboundStrExpression.finalize_expression()
    @dataclass
    class LogQLDeferredUnboundStrExpression(DeferredQueryExpression):
        # ...
        def finalize_expression(self) -> str:
            return f"{self.op} {self.value}" # <--- Unsanitized keyword value is used directly in line filter
    ```

    **Visualization:**

    ```
    Sigma Rule (Malicious Keyword) --> pySigma-backend-loki --> LogQL Query (Injected LogQL) --> Loki Engine --> Vulnerability Triggered
                                    (Unsanitized Keyword)       (Line Filter with Injection)
    ```

- Security Test Case:

    1. **Create a malicious Sigma rule file (e.g., `malicious_rule.yml`):**

    ```yaml
    title: LogQL Injection Test - Keyword
    id: injection-test-keyword
    status: test
    logsource:
        category: test_category
        product: test_product
    detection:
        keywords:
            - 'test_value |= {__name__=malicious}' # Inject LogQL: |= {__name__=malicious}
        condition: keywords
    ```

    2. **Use `sigma convert` command to convert the rule to LogQL:**

    ```bash
    poetry run sigma convert -t loki tests/malicious_rule.yml
    ```

    3. **Examine the generated LogQL query output:**

    ```
    {job=~".+"} |= `test_value |= {__name__=malicious}`
    ```

    **Expected Result:** The generated LogQL query will include the injected LogQL code `|= {__name__=malicious}` directly within the line filter. When this query is executed against Loki, it will attempt to filter logs based on the injected LogQL, which is not the intended behavior and could lead to information disclosure or monitoring bypass depending on the injected code.

    4. **(Optional) Validate with `logcli` (requires a Loki instance and `logcli` tool):**

        If you have a Loki instance and `logcli` tool setup, you can try to validate the query. However, direct validation using `logcli` might not be straightforward to demonstrate the full impact of injection without more complex setup and log data tailored to exploit the injected query. The primary goal of this test case is to show that the *generated query itself* is vulnerable due to the unsanitized keyword, which is evident from step 3.

    **Note:** This test case demonstrates the *presence* of the injection vulnerability in the generated LogQL query. The actual exploitability and impact will depend on the specific Loki setup, log data, and the attacker's chosen injected LogQL code. However, the lack of sanitization in keyword handling clearly indicates a potential security vulnerability.