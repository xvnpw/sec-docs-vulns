## Combined Vulnerability List

### Vulnerability 1: LogQL Injection via Unsanitized Custom Attributes in `SetCustomAttributeTransformation`

*   **Description:**
    1. An attacker crafts a malicious Sigma rule YAML file.
    2. Within this rule, the attacker defines a processing pipeline that includes `SetCustomAttributeTransformation`.
    3. In the `SetCustomAttributeTransformation`, the attacker sets a custom attribute (e.g., `loki_parser`, `logsource_loki_selection`) to a value that contains malicious LogQL code. For example, the attacker can set `loki_parser` to `'json | {malicious LogQL code}'`.
    4. An application using the `pysigma-backend-loki` library ingests this crafted Sigma rule.
    5. The application applies the defined processing pipeline to the rule, which executes the `SetCustomAttributeTransformation`.
    6. The `SetCustomAttributeTransformation` sets the custom attribute in the Sigma rule's `custom_attributes` dictionary with the attacker-provided malicious LogQL code as its value.
    7. When the application uses `LogQLBackend` to convert this Sigma rule into a LogQL query, the backend retrieves the attacker-controlled custom attribute value.
    8. The `LogQLBackend` incorporates this unsanitized value directly into the generated LogQL query string.
    9. If this generated LogQL query is then executed against a Grafana Loki instance, the injected malicious LogQL code will be executed as part of the query.

*   **Impact:**
    - **Unauthorized Data Access:** An attacker could craft malicious LogQL to extract sensitive data from Loki logs that they are not authorized to access.
    - **Query Manipulation:** An attacker could inject LogQL code to manipulate or disrupt legitimate Loki queries, potentially hiding malicious activity or causing operational issues.
    - **Potential for further exploitation:** Depending on the context and permissions of the application and Loki setup, further exploitation might be possible.

*   **Vulnerability Rank:** High

*   **Currently Implemented Mitigations:**
    - None. The code directly uses the provided custom attribute values without any sanitization or validation.

*   **Missing Mitigations:**
    - **Input Sanitization:** The `SetCustomAttributeTransformation` should sanitize or validate the `value` input to prevent injection of malicious LogQL code.  Specifically, when setting attributes like `loki_parser` or `logsource_loki_selection`, the input `value` should be checked against a whitelist of allowed characters or patterns, or parsed and validated to ensure it only contains safe LogQL constructs.
    - **Principle of Least Privilege:** Applications using this library should avoid allowing users to provide arbitrary Sigma rules or processing pipelines, especially if those users are not trusted. If user-provided rules are necessary, implement strict access controls and review processes.

*   **Preconditions:**
    - An application must be using the `pysigma-backend-loki` library.
    - This application must allow users to provide custom Sigma rules that are processed by a pipeline containing `SetCustomAttributeTransformation`.
    - The application must not sanitize or validate user-provided custom attribute values before using them in `SetCustomAttributeTransformation`.
    - The custom attribute set by `SetCustomAttributeTransformation` must be one that is used by `LogQLBackend` to influence the generated LogQL query (e.g., `loki_parser`, `logsource_loki_selection`).

*   **Source Code Analysis:**
    1. **File: `/code/sigma/pipelines/loki/loki.py`**:
        ```python
        @dataclass
        class SetCustomAttributeTransformation(Transformation):
            """Sets an arbitrary custom attribute on a rule, that will be used during processing."""

            attribute: str
            value: Any

            def apply(
                self, pipeline: ProcessingPipeline, rule: Union[SigmaRule, SigmaCorrelationRule]
            ) -> None:
                super().apply(pipeline, rule)
                rule.custom_attributes[self.attribute] = self.value
        ```
        - The `SetCustomAttributeTransformation` class directly assigns the provided `value` to the `rule.custom_attributes[self.attribute]` without any sanitization or validation. This is the core of the vulnerability.

    2. **File: `/code/sigma/backends/loki/loki.py`**:
        ```python
        def select_log_parser(self, rule: SigmaRule) -> Union[str, LogQLLogParser]:
            """Select a relevant log parser based on common approaches to ingesting data into Loki.
            Currently defaults to logfmt, but will use the json parser for Windows, Azure and Zeek
            signatures."""
            if LokiCustomAttributes.PARSER.value in rule.custom_attributes:
                return rule.custom_attributes[LokiCustomAttributes.PARSER.value]
            # ...
        ```
        ```python
        def select_log_stream(self, rule: SigmaRule) -> str:
            """Select a logstream based on the logsource information included within a rule and
            following the assumptions described in select_log_parser."""
            if LokiCustomAttributes.LOGSOURCE_SELECTION.value in rule.custom_attributes:
                return rule.custom_attributes[
                    LokiCustomAttributes.LOGSOURCE_SELECTION.value
                ]
            # ...
        ```
        ```python
        def finalize_query(
            self,
            rule: SigmaRule,
            query: Union[str, DeferredQueryExpression],
            index: int,
            state: ConversionState,
            output_format: str,
        ) -> Union[str, DeferredQueryExpression]:
            """Complete the conversion of the query, selecting an appropriate log parser if necessary,
            and pre-pending deferred line filters."""
            if isinstance(rule, SigmaRule):
                # selecting an appropriate log parser to use
                log_parser = str(self.select_log_parser(rule))
                query_log_parser = (
                    f"{'| ' if not log_parser.lstrip().startswith('|') else ''}{log_parser}"
                    f"{' |' if not log_parser.rstrip().endswith('|') else ''}"
                )
                # ...
                query = self.select_log_stream(rule) + " " + query
                return super().finalize_query(rule, query, index, state, output_format)
            # ...
        ```
        - The `select_log_parser` and `select_log_stream` functions directly retrieve values from `rule.custom_attributes` using `LokiCustomAttributes.PARSER.value` and `LokiCustomAttributes.LOGSOURCE_SELECTION.value` respectively.
        - The `finalize_query` function then incorporates these retrieved values (which can be attacker-controlled) directly into the LogQL query string without any further checks.

    **Visualization:**

    ```
    User-Provided Sigma Rule --> Application --> SetCustomAttributeTransformation (Unsanitized Value) --> rule.custom_attributes --> LogQLBackend.select_log_parser/select_log_stream --> LogQL Query Construction (Malicious LogQL Injection) --> Loki Query Execution
    ```

*   **Security Test Case:**
    1. Create a file named `malicious_rule.yml` with the following content:
        ```yaml
        title: LogQL Injection Test
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            sel:
                fieldA: valueA
            condition: sel
        processing:
            - name: InjectMaliciousLogQL
              priority: 10
              transformations:
                - type: set_custom_attribute
                  attribute: loki_parser
                  value: 'json | drop | {job=~".+"} | line_format "Vulnerable Rule Triggered: LogQL Injection Successful"'
        ```
        This rule injects `json | drop | {job=~".+"} | line_format "Vulnerable Rule Triggered: LogQL Injection Successful"` into the `loki_parser` custom attribute. `drop` is a LogQL operator that discards all logs, and the line_format is used to output a specific message, which will help to identify if the injection was successful.

    2. Create a Python script (e.g., `test_exploit.py`) to convert this rule using `pysigma-backend-loki`:
        ```python
        from sigma.collection import SigmaCollection
        from sigma.backends.loki import LogQLBackend
        from sigma.pipelines.loki import SetCustomAttributeTransformation

        # Load the malicious rule
        with open("malicious_rule.yml", "r") as f:
            sigma_rule = SigmaCollection.from_yaml(f.read())

        # Create Loki backend (no specific pipeline needed as the rule defines its own)
        backend = LogQLBackend()

        # Convert the rule
        logql_query = backend.convert(sigma_rule)

        # Print the generated LogQL query
        print(logql_query)
        ```

    3. Run the Python script: `python test_exploit.py`

    4. **Expected Output (Vulnerable):** The output LogQL query will contain the injected malicious LogQL code within the `loki_parser` section. For example, the output should be similar to:
        ```
        ["{job=~".+"} | json | drop | {job=~".+"} | line_format \\"Vulnerable Rule Triggered: LogQL Injection Successful\\" | logfmt | fieldA=~`(?i)^valueA$`"]
        ```
        - Notice the injected  `json | drop | {job=~".+"} | line_format \\"Vulnerable Rule Triggered: LogQL Injection Successful\\"` part prepended to the standard query components, demonstrating successful injection.

    5. **Mitigation Test (After Implementing Sanitization):** After implementing input sanitization in `SetCustomAttributeTransformation` to prevent LogQL injection (e.g., by whitelisting allowed characters or validating against a safe LogQL grammar), running the same test case should result in either:
        - An error during rule processing, indicating invalid input.
        - A sanitized LogQL query where the malicious code is removed or escaped in a way that it is no longer executable as LogQL injection. For example, the injected part might be treated as a literal string value if proper escaping is implemented.

    This test case demonstrates how an attacker can inject malicious LogQL code through a custom attribute, confirming the vulnerability.

### Vulnerability 2: LogQL Injection via Sigma Rule Keywords

*   **Description:**
    1. A malicious user crafts a Sigma rule that includes a keyword designed to inject LogQL code. For example, the keyword could be crafted to include LogQL operators like `|=`, `|~`, `!=`, `!~`, or functions or control characters like `}`.
    2. When this Sigma rule is processed by the pySigma-backend-loki, the keyword is not properly sanitized or escaped before being incorporated into the LogQL query.
    3. The backend directly includes this unsanitized keyword in the generated LogQL query as a line filter.
    4. When the generated LogQL query is executed against Loki, the injected LogQL code within the keyword is also executed. This can lead to unintended query behavior, potentially bypassing intended security monitoring or exposing sensitive information depending on the injected LogQL.

*   **Impact:**
    - **Information Disclosure:** An attacker could inject LogQL code to extract sensitive information from Loki logs that they would not normally have access to. For example, by injecting a query that selects specific log streams or labels, bypassing the intended scope of the Sigma rule.
    - **Security Monitoring Bypass:** By injecting LogQL code, an attacker could manipulate the generated query to effectively bypass the security monitoring intended by the original Sigma rule. They could craft rules that appear to detect threats but in reality are ineffective due to the injected LogQL altering the query logic.
    - **Sensitive Data Extraction:** The attacker can craft queries to extract sensitive log data that they are not authorized to access.
    - **Information Disclosure:** The attacker can gain insights into the system's logs and potentially the infrastructure.
    - **Data Manipulation (Potentially):** Depending on Loki's capabilities and configurations, it might be possible to manipulate or delete log data.

*   **Vulnerability Rank:** Critical

*   **Currently Implemented Mitigations:**
    - The project uses `quote_string_value` in `sigma/shared.py` and `convert_value_str` in `sigma/backends/loki/loki.py` to quote string values. However, this mitigation is not consistently applied to all parts of the query construction, specifically unbound keywords are directly inserted as line filters without proper sanitization. No specific sanitization or input validation is implemented for the `keywords` section in the provided code to prevent LogQL injection. The code directly incorporates the keywords into the LogQL query using line filters, without escaping or validating for potentially harmful LogQL syntax.

*   **Missing Mitigations:**
    - **Keyword Sanitization:** Implement sanitization or escaping for keywords before incorporating them into LogQL queries, similar to how field names and values are handled. This should involve escaping LogQL operators and special characters that could be used for injection within keywords. Implement robust input sanitization for the `keywords` section of Sigma rules. This should involve identifying and escaping or rejecting any LogQL operators, functions, or syntax that could be used for injection.
    - **Input Validation for Keywords:** Introduce input validation for keywords to reject or sanitize keywords that contain potentially malicious LogQL syntax. Validate Sigma rules against a strict schema to ensure that keywords and other rule components conform to expected formats and do not contain malicious LogQL syntax.
    - **Principle of Least Privilege:** Ensure that the permissions under which the generated LogQL queries are executed are restricted to the minimum necessary for legitimate log analysis, limiting the potential damage from injected commands. Ensure that the user or system processing Sigma rules and executing LogQL queries operates with the minimum necessary privileges to reduce the potential impact of successful injection.

*   **Preconditions:**
    - The attacker needs to be able to provide a crafted Sigma rule to the system using pySigma-backend-loki. This could be through an interface that allows users to upload or define Sigma rules, or if the system automatically processes externally sourced Sigma rules without proper validation. The `pySigma-backend-loki` library is deployed and used to convert Sigma rules into LogQL queries. An attacker has the ability to submit or influence the Sigma rules that are processed by the library.

*   **Source Code Analysis:**
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
    1. File: `/code/sigma/backends/loki/loki.py`
    2. Function: `convert_condition_val_str(self, cond: ConditionValueExpression, state: ConversionState)`
    3. This function is responsible for converting unbound string value conditions (like keywords) into LogQL.
    4. The code constructs a `LogQLDeferredUnboundStrExpression` which is used for line filters.
    5. The value from Sigma rule `keywords` is passed to `self.convert_value_str(cond.value, state)`.
    6. Function: `convert_value_str(self, s: SigmaString, state: ConversionState) -> str` in the same file.
    7. This function calls `quote_string_value(s)`.
    8. Function: `quote_string_value(s: SigmaString) -> str` in `/code/sigma/shared.py`.
    9. This function checks if the string `s` contains backtick (`) and if so uses double quotes (`"`) for quoting and escapes backslash (`\`) and double quote (`"`) characters using backslash (`\`). If backtick is not present, it uses backtick quotes without any escaping other than what's already in `s.convert()`.
    10. **Vulnerability:** While `quote_string_value` provides some basic quoting, it **does not sanitize** LogQL operators or functions within the string. If an attacker inserts LogQL syntax like `}`) or `}`, these characters are not escaped or removed. When backtick quoting is used (and it will be used if no backticks are present in the input string), no escaping is performed at all by `quote_string_value` beyond what's already in `s.convert()`, which is minimal for SigmaString by default. This allows for LogQL injection through the `keywords` section because the provided string is incorporated into the LogQL query without sufficient sanitization.

*   **Security Test Case:**
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
    1. **Setup:** Have a test environment where you can run `sigma convert` command from `sigma-cli` with `loki` plugin installed, and you can inspect the generated LogQL query.
  2. **Craft Malicious Sigma Rule:** Create a Sigma rule YAML file (e.g., `malicious_rule.yml`) with the following content:
     ```yaml
     title: LogQL Injection Test - Keywords
     status: test
     logsource:
         category: test_category
         product: test_product
     detection:
         keywords:
             - 'test_value`} | logfmt | {__name__=~".+"} | line_format "{{.message}} {{.__name__}}"` # Malicious injection '
         condition: keywords
     ```
     **Explanation of Malicious Payload:**
     - `test_value`} `:  Starts with a benign value `test_value` followed by `}` to potentially close a LogQL expression.
     - `| logfmt | {__name__=~".+"} | line_format "{{.message}} {{.__name__}}" `: This is the injected LogQL code.
       - `| logfmt`: Ensures logfmt parsing (though might be redundant here).
       - `{__name__=~".+"}`:  A LogQL stream selector that selects all streams (intending to fetch all logs). `__name__` is a common Loki label.
       - `| line_format "{{.message}} {{.__name__}}"`: Formats the output to include the original log message and the `__name__` label, useful for demonstration.

  3. **Convert Sigma Rule:** Use the `sigma convert` command to convert the malicious Sigma rule to a Loki LogQL query:
     ```sh
     poetry run sigma convert -t loki tests/malicious_rule.yml
     ```
  4. **Inspect Generated Query:** Examine the outputted LogQL query. It should resemble something like this (the exact job selector might vary):
     ```
     {job=~".+"} |~ `(?i)test_value} | logfmt | {__name__=~".+"} | line_format "{{.message}} {{.__name__}}"`
     ```
     **Verification:**
     - Verify that the injected LogQL code  `| logfmt | {__name__=~".+"} | line_format "{{.message}} {{.__name__}}"` is present in the generated query, directly after the (partially quoted) keyword value, and is not escaped or sanitized. This confirms the LogQL injection vulnerability.
     - If you execute this query against a Loki instance, it will likely return all logs due to the injected `{__name__=~".+"}` stream selector, demonstrating successful injection and impact.