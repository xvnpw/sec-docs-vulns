## Vulnerability List

### Vulnerability 1: LogQL Injection via Sigma Rule Keywords

*   **Description:**
    1. An attacker crafts a malicious Sigma rule that includes a keyword containing LogQL control characters or commands.
    2. When the `LogQLBackend` processes this rule, it incorporates the malicious keyword directly into the LogQL query without sufficient sanitization.
    3. This allows the attacker to inject arbitrary LogQL commands, potentially bypassing intended query logic and gaining unauthorized access to log data or manipulating query execution.

*   **Impact:**
    *   **High:** An attacker could potentially execute arbitrary LogQL queries, allowing them to:
        *   Exfiltrate sensitive log data that they are not authorized to access.
        *   Modify or delete logs, potentially covering their tracks or disrupting operations.
        *   Cause Loki to perform resource-intensive queries, leading to performance degradation.

*   **Vulnerability Rank:** High

*   **Currently Implemented Mitigations:**
    *   None observed in the provided code. The code focuses on converting Sigma rule syntax to LogQL syntax but does not appear to sanitize Sigma rule content for LogQL injection vulnerabilities.

*   **Missing Mitigations:**
    *   **Input Sanitization:** Implement robust sanitization of Sigma rule keywords and other user-provided input before incorporating them into LogQL queries. This should include escaping LogQL control characters and potentially validating the structure of keywords to prevent injection attacks.
    *   **Input Validation:** Validate Sigma rules against a strict schema to ensure that keywords and other rule components conform to expected formats and do not contain malicious LogQL syntax.
    *   **Principle of Least Privilege:** Ensure that the permissions under which the generated LogQL queries are executed are restricted to the minimum necessary for legitimate log analysis, limiting the potential damage from injected commands.

*   **Preconditions:**
    *   The attacker must be able to submit a crafted Sigma rule to the `pySigma-backend-loki` library for conversion. This could be through a web interface, API, or any other mechanism that utilizes this library to process Sigma rules.

*   **Source Code Analysis:**
    1.  **File:** `/code/sigma/backends/loki/loki.py`
    2.  **Function:** `convert_condition_val_str` and `convert_condition_val_num`
    3.  These functions are responsible for converting Sigma `keywords` into LogQL unbound queries.
    4.  In `convert_condition_val_str` and `convert_condition_val_num`, the `value` from the Sigma rule keyword is directly incorporated into the LogQL query using string formatting:
        ```python
        class LogQLDeferredUnboundStrExpression(DeferredQueryExpression):
            # ...
            def finalize_expression(self) -> str:
                return f"{self.op} {self.value}"
        ```
    5.  The `self.value` here is derived directly from the Sigma rule's `keywords` without any sanitization for LogQL syntax.
    6.  **Visualization:**

        ```
        Sigma Rule (keywords: "malicious LogQL") --> LogQLBackend --> LogQL Query ("|= malicious LogQL") --> Loki (executes "malicious LogQL" as part of query)
        ```

*   **Security Test Case:**
    1.  **Setup:** Have a running instance of `pySigma-backend-loki` integrated with `sigma-cli` and a test Loki instance (or use `sigma_backend_tester.py` with `-v` flag).
    2.  **Craft Malicious Sigma Rule:** Create a Sigma rule (e.g., `malicious_rule.yml`) with a keyword designed to inject LogQL. For example, use a keyword that attempts to execute a metric query or bypass filters:

        ```yaml
        title: LogQL Injection Test
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            keywords:
                - '{job=~".+"} | line_format "Vulnerable" # ' # Inject malicious LogQL
            condition: keywords
        ```
    3.  **Convert Sigma Rule:** Use `sigma convert -t loki malicious_rule.yml` to convert the malicious Sigma rule into a LogQL query.
    4.  **Analyze Generated LogQL Query:** Inspect the output LogQL query. It will contain the injected LogQL command directly within the query string, likely after the initial stream selector:

        ```logql
        {job=~".+"} |~ `{job=~".+"} | line_format "Vulnerable" # `
        ```
    5.  **Execute LogQL Query (Simulated):**  If using `sigma_backend_tester.py -v`, the script attempts to validate the generated query against a Loki instance (or `logcli`). If you are manually testing, execute the generated LogQL query against your test Loki instance.
    6.  **Verify Injection:** Observe the results in Loki. If the injection is successful, you might see the output of the injected `line_format` command (e.g., "Vulnerable" lines appearing in your Loki output), or other effects depending on the injected LogQL. In this test case, if successful, every log line will be formatted to contain "Vulnerable", demonstrating code injection.

### Vulnerability 2: LogQL Injection via Custom Attributes (Parser/Log Source Selection)

*   **Description:**
    1. An attacker crafts a malicious Sigma rule that includes custom attributes (`loki_parser`, `logsource_loki_selection`) containing LogQL control characters or commands.
    2. The `LogQLBackend` directly uses these custom attributes to construct parts of the LogQL query (parser expression, log stream selector) without sanitization.
    3. This allows the attacker to inject arbitrary LogQL commands into critical query components, potentially altering query behavior and gaining unauthorized access or control.

*   **Impact:**
    *   **High:** Similar to Vulnerability 1, successful exploitation allows arbitrary LogQL execution, leading to data exfiltration, log manipulation, and potential performance issues in Loki. This vulnerability is particularly critical as it targets core query components like the parser and stream selector.

*   **Vulnerability Rank:** High

*   **Currently Implemented Mitigations:**
    *   None observed. The code retrieves and incorporates custom attributes directly into the LogQL query structure without sanitization.

*   **Missing Mitigations:**
    *   **Input Sanitization:** Sanitize custom attribute values (`loki_parser`, `logsource_loki_selection`) to prevent LogQL injection. This should include escaping control characters and validating attribute content against expected formats.
    *   **Input Validation:** Implement strict validation for custom attributes to ensure they adhere to predefined schemas and do not contain malicious LogQL syntax.

*   **Preconditions:**
    *   The attacker needs to be able to provide a crafted Sigma rule with malicious custom attributes. This could be through the same mechanisms as described in Vulnerability 1.

*   **Source Code Analysis:**
    1.  **File:** `/code/sigma/backends/loki/loki.py`
    2.  **Function:** `select_log_parser` and `select_log_stream`
    3.  These functions retrieve custom attributes from the Sigma rule and directly incorporate them into the LogQL query:
        ```python
        def select_log_parser(self, rule: SigmaRule) -> Union[str, LogQLLogParser]:
            if LokiCustomAttributes.PARSER.value in rule.custom_attributes:
                return rule.custom_attributes[LokiCustomAttributes.PARSER.value]
            # ...

        def select_log_stream(self, rule: SigmaRule) -> str:
            if LokiCustomAttributes.LOGSOURCE_SELECTION.value in rule.custom_attributes:
                return rule.custom_attributes[
                    LokiCustomAttributes.LOGSOURCE_SELECTION.value
                ]
            # ...
        ```
    4.  The returned values from these functions are directly embedded in the LogQL query string without sanitization, creating injection points.
    5.  **Visualization:**

        ```
        Sigma Rule (custom_attributes: {loki_parser: "malicious LogQL"}) --> LogQLBackend --> LogQL Query ("... | malicious LogQL | ...") --> Loki (executes "malicious LogQL" as parser)
        ```

*   **Security Test Case:**
    1.  **Setup:** Same as Vulnerability 1.
    2.  **Craft Malicious Sigma Rule:** Create a Sigma rule (e.g., `malicious_custom_attr_rule.yml`) with a malicious custom attribute for `loki_parser`:

        ```yaml
        title: LogQL Custom Attribute Injection Test
        status: test
        logsource:
            category: test_category
            product: test_product
        loki_parser: 'json | line_format "Injected" # ' # Malicious parser injection
        detection:
            sel:
                fieldA: valueA
            condition: sel
        ```
    3.  **Convert Sigma Rule:** Use `sigma convert -t loki malicious_custom_attr_rule.yml`.
    4.  **Analyze Generated LogQL Query:** Inspect the output LogQL query. The `loki_parser` section will contain the injected LogQL command:

        ```logql
        {job=~".+"} | json | line_format "Injected" #  | logfmt | fieldA=~`(?i)^valueA$`
        ```
    5.  **Execute LogQL Query (Simulated):**  Use `sigma_backend_tester.py -v` or manually execute against Loki.
    6.  **Verify Injection:** Check Loki output. Successful injection via `loki_parser` could lead to logs being incorrectly parsed or the injected `line_format` command altering the output as in Vulnerability 1, confirming the vulnerability. Similarly, test `logsource_loki_selection` by injecting malicious stream selectors that could broaden the scope of the query beyond intended boundaries. For example:

        ```yaml
        title: LogQL Custom Attribute Injection Test - Log Source Selection
        status: test
        logsource:
            category: test_category
            product: test_product
        logsource_loki_selection: '{job=~".+"} or {job=~"malicious_job"}' # Malicious stream selector injection
        detection:
            sel:
                fieldA: valueA
            condition: sel
        ```
        This injected `logsource_loki_selection` would cause the query to potentially include logs from a job named "malicious_job", even if it's not intended by the original Sigma rule.