* Vulnerability Name: LogQL Injection via Unsanitized Custom Attributes in `SetCustomAttributeTransformation`
* Description:
    1. An attacker crafts a malicious Sigma rule YAML file.
    2. Within this rule, the attacker defines a processing pipeline that includes `SetCustomAttributeTransformation`.
    3. In the `SetCustomAttributeTransformation`, the attacker sets a custom attribute (e.g., `loki_parser`, `logsource_loki_selection`) to a value that contains malicious LogQL code. For example, the attacker can set `loki_parser` to `'json | {malicious LogQL code}'`.
    4. An application using the `pysigma-backend-loki` library ingests this crafted Sigma rule.
    5. The application applies the defined processing pipeline to the rule, which executes the `SetCustomAttributeTransformation`.
    6. The `SetCustomAttributeTransformation` sets the custom attribute in the Sigma rule's `custom_attributes` dictionary with the attacker-provided malicious LogQL code as its value.
    7. When the application uses `LogQLBackend` to convert this Sigma rule into a LogQL query, the backend retrieves the attacker-controlled custom attribute value.
    8. The `LogQLBackend` incorporates this unsanitized value directly into the generated LogQL query string.
    9. If this generated LogQL query is then executed against a Grafana Loki instance, the injected malicious LogQL code will be executed as part of the query.
* Impact:
    - **Unauthorized Data Access:** An attacker could craft malicious LogQL to extract sensitive data from Loki logs that they are not authorized to access.
    - **Query Manipulation:** An attacker could inject LogQL code to manipulate or disrupt legitimate Loki queries, potentially hiding malicious activity or causing operational issues.
    - **Potential for further exploitation:** Depending on the context and permissions of the application and Loki setup, further exploitation might be possible.
* Vulnerability Rank: High
* Currently Implemented Mitigations:
    - None. The code directly uses the provided custom attribute values without any sanitization or validation.
* Missing Mitigations:
    - **Input Sanitization:** The `SetCustomAttributeTransformation` should sanitize or validate the `value` input to prevent injection of malicious LogQL code.  Specifically, when setting attributes like `loki_parser` or `logsource_loki_selection`, the input `value` should be checked against a whitelist of allowed characters or patterns, or parsed and validated to ensure it only contains safe LogQL constructs.
    - **Principle of Least Privilege:** Applications using this library should avoid allowing users to provide arbitrary Sigma rules or processing pipelines, especially if those users are not trusted. If user-provided rules are necessary, implement strict access controls and review processes.
* Preconditions:
    - An application must be using the `pysigma-backend-loki` library.
    - This application must allow users to provide custom Sigma rules that are processed by a pipeline containing `SetCustomAttributeTransformation`.
    - The application must not sanitize or validate user-provided custom attribute values before using them in `SetCustomAttributeTransformation`.
    - The custom attribute set by `SetCustomAttributeTransformation` must be one that is used by `LogQLBackend` to influence the generated LogQL query (e.g., `loki_parser`, `logsource_loki_selection`).
* Source Code Analysis:
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

* Security Test Case:
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