- Vulnerability Name: LogQL Injection via Sigma Rule Keywords

- Description:
  An attacker can inject malicious LogQL code into Sigma rules by crafting a rule that includes a Sigma `keywords` section containing LogQL operators or functions. When this rule is processed by the `pySigma-backend-loki` library, the injected LogQL code is incorporated directly into the generated LogQL query without proper sanitization. This allows the attacker to bypass the intended Sigma rule logic and execute arbitrary LogQL queries against the Grafana Loki instance.

  Steps to trigger the vulnerability:
  1. An attacker crafts a Sigma rule in YAML format.
  2. Within the `detection` section of the rule, the attacker includes a `keywords` section.
  3. Inside the `keywords` section, the attacker inserts a string that contains malicious LogQL code, such as `}`) or `}`, potentially aiming to close the query prematurely or append their own LogQL expressions.
  4. The attacker submits this malicious Sigma rule to the `pySigma-backend-loki` library for conversion.
  5. The library processes the rule, and the malicious LogQL code from the `keywords` section is incorporated into the generated LogQL query.
  6. When this generated LogQL query is executed against Grafana Loki, the injected malicious code is executed, potentially leading to sensitive data extraction or other unauthorized actions.

- Impact:
  Successful exploitation of this vulnerability can allow an attacker to perform LogQL injection. This can lead to:
  * **Sensitive Data Extraction:** The attacker can craft queries to extract sensitive log data that they are not authorized to access.
  * **Information Disclosure:** The attacker can gain insights into the system's logs and potentially the infrastructure.
  * **Data Manipulation (Potentially):** Depending on Loki's capabilities and configurations, it might be possible to manipulate or delete log data.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
  No specific sanitization or input validation is implemented for the `keywords` section in the provided code to prevent LogQL injection. The code directly incorporates the keywords into the LogQL query using line filters, without escaping or validating for potentially harmful LogQL syntax.

- Missing Mitigations:
  * **Input Sanitization:** Implement robust input sanitization for the `keywords` section of Sigma rules. This should involve identifying and escaping or rejecting any LogQL operators, functions, or syntax that could be used for injection.
  * **Validation of Sigma Rule Structure:** Validate the structure and content of the Sigma rule before conversion to ensure that it adheres to the expected schema and does not contain malicious code.
  * **Principle of Least Privilege:** Ensure that the user or system processing Sigma rules and executing LogQL queries operates with the minimum necessary privileges to reduce the potential impact of successful injection.

- Preconditions:
  * The `pySigma-backend-loki` library is deployed and used to convert Sigma rules into LogQL queries.
  * An attacker has the ability to submit or influence the Sigma rules that are processed by the library.

- Source Code Analysis:
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

- Security Test Case:
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

This vulnerability allows for LogQL injection via the `keywords` section of Sigma rules due to insufficient input sanitization in the `pySigma-backend-loki` library.