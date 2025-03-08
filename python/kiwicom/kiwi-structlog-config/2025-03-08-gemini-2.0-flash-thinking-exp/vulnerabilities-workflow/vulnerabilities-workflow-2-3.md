### Vulnerability List

- Vulnerability Name: Incomplete Data Anonymization due to Overly Specific Regular Expressions

- Description:
    1. A user configures the `Anonymize` processor with regular expressions to mask sensitive data in logs.
    2. The user defines a regular expression that is too specific and does not account for variations in the format of the sensitive data.
    3. The application logs events containing sensitive data that matches both the intended format and variations not covered by the overly specific regular expression.
    4. The `Anonymize` processor only applies the masking to the data matching the specific format defined in the regex.
    5. Sensitive data that does not match the overly specific regex is logged in plain text, bypassing the intended anonymization.

- Impact:
    -洩漏 sensitive information in logs due to incomplete anonymization.
    -Compromise of personal data, such as email addresses, phone numbers, or credit card numbers, if the overly specific regex fails to cover all variations of these data types.
    -Potential compliance violations if logging sensitive data in plain text is against regulations (e.g., GDPR, PCI DSS).

- Vulnerability Rank: Medium

- Currently Implemented Mitigations:
    - No specific mitigations in the code to prevent users from creating overly specific regex patterns. The `Anonymize` processor applies the provided regex patterns as configured.

- Missing Mitigations:
    - **Documentation Enhancement:** Improve documentation to strongly emphasize the importance of writing comprehensive and robust regular expressions for anonymization. Provide examples of common pitfalls with overly specific regex patterns and suggest best practices for creating more general patterns.
    - **Regex Validation (Optional):** Consider adding an optional regex validation mechanism during the configuration of the `Anonymize` processor. This could involve:
        - Providing a set of predefined regex patterns for common sensitive data types (e.g., email, phone, credit card).
        - Allowing users to test their custom regex patterns against sample data to visualize the anonymization results and identify potential gaps.
        - Implementing warnings or suggestions if a regex pattern appears to be too narrow or might miss common variations.

- Preconditions:
    - The application uses the `kiwi-structlog-config` library.
    - The `Anonymize` processor is configured to anonymize specific data fields.
    - The user provides regular expressions for anonymization that are overly specific and do not cover all variations of the sensitive data.
    - Logs are generated that contain sensitive data in formats not covered by the overly specific regex.

- Source Code Analysis:
    1. **`kw/structlog_config/processors.py` - `Anonymize` class:**
        ```python
        class Anonymize:
            # ...
            def __call__(self, logger, method_name, event_dict):
                for key in set(event_dict) & set(self.patterns):
                    pattern, replacement = self.patterns[key]
                    event_dict[key] = re.sub(pattern, replacement, event_dict[key])
                return event_dict
        ```
        - The `Anonymize.__call__` method iterates through the configured patterns and applies the corresponding regex substitution using `re.sub`.
        - If the provided `pattern` in `self.patterns` is overly specific, `re.sub` will only replace matches to that specific pattern. Data that does not match the pattern will not be anonymized.
    2. **`kw/structlog_config/config.py` - Configuration:**
        - The configuration of the `Anonymize` processor is done by users when they instantiate it and pass it to `configure_structlog` as part of `extra_processors`.
        - The library does not enforce any checks or validation on the provided regex patterns.

- Security Test Case:
    1. **Setup:**
        - Install the `kiwi-structlog-config` library in a test environment.
        - Create a test Python application that uses `structlog` and `kiwi-structlog-config`.
    2. **Configuration:**
        - Configure `structlog` with the `Anonymize` processor.
        - Define an overly specific regex pattern for email anonymization, for example, only targeting `@example.com` domains:
          ```python
          from kw.structlog_config import configure_structlog, processors
          anonymize = processors.Anonymize(patterns=[
              ({"email"}, r"(\w+)@example\.com", r"\1@masked.com"),
          ])
          configure_structlog(extra_processors=[anonymize])
          ```
        - Configure standard logging to use structlog.
        ```python
        from kw.structlog_config import configure_stdlib_logging
        configure_stdlib_logging()
        import logging
        logger = logging.getLogger(__name__)
        ```
    3. **Logging Events:**
        - In the test application, log events containing email addresses with different domains, including one that matches the specific regex and one that does not:
          ```python
          logger.info("User login attempt", email="test@example.com", event="login_attempt") # Matches regex, should be anonymized
          logger.info("User login attempt", email="test@gmail.com", event="login_attempt")   # Does not match regex, should NOT be anonymized (vulnerability)
          ```
    4. **Verification:**
        - Examine the logs generated by the test application.
        - **Expected Result (Vulnerability):**
            - The log entry for `test@example.com` should have the email anonymized (e.g., `test@masked.com`).
            - The log entry for `test@gmail.com` should have the email logged in plain text (`test@gmail.com`), demonstrating the incomplete anonymization due to the overly specific regex.
        - **Desired Result (Mitigated):**
            - After mitigation (e.g., improved regex or validation), both email addresses should be appropriately anonymized, regardless of the domain. For example, using a more general regex like `r"[\w.-]+@[\w.-]+"`

This test case demonstrates that using an overly specific regular expression in the `Anonymize` processor can lead to sensitive data being logged in plain text when it does not exactly match the narrow pattern, highlighting the vulnerability.