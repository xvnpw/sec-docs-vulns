## Vulnerabilities

### Vulnerability: Insecure Anonymization due to Regex Misconfiguration

* Description:
    * A developer using the `kiwi-structlog-config` library can misconfigure the `Anonymize` processor by providing incorrect regular expressions or specifying the wrong keys for sensitive data.
    * This misconfiguration can lead to sensitive information not being properly anonymized and subsequently being logged in plain text.
    * An attacker who gains access to these logs can then retrieve the exposed sensitive information.
    * Steps to trigger vulnerability:
        1. A developer implements logging in their application using `kiwi-structlog-config`.
        2. The developer intends to anonymize credit card numbers using the `Anonymize` processor.
        3. The developer provides an incorrect regular expression in the `patterns` argument of the `Anonymize` processor, for example, a regex that doesn't match all possible credit card formats or has flaws.
        4. The developer also might incorrectly specify the keys to be anonymized, missing some keys where sensitive information is logged.
        5. The application logs events containing credit card numbers in a format that is not matched by the provided regex, or under keys that are not configured for anonymization.
        6. The logs are stored and become accessible to an attacker (e.g., through a compromised logging system or monitoring platform).
        7. The attacker analyzes the logs and finds unanonymized credit card numbers.

* Impact:
    * High.
    * Exposure of sensitive information, such as credit card numbers, personal identification information, or other confidential data, within application logs.
    * This can lead to:
        * Financial fraud if credit card numbers are exposed.
        * Identity theft if personal identification information is leaked.
        * Reputational damage and legal repercussions for the organization due to data breach.
        * Loss of customer trust.

* Vulnerability Rank: High

* Currently implemented mitigations:
    * None in the code itself to prevent misconfiguration. The library provides the `Anonymize` processor, but it relies on the developer to configure it correctly.
    * The `README.md` provides an example of how to use the `Anonymize` processor, but it doesn't explicitly warn about the risks of misconfiguration or best practices for creating secure anonymization patterns.

* Missing mitigations:
    * **Input validation and pattern testing:** The `Anonymize` processor could include functionality to validate the provided regex patterns and keys. This could involve:
        * Basic regex syntax checking.
        * Optional testing functionality to allow developers to test their patterns against sample data and verify the anonymization outcome.
        * Warn developers about overly broad or potentially insecure regex patterns (e.g., patterns that are too generic and might anonymize unintended data).
    * **Documentation with security best practices:** Enhance the documentation to include:
        * Clear warnings about the security risks of misconfiguring the `Anonymize` processor.
        * Best practices for creating robust and secure regex patterns for anonymization.
        * Examples of common misconfigurations and how to avoid them.
        * Guidance on testing anonymization configurations.
        * Recommendation to review and regularly update anonymization patterns as data formats evolve.
    * **Predefined secure patterns:** Consider providing a set of predefined, well-tested regex patterns for common sensitive data types (e.g., credit card numbers, email addresses, phone numbers). Developers could use these as a starting point or as examples to build upon.

* Preconditions:
    * A developer must use the `Anonymize` processor from the `kiwi-structlog-config` library.
    * The developer must misconfigure the `Anonymize` processor by providing incorrect regex patterns or keys in the `patterns` argument.
    * Sensitive data that should be anonymized must be logged by the application using the configured logger.
    * An attacker must gain access to the logs where the unanonymized sensitive data is stored.

* Source code analysis:
    * **File: /code/kw/structlog_config/processors.py**
    * **Class `Anonymize`:**
        ```python
        class Anonymize:
            r"""Anonymize personal data.

            anonymize = Anonymize(patterns=[
                ({"visa", "amex"}, r"\d+(\d{4})", "*"*12 + r"\1"),
                ({"passenger_name"}, r"(\w)\w*", r"\1***"),
            ])
            """

            def __init__(self, patterns):
                self.patterns = self.build_mapping(patterns)

            @classmethod
            def build_mapping(cls, patterns):
                """Flatten input in a dict and compile regex patterns."""
                mapping = {}
                for keys, pattern, replacement in patterns:
                    regex = re.compile(pattern) # Regex is compiled here, but no validation is performed.
                    mapping.update({key: (regex, replacement) for key in keys})
                return mapping

            def __call__(self, logger, method_name, event_dict):
                for key in set(event_dict) & set(self.patterns):
                    pattern, replacement = self.patterns[key]
                    event_dict[key] = re.sub(pattern, replacement, event_dict[key]) # Regex substitution is performed.
                return event_dict
        ```
        * The `Anonymize` class takes a list of `patterns` in its constructor. Each pattern is a tuple containing:
            * `keys`: A set of keys in the `event_dict` to apply the anonymization to.
            * `pattern`: A regular expression string.
            * `replacement`: The string to replace the matched parts with.
        * The `build_mapping` method compiles the regex patterns using `re.compile()`. **Crucially, there is no validation or error handling for the provided regex patterns.** If a developer provides an incorrect or ineffective regex, the code will not detect it.
        * The `__call__` method iterates through the keys in the `event_dict` and applies the regex substitution using `re.sub()`. If the regex pattern is flawed or doesn't match the actual format of the sensitive data, the data will not be anonymized.
        * **Example of Misconfiguration:**
            * Let's say a developer wants to anonymize credit card numbers and uses the following pattern: `r"\d{12}(\d{4})"` expecting to anonymize 16-digit credit card numbers and keep the last 4 digits. However, if some credit card numbers in the logs are 15 digits long (e.g., American Express), this regex will fail to match them, and those credit card numbers will be logged in plain text.
            * Another example: If the developer intends to anonymize credit card numbers under the key `"credit_card_number"` but accidentally logs them under the key `"cc_number"`, and only configures anonymization for `"credit_card_number"`, the credit card numbers under `"cc_number"` will not be anonymized.

* Security test case:
    * Step 1: Setup a logging configuration using `kiwi-structlog-config` and include the `Anonymize` processor with a flawed regex pattern.
        ```python
        import structlog
        from kw.structlog_config import configure_structlog, processors

        # Flawed regex pattern that only matches 16-digit numbers, not 15-digit (e.g., Amex)
        anonymize = processors.Anonymize(patterns=[
            ({"credit_card"}, r"\d{16}", "****")
        ])
        configure_structlog(extra_processors=[anonymize])
        logger = structlog.get_logger()
        ```
    * Step 2: Log an event containing a 15-digit credit card number under the key `"credit_card"`.
        ```python
        logger.info("payment_processed", credit_card="341200008881234") # 15-digit Amex card
        ```
    * Step 3: Capture the log output.
    * Step 4: Analyze the log output.
    * Expected result: The 15-digit credit card number in the log output will **not be anonymized** because the regex `r"\d{16}"` only matches 16-digit numbers. The log will contain the full credit card number "341200008881234", demonstrating the vulnerability.

    * Step 5: Repeat the test with a correctly configured regex that handles both 15 and 16 digit card numbers, e.g., `r"\d{15,16}"` or more specific patterns for different card types.
        ```python
        anonymize = processors.Anonymize(patterns=[
            ({"credit_card"}, r"\d{15,16}", "****") # Corrected regex
        ])
        configure_structlog(extra_processors=[anonymize])
        logger = structlog.get_logger()
        logger.info("payment_processed", credit_card="341200008881234") # 15-digit Amex card
        ```
    * Step 6: Analyze the log output again.
    * Expected result: The 15-digit credit card number in the log output will now be anonymized as "****", demonstrating the fix and highlighting the initial vulnerability caused by regex misconfiguration.