## Vulnerabilities

### Vulnerability: Insecure Anonymization due to Regex Misconfiguration

* Description:
    * Developers using the `kiwi-structlog-config` library can misconfigure the `Anonymize` processor by providing incorrect, ineffective, or overly specific regular expressions, or by specifying wrong or incomplete keys for sensitive data. This can lead to sensitive information not being properly anonymized and subsequently being logged in plain text.
    * Misconfigurations can manifest in various ways:
        * **Incorrect Regex:** Providing regular expressions that do not accurately match all formats of the sensitive data (e.g., regex for credit cards that only matches 16-digit numbers but not 15-digit Amex cards, or regex that fails to account for spaces or hyphens in credit card numbers).
        * **Overly Specific Regex:** Defining regex patterns that are too narrow and do not cover common variations in the format of sensitive data (e.g., a regex for email addresses that only targets `@example.com` domains, missing other email domains).
        * **Incomplete Keys:**  Specifying an incomplete set of keys to be anonymized, missing some keys under which sensitive information is logged.
    * When such misconfigurations occur, the `Anonymize` processor will fail to mask sensitive data effectively.  For example, if a regex is designed to anonymize only 16-digit credit card numbers, 15-digit credit card numbers or credit card numbers with spaces will be logged without anonymization. Similarly, overly specific regex patterns will only anonymize data that exactly matches the narrow pattern, leaving variations unmasked.
    * An attacker who gains access to these logs can then retrieve the exposed sensitive information.
    * Steps to trigger vulnerability:
        1. A developer implements logging in their application using `kiwi-structlog-config` and intends to anonymize sensitive data.
        2. The developer configures the `Anonymize` processor, providing regular expressions and keys for anonymization.
        3. The developer makes a mistake in the configuration, providing incorrect, ineffective, or overly specific regex patterns, or specifying wrong or incomplete keys.
        4. The application logs events containing sensitive data under the configured keys. Some of this data does not match the provided regex patterns due to format variations or is logged under keys not configured for anonymization.
        5. The logs are stored and become accessible to an attacker (e.g., through a compromised logging system or monitoring platform).
        6. The attacker analyzes the logs and finds unanonymized sensitive information.

* Impact:
    * High.
    * Exposure of sensitive information, such as credit card numbers, personal identification information, API keys, passwords, email addresses, phone numbers, or other confidential data, within application logs.
    * This can lead to:
        * Financial fraud if credit card numbers or financial data are exposed.
        * Identity theft if personal identification information is leaked.
        * Reputational damage and legal repercussions for the organization due to data breach and privacy violations.
        * Loss of customer trust.
        * Compliance violations if logging sensitive data in plain text is against regulations (e.g., GDPR, PCI DSS).

* Vulnerability Rank: High

* Currently implemented mitigations:
    * None in the code itself to prevent misconfiguration. The library provides the `Anonymize` processor, but it relies entirely on the developer to configure it correctly.
    * The `README.md` provides basic examples of how to use the `Anonymize` processor, but it lacks explicit warnings about the security risks of misconfiguration, best practices for creating secure anonymization patterns, or guidance on testing anonymization configurations.

* Missing mitigations:
    * **Input validation and pattern testing:** The `Anonymize` processor could include functionality to validate the provided regex patterns and keys. This could involve:
        * Basic regex syntax checking to catch syntax errors.
        * Optional testing functionality to allow developers to test their patterns against sample data and verify the anonymization outcome before deployment.
        * Warn developers about overly broad or potentially insecure regex patterns (e.g., patterns that are too generic and might anonymize unintended data).
    * **Documentation with security best practices:** Enhance the documentation to include:
        * Clear and prominent warnings about the security risks of misconfiguring the `Anonymize` processor and the potential for sensitive data leakage.
        * Best practices and detailed guidance for creating robust and secure regex patterns for anonymization, emphasizing the need to handle variations in data formats.
        * Examples of common misconfigurations, such as overly specific regex or regex failing to handle spaces, and how to avoid them.
        * Guidance on thorough testing of anonymization configurations, including providing security test case examples.
        * Recommendation to regularly review and update anonymization patterns as data formats evolve and new sensitive data types are introduced.
    * **Predefined secure patterns:** Consider providing a set of predefined, well-tested, and regularly updated regex patterns for common sensitive data types (e.g., credit card numbers of different types, email addresses, phone numbers, social security numbers). Developers could use these as a starting point or as examples to build upon and customize.
    * **Pattern weakness detection:** The library could incorporate a feature to analyze the provided regex patterns for potential weaknesses, such as overly broad patterns or patterns that are easily bypassed by slight variations in the sensitive data format. If weaknesses are detected, the library could issue warnings to the developer during configuration or runtime.

* Preconditions:
    * A developer must use the `Anonymize` processor from the `kiwi-structlog-config` library to anonymize sensitive data in logs.
    * The developer must misconfigure the `Anonymize` processor by providing incorrect, ineffective, or overly specific regex patterns, or by specifying wrong or incomplete keys.
    * Sensitive data that should be anonymized must be logged by the application under keys that are (or intended to be) targeted by the `Anonymize` processor's configuration.
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
        * The `Anonymize` class takes a list of `patterns` in its constructor. Each pattern is a tuple containing keys, a regular expression string, and a replacement string.
        * The `build_mapping` method compiles the regex patterns using `re.compile()`. **Critically, there is no validation or error handling for the provided regex patterns.** If a developer provides an incorrect, ineffective, or overly specific regex, the code will not detect it.
        * The `__call__` method iterates through the keys in the `event_dict` and applies the regex substitution using `re.sub()`. The effectiveness of anonymization is entirely dependent on the accuracy and comprehensiveness of the regex `pattern`. If the regex pattern is flawed, too specific, or doesn't match the actual format of the sensitive data (or all variations of it), the data will not be fully or correctly anonymized.
        * **Examples of Misconfiguration:**
            * **Incorrect Regex (Credit Card Numbers):** A developer uses `r"\d{16}"` intending to anonymize 16-digit credit card numbers. This regex will fail to match 15-digit American Express cards or credit card numbers containing spaces or hyphens, leaving them unanonymized.
            * **Overly Specific Regex (Email Addresses):** A developer uses `r"(\w+)@example\.com"` to anonymize email addresses, only targeting `@example.com` domains. Email addresses with other domains (e.g., `@gmail.com`, `@company.com`) will not be anonymized.
            * **Incorrect Keys:** A developer intends to anonymize credit card numbers under the key `"credit_card_number"` but accidentally logs them under the key `"cc_number"` and only configures anonymization for `"credit_card_number"`. The credit card numbers under `"cc_number"` will not be anonymized.

* Security test case:
    * **Test Case 1: Credit Card Number Anonymization Bypass with Spaces**
        1. Setup a logging configuration using `kiwi-structlog-config` and include the `Anonymize` processor with a regex pattern that does not handle spaces in credit card numbers, e.g., `r"\d+(\d{4})"`.
        ```python
        import structlog
        from kw.structlog_config import configure_structlog, processors

        anonymize = processors.Anonymize(patterns=[
            ({"card_number"}, r"\d+(\d{4})", "*" * 12 + r"\1"),
        ])
        configure_structlog(extra_processors=[anonymize])
        logger = structlog.get_logger()
        ```
        2. Log an event containing a credit card number with spaces under the key `"card_number"`.
        ```python
        logger.info("payment_processed", card_number="4321 0000 8888 1234")
        ```
        3. Capture and analyze the log output.
        4. Expected result: The credit card number in the log output will **not be fully anonymized** due to the spaces preventing the regex from matching the entire number.  The log might contain a partially anonymized or fully unanonymized credit card number, demonstrating the vulnerability.

    * **Test Case 2: Incomplete Anonymization due to Overly Specific Regex (Email Addresses)**
        1. Setup a logging configuration with an overly specific regex for email anonymization, e.g., only targeting `@example.com` domains:
        ```python
        from kw.structlog_config import configure_structlog, processors
        from kw.structlog_config import configure_stdlib_logging
        import logging

        anonymize = processors.Anonymize(patterns=[
            ({"email"}, r"(\w+)@example\.com", r"\1@masked.com"),
        ])
        configure_structlog(extra_processors=[anonymize])
        configure_stdlib_logging()
        logger = logging.getLogger(__name__)
        ```
        2. Log events containing email addresses with different domains, including one matching the specific regex and one with a different domain.
        ```python
        logger.info("User login attempt", email="test@example.com", event="login_attempt")
        logger.info("User login attempt", email="test@gmail.com", event="login_attempt")
        ```
        3. Examine the generated logs.
        4. Expected Result: The log entry for `test@example.com` will have the email anonymized. However, the log entry for `test@gmail.com` will have the email logged in plain text (`test@gmail.com`), demonstrating the incomplete anonymization due to the overly specific regex.