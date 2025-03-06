#### 1. Information Leakage via Insecure Logging

- **Description:**
    1. The Amazon Pay Python SDK allows merchants to enable logging of API requests and responses by setting `log_enabled=True` during client initialization.
    2. The SDK includes `_sanitize_request_data` and `_sanitize_response_data` functions in `payment_request.py` to remove potentially sensitive information from log outputs.
    3. However, these sanitization functions rely on regular expressions that might not be exhaustive or correctly identify all sensitive data in all API calls and responses.
    4. Specifically, the current regex patterns focus on removing fields like `SellerNote`, `Buyer`, `PhysicalDestination`, `BillingAddress` etc. in the response and `SellerNote`, `SellerAuthorizationNote`, `SellerCaptureNote`, `SellerRefundNote` in request headers.
    5. There is a risk that other sensitive data, such as API keys, Personally Identifiable Information (PII) not covered by these patterns, or transaction details, could still be logged if merchants enable detailed logging (e.g., DEBUG level).
    6. An attacker gaining access to these log files (e.g., through server-side vulnerabilities in the merchant's application) could potentially extract sensitive information.

- **Impact:**
    - Exposure of sensitive information including customer PII (like addresses, buyer information if not completely sanitized), merchant-specific order details, and potentially, if sanitization is severely flawed, even parts of API credentials if they were somehow included in request/response bodies (though less likely with proper SDK usage, but possible via misconfiguration or extensions).
    - This information could be used for identity theft, fraud, or gaining unauthorized access to merchant or customer accounts.

- **Vulnerability Rank:** Medium

- **Currently Implemented Mitigations:**
    - The SDK includes `_sanitize_request_data` and `_sanitize_response_data` functions in `/code/amazon_pay/payment_request.py` to redact some fields from log output.
    - Logging is disabled by default (`log_enabled=False`).
    - The `README.md` provides examples of how to enable logging and configure log levels and file output.

- **Missing Mitigations:**
    - **Comprehensive Sanitization:** The sanitization functions should be reviewed and expanded to cover all potentially sensitive data in all API requests and responses. This should include, but not be limited to, PII, transaction amounts, and any other data that could be misused if exposed. Consider using a structured approach to identify and sanitize sensitive fields based on API specifications rather than relying solely on regex patterns.
    - **Security Guidance on Logging:**  The documentation (currently only `README.md`) should include explicit security warnings about the risks of enabling detailed logging in production environments. It should advise merchants to carefully consider the log level and ensure log files are stored securely and access is restricted. It should also strongly recommend against logging request/response bodies in production unless absolutely necessary and with extreme caution.
    - **Configuration Best Practices:** Provide clearer guidance on secure logging configurations, such as using dedicated secure log storage, log rotation, and access controls.

- **Preconditions:**
    - Merchant has enabled logging in the Amazon Pay SDK client by setting `log_enabled=True`.
    - Merchant has configured logging to output to a file or console that is accessible to unauthorized parties (e.g., due to other vulnerabilities in the merchant's application or server configuration).
    - Sensitive information is present in the API requests or responses that is not adequately sanitized by the SDK's sanitization functions.

- **Source Code Analysis:**
    - **File: /code/amazon_pay/payment_request.py**
    - The `PaymentRequest` class initializes a logger and uses it to log request headers and responses in the `_request` method.
    ```python
    class PaymentRequest:
        logger = logging.getLogger('__amazon_pay_sdk__')
        logger.addHandler(logging.NullHandler())

        # ...

        def _request(self, retry_time):
            # ...
            self.logger.debug('Request Header: %s',
                self._sanitize_request_data(str(self._headers)))

            r = requests.post(
                url=self._mws_endpoint,
                data=data,
                headers=self._headers,
                verify=True)
            r.encoding = 'utf-8'
            self._status_code = r.status_code

            if self._status_code == 200:
                # ...
                self.logger.debug('Response: %s',
                    self._sanitize_response_data(r.text))
            else:
                # ...
                self.logger.debug('Response: %s',
                    self._sanitize_response_data(r.text))
    ```
    - The `_sanitize_request_data` and `_sanitize_response_data` methods use regex to replace specific patterns with "REMOVED".
    ```python
    def _sanitize_request_data(self, text):
        editText = text
        patterns = []
        patterns.append(r'(?s)(SellerNote).*(&)')
        patterns.append(r'(?s)(SellerAuthorizationNote).*(&)')
        patterns.append(r'(?s)(SellerCaptureNote).*(&)')
        patterns.append(r'(?s)(SellerRefundNote).*(&)')
        replacement = r'\1 REMOVED \2'

        for pattern in patterns:
            editText = re.sub(pattern, replacement, editText)
        return editText

    def _sanitize_response_data(self, text):
        editText = text
        patterns = []
        patterns.append(r'(?s)(<Buyer>).*(</Buyer>)')
        patterns.append(r'(?s)(<PhysicalDestination>).*(</PhysicalDestination>)')
        patterns.append(r'(?s)(<BillingAddress>).*(<\/BillingAddress>)')
        patterns.append(r'(?s)(<SellerNote>).*(<\/SellerNote>)')
        patterns.append(r'(?s)(<AuthorizationBillingAddress>).*(<\/AuthorizationBillingAddress>)')
        patterns.append(r'(?s)(<SellerAuthorizationNote>).*(<\/SellerAuthorizationNote>)')
        patterns.append(r'(?s)(<SellerCaptureNote>).*(<\/SellerCaptureNote>)')
        patterns.append(r'(?s)(<SellerRefundNote>).*(<\/SellerRefundNote>)')
        replacement = r'\1 REMOVED \2'

        for pattern in patterns:
            editText = re.sub(pattern, replacement, editText)
        return editText
    ```
    - **Visualization:**
    ```
    [Merchant Application] --> [Amazon Pay SDK Client] --> [PaymentRequest._request()]
                                                            |
                                                            V
                                        [PaymentRequest._sanitize_request_data()] - Sanitizes Request Header (Limited Regex)
                                                            |
                                                            V
                                                [Logs Request Header] --> [Log File/Console] (Potential Information Leak)
                                                            |
                                                            V
                                                [Send Request to Amazon Pay API]
                                                            |
                                                            V
                                              [Receive Response from Amazon Pay API]
                                                            |
                                                            V
                                        [PaymentRequest._sanitize_response_data()] - Sanitizes Response Body (Limited Regex)
                                                            |
                                                            V
                                                [Logs Response Body] --> [Log File/Console] (Potential Information Leak)
    ```

- **Security Test Case:**
    1. **Setup:**
        - Deploy a sample merchant application using the deprecated Amazon Pay Python SDK in a test environment where you can access the application's logs.
        - Enable logging in the Amazon Pay SDK client within the application by setting `log_enabled=True` and `log_level="DEBUG"` during client initialization and configure it to log to a file accessible to you.
        - Use the sandbox environment for testing to avoid real transactions.
    2. **Trigger Vulnerability:**
        - Initiate a payment flow in the merchant application that involves making API calls to Amazon Pay (e.g., `Authorize`, `Capture`, `GetOrderReferenceDetails`). Ensure that the API calls will likely contain potentially sensitive information in both requests and responses (e.g., customer address, order details, seller notes).
        - For example, use the `set_order_reference_details` and `get_order_reference_details` calls with parameters that include seller notes and custom information.
    3. **Analyze Logs:**
        - Access and examine the log file generated by the application.
        - Search for log entries corresponding to the Amazon Pay API requests and responses made during the payment flow.
        - Check if sensitive information that should have been sanitized is still present in the logs. Specifically, look for:
            - Customer names, addresses, email addresses in request headers or response bodies that were not removed by sanitization.
            - Order details, seller notes, custom information that are logged in plain text without redaction.
            - Any other data beyond the intended sanitization scope that could be considered sensitive.
    4. **Expected Result:**
        - If the sanitization is incomplete, you should find instances of sensitive information (beyond what's intended to be sanitized by the current regex patterns) logged in the application logs, demonstrating information leakage. For example, if you include a phone number or specific product details in the `custom_information` field, and the regex doesn't cover these, they might appear in the logs.
    5. **Pass/Fail:**
        - **Fail:** If sensitive information is found in the logs beyond the intended redaction, the test fails, confirming the vulnerability.
        - **Pass:** If all sensitive information is effectively sanitized according to the current sanitization rules (though the rules themselves might be incomplete), the test passes in terms of demonstrating *this specific test case*, but the broader vulnerability of incomplete sanitization still exists.