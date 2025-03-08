### Vulnerability List

- Vulnerability Name: Sensitive Data Exposure via Sentry Tags and Context
- Description:
    1. An application integrates `structlog-sentry` to send logs to Sentry.
    2. The application logs events using `structlog`, and these log events may inadvertently or intentionally include sensitive user data (e.g., user IDs, email addresses, API keys, personal information) within the `event_dict`.
    3. The `SentryProcessor` is configured to send event data to Sentry as tags or context. This can be achieved by setting `tag_keys` to include keys that might contain sensitive data, using `tag_keys="__all__"` to send all event data as tags, or by setting `as_context=True` to send the entire `event_dict` as extra context.
    4. When a log event occurs at or above the configured `event_level`, the `SentryProcessor` processes the event and sends it to Sentry.
    5. Due to the configuration in step 3, the sensitive data from the `event_dict` is included in the Sentry event as either tags or context.
    6. If an attacker gains unauthorized access to the Sentry project (e.g., through compromised credentials or insider threat), they can view the Sentry events and potentially access the sensitive data that was logged.
- Impact: Exposure of sensitive user data within the Sentry error tracking system to unauthorized individuals who have access to the Sentry project. This can lead to privacy violations, compliance breaches, reputational damage, and potentially further security risks if exposed data includes credentials or API keys.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - The library provides options to control what data is sent to Sentry:
        - `tag_keys`: Allows specifying a list of keys to be sent as tags, instead of sending all data.
        - `as_context`: Allows disabling sending the entire `event_dict` as context.
        - `ignore_breadcrumb_data`: Allows excluding specific keys from breadcrumb data.
    - However, these are configuration options and not enforced mitigations. The default settings (`as_context=True`, and default `ignore_breadcrumb_data`) still carry the risk if sensitive information is logged. There is no built-in sanitization or warning against logging sensitive data.
- Missing Mitigations:
    - **Documentation Enhancement**: The documentation should be updated to explicitly warn users about the risks of logging sensitive data and sending it to Sentry, especially when using `tag_keys="__all__"` or `as_context=True`. It should recommend sanitizing or filtering log data to remove sensitive information before logging when using these options.
    - **Security Best Practices Guidance**: Include a section in the documentation with security best practices for using `structlog-sentry` safely, emphasizing data minimization and avoiding logging PII (Personally Identifiable Information) or other sensitive data unnecessarily.
    - **Consider Default Configuration Change**: Evaluate if changing the default value of `as_context` to `False` would be a more secure default, prompting users to explicitly enable context sending if needed, making them more aware of the data being sent. However, this might break backward compatibility and reduce the utility for users who rely on context being sent by default.
- Preconditions:
    1. An application uses `structlog-sentry` to integrate `structlog` logging with Sentry.
    2. The application's logging logic may include sensitive data in the `event_dict`.
    3. The `SentryProcessor` is configured to send event data as tags (e.g., `tag_keys` includes keys with sensitive data or `tag_keys="__all__"`) or context (`as_context=True`).
    4. A log event at or above the configured `event_level` is triggered in the application, and this event's `event_dict` contains sensitive data.
- Source Code Analysis:
    - `structlog_sentry/__init__.py` -> `SentryProcessor.__call__(self, logger: WrappedLogger, name: str, event_dict: EventDict) -> EventDict`: This is the main processing function. It receives the `event_dict` from `structlog`.
    - `structlog_sentry/__init__.py` -> `SentryProcessor._get_event_and_hint(self, event_dict: EventDict) -> tuple[dict, dict]`: This function is called when the log level is at or above `event_level`.
        - `if self._as_context: event["contexts"] = {"structlog": self._original_event_dict.copy()}`: If `as_context` is True, the entire `_original_event_dict` (which is a copy of the log event data) is added to the Sentry event as context, without any filtering or sanitization.
        - `if self.tag_keys == "__all__": event["tags"] = self._original_event_dict.copy()`: If `tag_keys` is set to `"__all__"`, all key-value pairs from `_original_event_dict` are added as tags to the Sentry event, again without sanitization.
        - `if isinstance(self.tag_keys, list): event["tags"] = {key: event_dict[key] for key in self.tag_keys if key in event_dict}`: If `tag_keys` is a list of keys, the values associated with these keys from the `event_dict` are added as tags. If these keys correspond to sensitive data, it will be sent to Sentry.
    - `structlog_sentry/__init__.py` -> `SentryProcessor._get_breadcrumb_and_hint(self, event_dict: EventDict) -> tuple[dict, dict]`: This function is called when the log level is at or above `level` (breadcrumb level).
        - `data = {k: v for k, v in event_dict.items() if k not in self.ignore_breadcrumb_data}`:  Data for breadcrumbs is extracted from the `event_dict`, excluding keys in `ignore_breadcrumb_data`.  While `ignore_breadcrumb_data` allows excluding some keys, it doesn't inherently prevent sensitive data exposure if users don't configure it correctly or if sensitive data is logged under keys not in the ignore list. The `data` dictionary is then sent as part of the breadcrumb.

    **Visualization:**

    ```
    [Structlog Logging in Application] --> event_dict (potentially with sensitive data)
                                            |
                                            v
    SentryProcessor.__call__() ---------> Checks log level, configurations (tag_keys, as_context)
                                            |
                                            v (if event_level reached)
    SentryProcessor._get_event_and_hint() --> Creates Sentry Event
                                                |--- Adds context from event_dict (if as_context=True)
                                                |--- Adds tags from event_dict (based on tag_keys config)
                                            |
                                            v (if level reached)
    SentryProcessor._get_breadcrumb_and_hint() -> Creates Sentry Breadcrumb
                                                |--- Adds data from event_dict (excluding ignore_breadcrumb_data)
                                            |
                                            v
    Sentry SDK -----------------------------> Sends Event/Breadcrumb to Sentry
                                            |
                                            v
    [Sentry Project] ------------------------> Sensitive data potentially exposed in Sentry UI
    ```

- Security Test Case:
    1. **Setup:**
        - Create a Python virtual environment and install `structlog`, `sentry-sdk`, and `structlog-sentry`.
        - Initialize Sentry SDK with a test DSN and configure `LoggingIntegration` to prevent duplicate logging.
        - Configure `structlog` to use `structlog.stdlib.ProcessorFormatter.wrap_for_formatter` and include `structlog.stdlib.add_logger_name`, `structlog.stdlib.add_log_level`, and `SentryProcessor` in the processors list. Set `SentryProcessor` with `event_level=logging.INFO` and `tag_keys="__all__"` and `as_context=True` to maximize data sending to Sentry.
        - Create a test logger using `structlog.get_logger()`.
        - Initialize a `CaptureTransport` to intercept Sentry events instead of sending them to a real Sentry instance. Set this transport to the Sentry client in an isolation scope.

    2. **Action:**
        - In the test application code, log an informational event using the test logger. Include sensitive data in the `event_dict`, for example: `log.info("User profile view", user_email="test@example.com", user_id=123, api_key="sensitive_api_key")`.

    3. **Verification:**
        - After logging the event, retrieve the captured Sentry events from the `CaptureTransport`.
        - Assert that at least one Sentry event is captured.
        - Inspect the captured Sentry event's `tags` and `contexts.structlog` sections.
        - Verify that the sensitive data, such as `user_email`, `user_id`, and `api_key`, are present in the Sentry event, either as tags or within the structlog context. This confirms that sensitive data logged by the application is indeed being sent to Sentry due to the `SentryProcessor` configuration.

This test case demonstrates that when `tag_keys="__all__"` or `as_context=True` is used, and sensitive data is included in the log event's `event_dict`, `structlog-sentry` will transmit this sensitive data to Sentry, making it potentially accessible to anyone with access to the Sentry project.