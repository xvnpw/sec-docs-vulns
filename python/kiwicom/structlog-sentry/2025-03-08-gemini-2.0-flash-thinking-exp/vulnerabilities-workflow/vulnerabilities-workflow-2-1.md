- Vulnerability name: Sensitive Data Exposure via Sentry Context
- Description:
    - A developer using `structlog-sentry` library configures `SentryProcessor` with default settings or explicitly sets `as_context=True`.
    - The developer logs an event using `structlog` and includes sensitive user information (e.g., passwords, API keys, personal data) within the `event_dict`. For example: `log.error("User login failed", username="john.doe", password="password123")`.
    - The `SentryProcessor` captures this log event.
    - Because `as_context` is enabled (by default), the entire `event_dict`, including the sensitive user information, is sent to Sentry as contextual information within the Sentry event.
    - If the Sentry instance is not properly secured or is compromised by an attacker, the attacker can access the Sentry account and view the Sentry events, including the sensitive user information logged as context data.
- Impact:
    - Exposure of sensitive user information to unauthorized parties.
    - Potential for identity theft, account compromise, or other security breaches due to leaked credentials or personal data.
    - Reputational damage and legal liabilities for the application and organization logging sensitive data.
- Vulnerability rank: High
- Currently implemented mitigations:
    - No default mitigation is implemented.
    - The library provides options to disable sending the event dictionary as context (`as_context=False`) or to ignore specific data keys (`ignore_breadcrumb_data`), or to send specific keys as tags (`tag_keys`). However, these are not enabled by default and require manual configuration by the developer.
- Missing mitigations:
    - Default configuration change: Set `as_context=False` by default to prevent sending the entire `event_dict` as context unless explicitly enabled.
    - Documentation enhancement: Add a prominent warning in the documentation highlighting the risk of logging sensitive data and recommending best practices such as:
        - Avoiding logging sensitive data altogether.
        - Using `ignore_breadcrumb_data` to exclude sensitive keys from being sent to Sentry.
        - Setting `as_context=False` and using `tag_keys` selectively for non-sensitive data.
        - Implementing data sanitization or masking before logging.
- Preconditions:
    - The `structlog-sentry` library is installed and `SentryProcessor` is used in the application's logging configuration.
    - `SentryProcessor` is initialized with default settings (specifically `as_context=True`) or `as_context=True` is explicitly set.
    - Developers inadvertently or unknowingly log sensitive information within the `event_dict` when using `structlog` logging methods.
    - The Sentry instance to which the logs are sent is either not properly secured (e.g., weak credentials, public access) or is compromised by an attacker.
- Source code analysis:
    - File: `/code/structlog_sentry/__init__.py`
    - Class: `SentryProcessor`
    - Method: `__call__(self, logger: WrappedLogger, name: str, event_dict: EventDict)`
        ```python
        def __call__(
            self, logger: WrappedLogger, name: str, event_dict: EventDict
        ) -> EventDict:
            """A middleware to process structlog `event_dict` and send it to Sentry."""
            self._original_event_dict = dict(event_dict) # event_dict is stored
            # ...
        ```
    - Method: `_get_event_and_hint(self, event_dict: EventDict) -> tuple[dict, dict]`
        ```python
        def _get_event_and_hint(self, event_dict: EventDict) -> tuple[dict, dict]:
            # ...
            if self._as_context: # self._as_context is True by default
                event["contexts"] = {"structlog": self._original_event_dict.copy()} # entire event_dict is added to context
            # ...
        ```
    - The `SentryProcessor` by default initializes `_as_context = True`.
    - When processing a log event in the `__call__` method, the `event_dict` is stored in `self._original_event_dict`.
    - The `_get_event_and_hint` method, which prepares the Sentry event, checks the `self._as_context` flag. If it's true (which is the default), it adds the entire `self._original_event_dict` (which is a copy of the log event's `event_dict`) to the `contexts` section of the Sentry event.
    - This design choice results in sending all data passed to the structlog logger to Sentry as context data by default, potentially including sensitive information if developers are not careful.
- Security test case:
    - Step 1: Setup a test environment with `structlog`, `sentry-sdk`, and `structlog-sentry`. Use a mock transport for `sentry-sdk` to capture events locally without sending them to a real Sentry instance.
    - Step 2: Configure `structlog` and `SentryProcessor` with default settings (or explicitly set `as_context=True`).
    - Step 3: Initialize `structlog` logger.
    - Step 4: Log an error event using `structlog` and include sensitive data in the `event_dict`. For example:
        ```python
        import structlog
        import logging
        from structlog_sentry import SentryProcessor
        import sentry_sdk
        from test.test_sentry_processor import CaptureTransport # Assuming CaptureTransport is accessible in test context

        transport = CaptureTransport()
        client = sentry_sdk.Client(transport=transport, integrations=[], auto_enabling_integrations=False)
        with sentry_sdk.isolation_scope() as scope:
            scope.set_client(client)

            structlog.configure(
                processors=[
                    structlog.stdlib.add_logger_name,
                    structlog.stdlib.add_log_level,
                    SentryProcessor(event_level=logging.ERROR), # default as_context=True
                    structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
                ],
                logger_factory=structlog.stdlib.LoggerFactory(),
                wrapper_class=structlog.stdlib.BoundLogger,
                cache_logger_on_first_use=True,
            )
            log = structlog.get_logger()
            sensitive_data = "password123"
            log.error("Login failed", username="testuser", password=sensitive_data) # Logging sensitive data
        captured_events = transport.events
        ```
    - Step 5: Assert that a Sentry event was captured.
    - Step 6: Inspect the captured Sentry event and verify that:
        - The event contains a `contexts` section.
        - The `contexts` section contains a `structlog` subsection.
        - The `structlog` subsection contains the entire `event_dict`, including the sensitive data (`password="password123"`).
        ```python
        assert len(captured_events) == 1
        sentry_event = captured_events[0]
        assert "contexts" in sentry_event
        assert "structlog" in sentry_event["contexts"]
        assert sentry_event["contexts"]["structlog"]["password"] == sensitive_data
        ```
    - If the assertions in Step 6 pass, it confirms the vulnerability: sensitive data logged in the `event_dict` is being sent to Sentry as context data by default.