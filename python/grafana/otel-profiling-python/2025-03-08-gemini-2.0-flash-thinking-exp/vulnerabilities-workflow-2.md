## Combined Vulnerability List

### Information Disclosure via Linked OpenTelemetry Traces and Pyroscope Profiles

*   **Vulnerability Name:** Information Disclosure via Linked OpenTelemetry Traces and Pyroscope Profiles
*   **Description:**
    1. Developers use OpenTelemetry to instrument their Python application for distributed tracing and Pyroscope for continuous profiling.
    2. The `pyroscope-otel` library is integrated to link OpenTelemetry traces and Pyroscope profiles.
    3. The `PyroscopeSpanProcessor` in `pyroscope-otel` adds a span attribute named `pyroscope.profile.id` to root spans in OpenTelemetry traces. This attribute's value is the span's ID.
    4. Simultaneously, for root spans, the processor adds a tag named `span_id` with the same span ID value to the Pyroscope profiles generated for the corresponding thread.
    5. This mechanism establishes a bidirectional link between OpenTelemetry traces and Pyroscope profiles using the span ID as a common identifier.
    6. **Scenario 1 (Span Attributes Disclosure):** Developers might unknowingly or unintentionally include sensitive information (e.g., API keys, passwords, personal data) as attributes in OpenTelemetry spans. If Pyroscope or systems consuming Pyroscope data are configured to capture or expose tags, the sensitive information from OpenTelemetry span attributes, linked by the `span_id` tag in Pyroscope profiles, can be inadvertently exposed. Attackers with access to Pyroscope data could potentially access this sensitive information.
    7. **Scenario 2 (Profile Data Disclosure):** If OpenTelemetry traces are exported to external systems (e.g., monitoring dashboards, observability platforms, or third-party collectors), the `pyroscope.profile.id` attribute is also exported. If Pyroscope profiles contain sensitive information about the application's internal workings, business logic, or data processing, an attacker gaining access to these exported OpenTelemetry traces can observe the `pyroscope.profile.id` attribute. By correlating this ID with access to Pyroscope data, they could potentially access and analyze these sensitive profiles.
    8. This linkage, intended for observability, can inadvertently expose sensitive data from either OpenTelemetry spans or Pyroscope profiles to unauthorized parties who have access to the linked data in the other system.

*   **Impact:**
    *   Disclosure of sensitive information originating from either OpenTelemetry span attributes or Pyroscope profiles. This could include:
        *   Credentials, API keys, Personally Identifiable Information (PII), or other confidential data mistakenly added as span attributes.
        *   Application internals (e.g., function names, execution flow) and business logic (e.g., algorithms, decision-making processes) revealed through Pyroscope profiles.
        *   Sensitive data being processed by the application if captured in Pyroscope profiles.
    *   Unauthorized access to sensitive systems or data if exposed credentials or API keys are compromised.
    *   Reputational damage and legal liabilities due to data breaches.
    *   Insights into application internals and business logic, potentially aiding further attacks.

*   **Vulnerability Rank:** Medium
    *   The vulnerability is not directly exploitable against the `pyroscope-otel` library itself.
    *   The risk depends on developer practices (adding sensitive data to span attributes, sensitivity of profiled data) and the configuration of the Pyroscope and OpenTelemetry infrastructure (how tags and traces are handled and exposed).
    *   However, the impact of information disclosure can be significant, potentially leading to further security breaches or exposure of sensitive business logic.

*   **Currently Implemented Mitigations:**
    *   None. The current code in `pyroscope-otel` focuses solely on linking traces and profiles by adding the `span_id` tag and `pyroscope.profile.id` attribute without any safeguards against information disclosure.

*   **Missing Mitigations:**
    *   **Documentation Warning:**  Crucially, the documentation must explicitly warn developers about the potential risks.
        *   Advise against including sensitive information in OpenTelemetry span attributes when using `pyroscope-otel`.
        *   Highlight that linking traces and profiles can expose sensitive information from either system if not carefully managed.
        *   Recommend sanitizing or filtering sensitive data from both OpenTelemetry span attributes and Pyroscope profiles.
    *   **Guidance on Data Sanitization:** Provide practical guidance on how to sanitize or filter sensitive data.
        *   Suggest strategies to configure Pyroscope to capture only non-sensitive data or to mask/redact sensitive information before profiles are generated.
        *   Advise on reviewing and removing sensitive attributes from OpenTelemetry spans before or during export.
    *   **Configuration Options (Optional):** Consider adding configuration options for advanced users.
        *   Option to disable the automatic tagging of Pyroscope profiles with `span_id` and attribute in traces `pyroscope.profile.id`. This would break the linking functionality but could be necessary in highly sensitive environments.
        *   Allowlist/Denylist for span attributes or profile tags to control what information is linked or propagated.

*   **Preconditions:**
    *   Python application using both OpenTelemetry and Pyroscope.
    *   `pyroscope-otel` library integrated into the application's OpenTelemetry setup.
    *   For Span Attribute Disclosure: Developers adding sensitive information as attributes to OpenTelemetry spans. Pyroscope or related infrastructure configured to expose tags.
    *   For Profile Data Disclosure: Pyroscope configured to capture profiles containing potentially sensitive information. OpenTelemetry traces exported to a system accessible to potential attackers.

*   **Source Code Analysis:**
    1. The `PyroscopeSpanProcessor` class is defined in `src/pyroscope/otel/__init__.py`.
    2. In the `on_start` method, for root spans (identified by `_is_root_span(span)`), the following actions occur:
        *   `span.set_attribute(PROFILE_ID_SPAN_ATTRIBUTE_KEY, format(span.context.span_id, "016x"))` adds the attribute `pyroscope.profile.id` to the OpenTelemetry span, using the span ID as value.
        *   `pyroscope.add_thread_tag(threading.get_ident(), PROFILE_ID_PYROSCOPE_TAG_KEY, _get_span_id(span))` adds a tag named `span_id` with the span ID value to the Pyroscope profile for the current thread.
    3. The `on_end` method, for root spans, calls `pyroscope.remove_thread_tag` to remove the tag when the span ends.

    **Visualization:**

    ```
    OpenTelemetry Span (Root Span)         Pyroscope Profiling Data (for thread)
    +-------------------------------------+   +-------------------------------------+
    | Attributes:                         |   | ...                                 |
    |   ...                               |   | Tags:                               |
    |   user_id: "sensitive_user_id"      | <-|  span_id: "span_id_hex"            | <---- Link
    |   ...                               |   | ...                                 |
    |   pyroscope.profile.id: "span_id_hex"| ->|                                     | <---- Link
    +-------------------------------------+   +-------------------------------------+
          ^                                       ^
          |                                       |
          | PyroscopeSpanProcessor.on_start()     | PyroscopeSpanProcessor.on_start()
          | Adds attribute to span                | Adds tag to Pyroscope profile
          -----------------------------------------

    ```

    **Explanation of Vulnerability Path:**

    The `PyroscopeSpanProcessor` creates a link between OpenTelemetry spans and Pyroscope profiles using the span ID. This is achieved by embedding the span ID as both an attribute in the OpenTelemetry span (`pyroscope.profile.id`) and as a tag in the Pyroscope profile (`span_id`).

    **Information Disclosure Scenario 1 (Span Attributes):** If developers add sensitive data as span attributes, and if Pyroscope tags are exposed, the `span_id` tag in Pyroscope profiles becomes a potential pathway to disclose this sensitive data.  If an attacker can access Pyroscope data and correlate the `span_id` tag back to OpenTelemetry spans (even indirectly), they might access sensitive span attributes.

    **Information Disclosure Scenario 2 (Profile Data):** If Pyroscope profiles contain sensitive application internals or business logic, and if OpenTelemetry traces with the `pyroscope.profile.id` attribute are exported and accessible, then the `pyroscope.profile.id` attribute in traces becomes a pathway to disclose sensitive profile data. An attacker accessing exported traces can use the `pyroscope.profile.id` to potentially retrieve and analyze corresponding Pyroscope profiles.

*   **Security Test Case:**
    1. **Prerequisites:**
        *   Set up a Python application with OpenTelemetry, Pyroscope, and `pyroscope-otel` integrated. Run a Pyroscope server (e.g., local instance).
        *   Configure OpenTelemetry to export traces (e.g., to console or Jaeger).
    2. **Modify Application Code (for Span Attribute Disclosure Test):**
        *   Create a root OpenTelemetry span and add a sensitive span attribute:
            ```python
            from opentelemetry import trace
            # ... (OpenTelemetry and Pyroscope setup) ...
            tracer = trace.get_tracer(__name__)
            with tracer.start_as_current_span("test-span") as span:
                span.set_attribute("sensitive_data", "洩漏的秘密") # Sensitive data
                print("Doing some work...")
            ```
    3. **Modify Application Code (for Profile Data Disclosure Test - requires Pyroscope setup to capture sensitive data, which is application specific and harder to generalize in a test case. Focus on demonstrating the link in this test case):**
        * Ensure Pyroscope configuration would capture some profile data during span execution.
    4. **Run the Application:** Execute the application to generate traces and profiles.
    5. **Observe OpenTelemetry Traces:**
        *   Examine exported traces (console output or Jaeger UI).
        *   Verify root spans contain the `pyroscope.profile.id` attribute. Note its value (span ID).
    6. **Observe Pyroscope Data (Simulated):**
        *   **For Span Attribute Disclosure Test:** Imagine inspecting Pyroscope data. Look for profiles related to "test-app" and check for the `span_id` tag. Confirm it matches the `pyroscope.profile.id` from traces.
        *   **For Profile Data Disclosure Test:**  Observe Pyroscope output/logs or UI for profiles generated around the same time as traces. Confirm presence of `span_id` tag matching `pyroscope.profile.id` in traces.
    7. **Analyze Results:**
        *   Confirm the presence of both `pyroscope.profile.id` in traces and `span_id` tag in Pyroscope profiles with matching values. This validates the linkage.
        *   **Demonstrate Potential Risk (Span Attributes):** Explain that if an attacker accesses Pyroscope data and can correlate `span_id` to OpenTelemetry, sensitive data in span attributes (`sensitive_data` in example) *could* be disclosed.
        *   **Demonstrate Potential Risk (Profile Data):** Explain that if an attacker accesses exported traces and finds `pyroscope.profile.id`, they could potentially use this ID to access and analyze linked Pyroscope profiles, disclosing sensitive application internals or business logic contained within profiles.

This test case demonstrates the linkage created by `pyroscope-otel` and highlights the potential information disclosure risks from both span attributes and profile data due to this linkage. It emphasizes the need for documentation warnings and careful handling of sensitive data in both OpenTelemetry spans and Pyroscope profiles when using this library.