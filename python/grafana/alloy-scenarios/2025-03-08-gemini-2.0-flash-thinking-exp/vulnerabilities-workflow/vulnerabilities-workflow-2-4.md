### Vulnerability List

- Vulnerability Name: Log Injection via Malicious JSON Payloads in Logs-TCP and Mail-House Scenarios
- Description:
  - The Grafana Alloy configurations provided in the `logs-tcp` and `mail-house` scenarios demonstrate parsing JSON logs received over TCP.
  - The `config.alloy` files (not provided in PROJECT FILES but assumed to exist based on scenario descriptions) likely utilize the `log.process` component to extract fields from these JSON logs and create labels and structured metadata.
  - An attacker can send crafted JSON payloads to the TCP listener on port 9999 (as defined in `docker-compose.yml` for both scenarios).
  - By manipulating the JSON structure and field values within these payloads, the attacker can inject arbitrary labels and structured metadata into the logs processed by Alloy.
  - These injected labels and metadata are then forwarded to Loki, leading to log injection. This can potentially compromise log analysis and monitoring by injecting false or misleading log entries.
- Impact:
  - Log Injection: An attacker can inject arbitrary log entries into the Loki log management system. This can:
    -  Obscure genuine log data, making it harder to detect real issues or security incidents.
    -  Inject misleading information, potentially causing incorrect alerts or analysis.
    -  Degrade the integrity of the log data, reducing trust in the monitoring system.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations: None in the provided example configurations. The configurations are designed for demonstration purposes and do not include input validation or sanitization.
- Missing Mitigations:
  - Input validation and sanitization: Implement strict validation of the incoming JSON payloads within the `config.alloy` file. This should include:
    - Schema validation: Ensure that the received JSON payload conforms to a predefined schema, rejecting payloads with unexpected fields or structures.
    - Data type validation: Verify that the data types of the fields are as expected (e.g., timestamps are valid timestamps, severity levels are from a defined set).
    - Sanitization: Sanitize field values to prevent injection of arbitrary characters or control sequences that could be misinterpreted by downstream systems or used for further attacks if logs are processed elsewhere.
  - Principle of least privilege: Ensure that the Alloy process runs with the minimum necessary privileges to reduce the potential impact of a successful exploit.
  - Monitoring and alerting: Implement monitoring within Grafana/Loki to detect suspicious log entries or patterns that might indicate log injection attempts. This could include alerting on logs with unexpected labels or unusual data formats.
- Preconditions:
  - The `logs-tcp` or `mail-house` scenario is deployed using the provided `docker-compose.yml` files.
  - The `config.alloy` files (assumed to exist and be configured to parse JSON logs using `log.process`) are in use without modification to add input validation.
  - The attacker has network access to send TCP traffic to the Alloy listener port (port 9999).
- Source Code Analysis:
  - **File: `/code/logs-tcp/config.alloy` (Assumed - not provided)**
    - Assume `config.alloy` uses a `tcp` source component to receive logs on port 9999.
    - Assume it then uses a `log.process` component to parse the incoming logs as JSON.
    - Assume the `log.process` component extracts fields from the JSON payload using expressions like `.message.timestamp`, `.message.severity`, etc., and assigns them as labels or structured metadata.
    - **Vulnerability Point:** If the `log.process` stage directly extracts fields without validation and uses them as labels, any attacker who can send data to the TCP port can control the labels associated with log entries by crafting malicious JSON payloads.

  - **File: `/code/mail-house/config.alloy` (Assumed - not provided)**
    - Similar assumptions as `logs-tcp/config.alloy` apply. The `mail-house` scenario also deals with parsing structured logs, likely JSON, and extracting fields.

- Security Test Case:
  1. Deploy the `logs-tcp` scenario:
     ```bash
     cd alloy-scenarios/logs-tcp
     docker-compose up -d
     ```
  2. Identify the IP address of the machine running Docker Compose. Let's assume it's `localhost`. Alloy is listening on port `9999`.
  3. Craft a malicious JSON payload. For example, to inject a label `injected_label=malicious_value`:
     ```json
     {
         "timestamp": "2024-01-01T00:00:00Z",
         "severity": "INFO",
         "body": "Malicious log entry with injected label",
         "service_name": "TestService",
         "injected_label": "malicious_value"
     }
     ```
  4. Send this payload to the Alloy TCP listener using `nc` (netcat):
     ```bash
     echo -e "POST /loki/api/v1/push HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\r\n$(echo '{"streams": [{"stream": {}, "values": [["$(date +%s%N)", "$(echo '{\"timestamp\": \"2024-01-01T00:00:00Z\", \"severity\": \"INFO\", \"body\": \"Malicious log entry with injected label\", \"service_name\": \"TestService\", \"injected_label\": \"malicious_value\"}' | jq -r tostring )"]]}]}')" | nc localhost 9999
     ```
     *Note:* This `nc` command is a simplified example and might need adjustment depending on the exact Alloy configuration and expected input format. A more robust test would directly send the raw JSON payload over TCP without HTTP framing if Alloy is configured for raw TCP JSON. For scenarios expecting HTTP, the provided `nc` command simulates a basic HTTP POST.
  5. Access Grafana UI at `http://localhost:3000`.
  6. Navigate to the Loki explorer.
  7. Query Loki for logs with the injected label: `{injected_label="malicious_value"}`.
  8. Verify that the injected log entry appears in Loki, and that the injected label `injected_label="malicious_value"` is present in the log entry's labels. This confirms the log injection vulnerability.
  9. Repeat steps 1-8 for the `mail-house` scenario to confirm the vulnerability there as well.

This vulnerability highlights the importance of input validation when processing data from potentially untrusted sources, especially when that data is used to generate labels or metadata in telemetry systems. While these scenarios are examples, users copying these configurations to production should be aware of and mitigate this risk.