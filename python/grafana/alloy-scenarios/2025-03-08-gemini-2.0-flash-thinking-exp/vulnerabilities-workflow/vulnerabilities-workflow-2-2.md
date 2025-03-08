### Vulnerability List

- Vulnerability Name: Unauthenticated TCP Log Ingestion Endpoint
- Description:
    - The example configurations in the `logs-tcp` scenario expose an unauthenticated TCP endpoint for receiving logs.
    - Specifically, the `config.alloy` file configures a `log_receiver.tcp` component listening on `0.0.0.0:9999`.
    - This endpoint is intended to receive logs in JSON format, as demonstrated by the `simulator.py` script.
    - An attacker can connect to this open TCP port and send arbitrary log messages in the expected JSON format.
    - These injected logs will be processed by Grafana Alloy and forwarded to Loki, polluting the log data.
- Impact:
    - Log Injection: Attackers can inject arbitrary log entries into the system's logs stored in Loki.
    - False Monitoring Data: Injected logs can lead to misleading dashboards and alerts in Grafana, undermining the integrity of the monitoring system.
    - Operational Disruption: Malicious logs can make it difficult to identify genuine issues, potentially delaying incident response and resolution.
    - Resource Exhaustion (Potential): While not a denial of service in itself, a large volume of injected logs could consume storage and processing resources in Loki.
    - Data Tampering: Injected logs can be used to cover up malicious activities or frame legitimate users.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The example configurations are explicitly designed for demonstration purposes and do not include any authentication or access control mechanisms for the TCP log ingestion endpoint.
- Missing Mitigations:
    - Authentication and Authorization: Implement authentication to verify the identity of log senders and authorization to control who can send logs. This could involve mutual TLS, API keys, or other authentication methods supported by Grafana Alloy or a reverse proxy in front of it.
    - Input Validation and Sanitization: Validate and sanitize incoming log data to prevent injection of malicious content or unexpected formats that could cause issues in downstream processing or storage.
    - Rate Limiting: Implement rate limiting on the log ingestion endpoint to prevent attackers from flooding the system with logs and potentially causing performance degradation.
    - Network Segmentation: Restrict network access to the log ingestion endpoint to only trusted sources.
- Preconditions:
    - The `logs-tcp` scenario is deployed using the provided `docker-compose.yml` and `config.alloy` without modifications.
    - The TCP port `9999` on the machine running Grafana Alloy is publicly accessible or accessible to the attacker's network.
- Source Code Analysis:
    - File: `/code/logs-tcp/config.alloy`
        ```alloy
        local.log_receiver.tcp "receiver" {
          listen_address = "0.0.0.0:9999"
          encoding       = "json"
          format         = "json"
        }
        ```
        - This code block defines a `log_receiver.tcp` component named "receiver".
        - `listen_address = "0.0.0.0:9999"`: This line configures the receiver to listen on all network interfaces (0.0.0.0) on port 9999. This makes the endpoint publicly accessible if the host machine is exposed to the internet or an attacker's network.
        - There are no authentication or authorization parameters configured for this `log_receiver.tcp` component.
    - File: `/code/logs-tcp/docker-compose.yml`
        ```yaml
        ports:
          - 12345:12345
          - 4318:4318
        ```
        - This docker-compose file explicitly publishes ports 12345 and 4318. While port 9999 is not explicitly published here, the `config.alloy` binds the TCP receiver to `0.0.0.0:9999`, which makes it accessible from within the docker network and potentially externally depending on network configurations.
    - File: `/code/logs-tcp/simulator.py`
        - This script demonstrates sending JSON formatted logs to the TCP endpoint at `TARGET_HOST:TARGET_PORT`, which defaults to `alloy:9999` in the docker-compose setup. This confirms the intended usage and lack of security.
- Security Test Case:
    1. Deploy the `logs-tcp` scenario: Navigate to the `/code/logs-tcp` directory in the cloned repository and run `docker-compose up -d`.
    2. Identify the IP address of the host machine where Docker is running. Let's assume it's `<HOST_IP>`.
    3. Open a terminal and use `netcat` (or a similar TCP client) to connect to the exposed TCP port `9999` on the host machine: `nc <HOST_IP> 9999`.
    4. Once connected, send a crafted JSON log message. For example:
        ```json
        {"timestamp": "2024-01-01T12:00:00Z", "severity": "CRITICAL", "body": "Malicious log injected by attacker", "service_name": "AttackerService"}
        ```
        Type or paste the JSON message into the `netcat` terminal and press Enter.
    5. Access Grafana: Open a web browser and go to `http://localhost:3000`. Log in with the default credentials if prompted (anonymous access is enabled in the provided configurations).
    6. Explore Logs in Grafana: Navigate to the "Explore" section (Loki explorer).
    7. Query for the injected log: In the Loki query field, enter `{service_name="AttackerService"}` and run the query.
    8. Verify Log Injection: Confirm that the log message "Malicious log injected by attacker" is present in the logs, associated with the `AttackerService`. This demonstrates successful log injection via the unauthenticated TCP endpoint.