### Vulnerability List

- Vulnerability Name: Unauthenticated Grafana Alloy Reload API Endpoint
- Description:
    1. The Grafana Alloy HTTP server is exposed on port `12345` as defined in `docker-compose.yml` without any authentication configured by default.
    2. The `/reload` endpoint of the Grafana Alloy API is accessible over HTTP on the exposed port. This endpoint is intended for administrators to dynamically reload the Alloy configuration without restarting the service.
    3. An attacker can send a POST request to the `/reload` endpoint without providing any authentication credentials.
    4. Upon receiving an unauthenticated reload request, Grafana Alloy will attempt to reload its configuration from the mounted `config.alloy` file.
    5. By replacing the legitimate `config.alloy` file with a malicious one, an attacker can inject arbitrary configurations into the running Grafana Alloy instance by triggering the reload API.
    6. This malicious configuration can be crafted to:
        - Exfiltrate sensitive data by modifying Alloy to send collected metrics and logs to an attacker-controlled endpoint.
        - Disrupt monitoring by altering or disabling metric and log collection pipelines.
        - Potentially gain further access to monitored systems depending on the Alloy configuration and integrated components.
- Impact:
    - **Configuration Injection:** An attacker can inject a malicious Grafana Alloy configuration.
    - **Data Exfiltration:** Sensitive data being monitored by Alloy (e.g., container metrics, logs) can be exfiltrated to an attacker's server by manipulating the Alloy configuration to forward data.
    - **Monitoring Disruption:** The attacker can disrupt the monitoring system by altering or disabling metric and log collection, leading to blind spots and potentially masking malicious activities within the monitored environment.
    - **Potential System Compromise:** Depending on the Alloy configuration and the extent of integrations, a successful configuration injection could be a stepping stone to further compromise of the monitored systems.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The provided project files and default setup do not include any authentication or access control mechanisms for the Grafana Alloy HTTP API or the `/reload` endpoint.
- Missing Mitigations:
    - **Implement Authentication:** Grafana Alloy's HTTP API, especially sensitive endpoints like `/reload`, should be protected by authentication. Options include:
        - Basic Authentication
        - API Keys
        - Mutual TLS (mTLS)
    - **Access Control:** Implement role-based access control to restrict who can reload the Alloy configuration.
    - **Secure Default Configuration:** The default `config.alloy` (or guidance for creating one) should emphasize the importance of securing the reload API and provide configuration examples for authentication.
    - **Documentation and Warnings:** Clearly document the security implications of exposing the reload API without authentication and provide explicit warnings in the workshop materials.
- Preconditions:
    - Grafana Alloy is deployed using the provided `docker-compose.yml` file, which exposes port `12345`.
    - No custom `config.alloy` is provided that explicitly configures authentication for the HTTP API.
    - The network port `12345` on the host running Grafana Alloy is reachable by the attacker.
- Source Code Analysis:
    1. **`docker-compose.yml`**: The `docker-compose.yml` file defines the deployment of Grafana Alloy and exposes port `12345` on the host to port `12345` of the Alloy container:
        ```yaml
        ports:
          - 12345:12345
        ```
        This makes the Grafana Alloy HTTP API accessible from outside the Docker environment if the host machine's firewall allows traffic on port `12345`.
    2. **`docker-compose.yml`**: The command used to start Grafana Alloy includes `--server.http.listen-addr=0.0.0.0:12345`:
        ```yaml
        command: run --server.http.listen-addr=0.0.0.0:12345 ... /etc/alloy/config.alloy
        ```
        This explicitly binds the Alloy HTTP server to all network interfaces (`0.0.0.0`) on port `12345`, further confirming its external accessibility.
    3. **`README.md`**: The `README.md` provides instructions on how to reload the Grafana Alloy configuration using `curl`:
        ```bash
        curl -X POST http://localhost:12345/-/reload
        ```
        This command, as provided, does not include any authentication headers or parameters, suggesting that the reload API is intended to be used without authentication in the workshop's default configuration.
    4. **Absence of `config.alloy` and Authentication Configuration**: The project does not include a default `config.alloy` file. Furthermore, there is no mention in the `README.md` or other provided files about configuring authentication for the Grafana Alloy HTTP API. This implies that by default, and as demonstrated in the provided `curl` command, the reload API is unauthenticated.
- Security Test Case:
    1. **Deploy the Workshop Stack**: Run `docker-compose up -d` in the `/code` directory to start the Grafana Alloy, Prometheus, Loki, and Grafana stack.
    2. **Access Grafana Alloy UI**: Verify that the Grafana Alloy UI is accessible by navigating to `http://localhost:12345` in a web browser. This confirms that the HTTP server is running and accessible on the exposed port.
    3. **Attempt Unauthenticated Reload**: Send a POST request to the Grafana Alloy reload API endpoint using `curl` from the host machine or any machine that can reach the host on port `12345`:
        ```bash
        curl -X POST http://localhost:12345/-/reload
        ```
    4. **Verify Successful Reload (No Authentication Required)**:
        - If the reload is successful, the `curl` command will likely return an HTTP 200 status code or a similar success response from the Grafana Alloy API.
        - Check the Grafana Alloy container logs (using `docker logs alloy`) for messages indicating that the configuration was reloaded successfully. There should be no authentication error messages.
    5. **Inject Malicious Configuration (Optional but Recommended for Full Validation)**:
        - Create a malicious `config.alloy` file. This file could be designed to forward collected metrics to an attacker-controlled HTTP endpoint using the `remote.http` component, or modify the data collection pipeline in other harmful ways.
        - Replace the original (or non-existent) `config.alloy` file mounted into the Grafana Alloy container with this malicious file. You might need to stop and remove the Alloy container (`docker stop alloy`, `docker rm alloy`) and then recreate it with `docker-compose up -d` to ensure the new `config.alloy` is mounted.
        - Repeat step 3: `curl -X POST http://localhost:12345/-/reload`.
        - Observe the behavior of Grafana Alloy. If the malicious configuration is successfully injected, you should see the intended malicious actions take effect (e.g., data being sent to the attacker's endpoint, monitoring being disrupted).

This test case confirms that the Grafana Alloy reload API is accessible without authentication in the default setup provided by the workshop, allowing for configuration injection and the potential impacts described in the vulnerability description.