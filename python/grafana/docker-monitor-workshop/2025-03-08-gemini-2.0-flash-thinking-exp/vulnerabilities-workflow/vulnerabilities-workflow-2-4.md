### Vulnerability List

- **Vulnerability Name:** Unauthenticated Access to Monitoring Stack Components

- **Description:**
    - The Docker Compose configuration provided for the workshop deploys Grafana, Loki, and Prometheus without any authentication enabled by default.
    - Step 1: Deploy the monitoring stack using `docker-compose up -d`.
    - Step 2: Identify the public IP address or hostname where the Docker Compose stack is deployed.
    - Step 3: Access Grafana UI by navigating to `http://<public_ip_or_hostname>:3000` in a web browser.
    - Step 4: Observe that Grafana UI is accessible without requiring any login credentials.
    - Step 5: Access Loki API by navigating to `http://<public_ip_or_hostname>:3100/loki/api/v1/status/buildinfo` in a web browser or using a tool like `curl`.
    - Step 6: Observe that Loki API endpoints are accessible without any authentication.
    - Step 7: Access Prometheus UI by navigating to `http://<public_ip_or_hostname>:9090` in a web browser.
    - Step 8: Observe that Prometheus UI is accessible without any authentication.
    - Step 9: Access Alloy UI by navigating to `http://<public_ip_or_hostname>:12345` in a web browser.
    - Step 10: Observe that Alloy UI is accessible without any authentication.

- **Impact:**
    - **Unauthorized Access to Sensitive Data:** Attackers can gain complete access to monitoring dashboards in Grafana, allowing them to view metrics, logs, and potentially other sensitive information collected by the monitoring stack.
    - **Information Disclosure:** Monitoring data can contain sensitive information about the application, infrastructure, and user activity. Unauthenticated access can lead to significant information disclosure.
    - **Grafana Admin Access:** Grafana is configured with `GF_AUTH_ANONYMOUS_ORG_ROLE=Admin`, granting anonymous users administrator privileges. This allows attackers to modify dashboards, data sources, alerts, and user settings within Grafana, potentially disrupting monitoring operations or using Grafana as a pivot point for further attacks.
    - **Loki and Prometheus Data Access:** Unauthenticated access to Loki and Prometheus allows attackers to query logs and metrics directly. This can be used to gather detailed information about system performance, errors, and security-related events.
    - **Alloy UI Access:** Unauthenticated access to Alloy UI exposes the configuration and operational status of the Alloy agent, which could be leveraged to understand the monitoring setup and potentially manipulate it if further vulnerabilities exist.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - None. The provided Docker Compose and configuration files do not implement any authentication or access control mechanisms for Grafana, Loki, Prometheus, or Alloy UI.

- **Missing Mitigations:**
    - **Enable Authentication for Grafana:** Configure Grafana to require authentication. Disable anonymous access by setting `GF_AUTH_ANONYMOUS_ENABLED=false` and enable basic authentication or integrate with an external authentication provider (like OAuth 2.0, LDAP, or SAML).
    - **Implement Authentication and Authorization for Loki:** Configure Loki to enable authentication. This can be done using various methods like HTTP Basic Auth, OAuth 2.0, or mTLS. Implement authorization policies to control access to log streams.
    - **Implement Authentication and Authorization for Prometheus:** Configure Prometheus to enable authentication. Similar to Loki, Prometheus supports authentication methods like HTTP Basic Auth, OAuth 2.0, and TLS client authentication. Use authorization rules to restrict access to metrics and API endpoints.
    - **Restrict Access to Alloy UI:** If Alloy UI is not intended for public access, restrict access to it using network-level firewalls or by configuring authentication within Alloy itself if possible. Consider disabling Alloy UI in production deployments if it's not necessary for operational purposes.

- **Preconditions:**
    - The workshop participant deploys the Docker Compose stack as provided and makes the ports (3000, 3100, 9090, 12345) accessible from a network that an attacker can reach. This could be a public IP address or a network accessible via VPN.

- **Source Code Analysis:**
    - **`/code/docker-compose.yml`**:
        - Exposes port `3000:3000` for Grafana, `3100:3100` for Loki, `9090:9090` for Prometheus, and `12345:12345` for Alloy. This makes these services accessible on the host machine's network interfaces.
        - Grafana service configuration includes environment variables:
            - `GF_AUTH_ANONYMOUS_ENABLED=true`:  **This explicitly enables anonymous access to Grafana.**
            - `GF_AUTH_ANONYMOUS_ORG_ROLE=Admin`: **This grants anonymous users Admin role within Grafana, providing full administrative privileges.**
            - `GF_AUTH_BASIC_ENABLED=false`: Disables basic authentication, further reinforcing anonymous access as the primary access method.
    - **`/code/loki-config.yaml`**:
        - `auth_enabled: false`: **This explicitly disables authentication for Loki.** This means all Loki API endpoints are publicly accessible without any credentials.
    - **Prometheus Configuration**:
        - The `docker-compose.yml` file uses the default Prometheus image and only specifies command-line arguments. It does not include any configuration files to enable authentication. By default, Prometheus does not have authentication enabled.
    - **Alloy Configuration**:
        - The `docker-compose.yml` file exposes port `12345` for Alloy and mounts `./config.alloy:/etc/alloy/config.alloy`. While the `config.alloy` file content is not provided in the project files, the command `run --server.http.listen-addr=0.0.0.0:12345` suggests that the Alloy UI is exposed on `0.0.0.0:12345` without any specific authentication configuration in the provided files.

- **Security Test Case:**
    1. **Setup:**
        - Clone the repository: `git clone https://github.com/grafana/docker-monitor-workshop.git`
        - Navigate to the code directory: `cd docker-monitor-workshop/code`
        - Deploy the monitoring stack: `docker-compose up -d`
    2. **Test Grafana Unauthenticated Access:**
        - Open a web browser and go to `http://localhost:3000`.
        - Verify that you are able to access the Grafana dashboard without being prompted for login credentials.
        - Navigate through Grafana menus and settings. Verify that you have administrator privileges (e.g., you can add data sources, create dashboards, modify users, etc.).
    3. **Test Loki Unauthenticated Access:**
        - Open a web browser or use `curl`.
        - Access the Loki build info endpoint: `http://localhost:3100/loki/api/v1/status/buildinfo`
        - Verify that you receive a JSON response containing Loki build information without any authentication challenge.
    4. **Test Prometheus Unauthenticated Access:**
        - Open a web browser and go to `http://localhost:9090`.
        - Verify that you are able to access the Prometheus UI without being prompted for login credentials.
        - Navigate through Prometheus menus and explore metrics.
    5. **Test Alloy UI Unauthenticated Access:**
        - Open a web browser and go to `http://localhost:12345`.
        - Verify that you are able to access the Alloy UI without being prompted for login credentials.
        - Explore the Alloy UI to view configuration and status.

    If all steps in 2, 3, 4, and 5 are successful in accessing the services without authentication, the vulnerability is confirmed.