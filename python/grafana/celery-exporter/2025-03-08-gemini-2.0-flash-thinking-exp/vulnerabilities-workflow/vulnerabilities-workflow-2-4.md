### Vulnerability 1: Information Disclosure via Publicly Accessible Metrics Endpoint

- Description:
    - Celery Exporter exposes a `/metrics` endpoint that provides detailed metrics about the Celery application, including task names, states, runtime, latency, and worker information.
    - By default, the exporter listens on address `0.0.0.0:9540`, as configured in `celery_exporter/__main__.py` and documented in `README.md`.
    - This default configuration makes the metrics endpoint publicly accessible if the exporter is deployed on a publicly accessible server.
    - An attacker can access this endpoint without any authentication or authorization.
    - Once accessed, the attacker can scrape Prometheus metrics data, revealing sensitive information about the Celery application's internal operations.
    - This information can include:
        - Names of Celery tasks being executed, potentially revealing business logic or application functionality.
        - States of tasks (PENDING, RECEIVED, STARTED, SUCCESS, FAILURE, RETRY, REVOKED, REJECTED), indicating workload and processing status.
        - Runtime and latency of tasks, which could expose performance characteristics or bottlenecks.
        - Number of Celery workers, providing insight into the application's scaling and capacity.
        - Queue names, revealing the application's task routing and prioritization.
    - Step-by-step trigger:
        1. Deploy Celery Exporter with the default configuration (`listen_address: 0.0.0.0:9540`).
        2. Ensure the exporter's host is publicly accessible on port 9540.
        3. An attacker from an external network accesses the metrics endpoint using a web browser or `curl` at `http://<exporter-host-ip>:9540/metrics`.
        4. The exporter responds with Prometheus metrics data without requesting any authentication.
        5. The attacker parses the metrics data to gather information about the Celery application.

- Impact:
    - **Information Disclosure:** Publicly exposed metrics can reveal sensitive information about the Celery application's internal workings.
    - **Business Logic Exposure:** Task names might disclose business logic, application features, or internal processes.
    - **Operational Insights for Attackers:** Metrics like task states, runtime, and latency can provide attackers with insights into application performance and potential weaknesses.
    - **Reduced Security Posture:** Exposing internal metrics without access control weakens the overall security posture by providing unnecessary information to potential attackers.

- Vulnerability Rank: Medium

- Currently Implemented Mitigations:
    - None. The provided code and documentation do not include any built-in mechanisms for authentication or access control to the `/metrics` endpoint.

- Missing Mitigations:
    - **Authentication and Authorization:** Implement authentication and authorization mechanisms to restrict access to the `/metrics` endpoint.
        - Options include:
            - Basic Authentication: Simple username/password protection.
            - API Key Authentication: Require a valid API key in the request header or query parameter.
            - OAuth 2.0 or similar protocols: For more robust and centralized authentication and authorization.
    - **Configuration Option for Access Control:** Provide configuration options to enable or disable public access to the metrics endpoint, or to configure authentication methods.
    - **Documentation Update:** Clearly document the security implications of exposing the metrics endpoint publicly and advise users to implement appropriate access controls.

- Preconditions:
    - Celery Exporter is deployed with the default `listen_address` (`0.0.0.0:9540`).
    - The network where Celery Exporter is deployed allows public access to port 9540.

- Source Code Analysis:
    - `celery_exporter/core.py`:
        - The `CeleryExporter` class initializes and starts the Prometheus HTTP server in the `_start_httpd` method.
        - ```python
          def _start_httpd(self):  # pragma: no cover
              """
              Starts the exposing HTTPD using the addr provided in a separate
              thread.
              """
              host, port = self._listen_address.split(":")
              logger.info(f"Starting HTTPD on {host}:{port}")
              prometheus_client.start_http_server(int(port), host)
          ```
        - `prometheus_client.start_http_server(int(port), host)` starts a basic HTTP server without any authentication or authorization middleware.
    - `celery_exporter/__main__.py`:
        - The `listen_address` option defaults to `0.0.0.0:9540`.
        - ```python
          @click.option(
              "--listen-address",
              "-l",
              type=str,
              show_default=True,
              show_envvar=True,
              default="0.0.0.0:9540",
              help="Address the HTTPD should listen on.",
          )
          ```
        - This default address makes the endpoint accessible on all network interfaces, including public ones.
    - No code in the provided files implements any form of authentication or access control for the HTTP server or the `/metrics` endpoint.

- Security Test Case:
    1. **Setup:**
        - Deploy Celery Exporter using Docker or manual setup as described in the `README.md`. Use the default configuration, ensuring no authentication is configured.
        - Make sure the host machine where Celery Exporter is running is publicly accessible, or at least accessible from a separate testing network.
        - Start Celery and Celery workers to generate some metrics.
    2. **Access Metrics Endpoint:**
        - From an external machine (or a machine on a different network segment), open a web browser or use `curl` to access the metrics endpoint of the deployed Celery Exporter.
        - The URL will be `http://<exporter-host-ip>:9540/metrics`, where `<exporter-host-ip>` is the public IP address or hostname of the machine running Celery Exporter.
    3. **Verify Public Access:**
        - Observe that the metrics data is returned in the Prometheus format without any authentication challenge (e.g., HTTP 401 Unauthorized or login prompt).
        - Examine the returned metrics data. It should contain metrics like `celery_tasks_total`, `celery_tasks_runtime_seconds`, `celery_tasks_latency_seconds`, and `celery_workers`, as described in `README.md`.
    4. **Analyze Exposed Information:**
        - Review the scraped metrics and identify sensitive information that is exposed, such as task names, task states, queue names, worker counts, and performance metrics.
        - For example, task names might reveal internal application functionality, and task states could indicate current workload.
    5. **Expected Result:**
        - The metrics endpoint should be publicly accessible without authentication.
        - Sensitive information about the Celery application should be readily available in the scraped metrics data.
        - This test case confirms the information disclosure vulnerability due to the lack of access control on the metrics endpoint.