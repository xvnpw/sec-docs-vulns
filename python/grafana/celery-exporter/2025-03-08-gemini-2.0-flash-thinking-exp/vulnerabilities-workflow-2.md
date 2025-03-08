## Vulnerability: Unauthenticated Prometheus Metrics Endpoint

- **Description:**
    The Celery Exporter exposes a Prometheus metrics endpoint at `/metrics` which provides detailed operational data about the Celery application. This endpoint is served via HTTP on the address and port specified by the `--listen-address` option, defaulting to `0.0.0.0:9540`. By default, no authentication or authorization mechanisms are implemented to protect access to this endpoint. Consequently, if the Celery Exporter is deployed with its metrics port publicly accessible, an attacker can retrieve sensitive information about the Celery application by sending an HTTP GET request to the `/metrics` endpoint.

    Steps to trigger the vulnerability:
    1. Deploy the Celery Exporter with the default configuration, allowing it to listen on `0.0.0.0:9540`.
    2. Ensure the exporter's host is publicly accessible on port 9540.
    3. An attacker identifies the public IP address or hostname where the Celery Exporter is running and the metrics port.
    4. The attacker sends an HTTP GET request to `http://<exporter-address>:<metrics-port>/metrics` using tools like `curl` or a web browser.
    5. The exporter responds with the metrics data in Prometheus format, without requiring any authentication.
    6. The attacker parses the metrics data to gather information about the Celery application.

- **Impact:**
    Exposure of sensitive information about the Celery application. This information includes:
    - Number of Celery workers (`celery_workers`).
    - Number of tasks in different states (received, pending, started, retry, failure, revoked, success) labeled by task name, state, queue, and namespace (`celery_tasks_total`).
    - Task runtime histograms labeled by task name and queue (`celery_tasks_runtime_seconds`).
    - Task latency histograms labeled by task name and queue (`celery_tasks_latency_seconds`).
    - Queue lengths (`celery_queue_length`) if queue monitoring is enabled.

    This information disclosure can lead to:
    - **Business Logic Exposure:** Task names might reveal business logic, application features, or internal processes.
    - **Operational Insights for Attackers:** Metrics like task states, runtime, and latency can provide attackers with insights into application performance and potential weaknesses, aiding in planning more targeted attacks.
    - **Monitoring Eavesdropping:** Attackers can continuously monitor the metrics to understand application behavior, performance bottlenecks, and task processing patterns.
    - **Reduced Security Posture:** Exposing internal metrics without access control weakens the overall security posture by providing unnecessary information to potential attackers.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    None. The Celery Exporter does not implement any authentication or authorization mechanisms for the metrics endpoint by default.

- **Missing Mitigations:**
    - **Authentication:** Implement authentication to verify the identity of clients accessing the metrics endpoint. Basic authentication, API key authentication, or integration with more robust authentication protocols like OAuth 2.0 could be considered.
    - **Authorization:** Implement authorization to control which clients are allowed to access the metrics endpoint. This could be based on IP address whitelisting, role-based access control, or other authorization methods.
    - **Network Segmentation:** Deploy the Celery Exporter in a secured network segment, isolated from public access. Use network firewalls or security groups to restrict access to the metrics endpoint from untrusted networks or the public internet.
    - **Configuration Option for Access Control:** Provide configuration options to enable or disable public access to the metrics endpoint, or to configure authentication methods, allowing users to secure the endpoint as needed.
    - **Documentation Update:** Clearly document the security implications of exposing the metrics endpoint publicly and advise users to implement appropriate access controls, emphasizing network security best practices and potential authentication mechanisms.

- **Preconditions:**
    - The Celery Exporter is deployed with the metrics port exposed to a network accessible by the attacker, typically using the default `listen_address` (`0.0.0.0:9540`).
    - No network access control (firewall rules, security groups) or authentication is configured to protect the metrics endpoint.

- **Source Code Analysis:**
    - The vulnerability originates from the way the HTTP server is started for the Prometheus metrics endpoint within the Celery Exporter's codebase.
    - In `/code/celery_exporter/core.py`, the `CeleryExporter` class's `_start_httpd` method is responsible for starting the HTTP server.
    ```python
    def _start_httpd(self):  # pragma: no cover
        """
        Starts the exposing HTTPD using the addr provided in a separate
        thread.
        """
        host, port = self._listen_address.split(":")
        logger.info(f"Starting HTTPD on {host}:{port}")
        prometheus_client.start_http_server(int(port), host) # Vulnerable line - no authentication
    ```
    - The `prometheus_client.start_http_server(int(port), host)` function, part of the `prometheus-client` library, is used to initiate the HTTP server. Critically, this function, when used in this manner, does not incorporate any built-in authentication or authorization mechanisms. It simply serves the registered Prometheus metrics on the `/metrics` path without access control.
    - Examining `/code/celery_exporter/__main__.py`, the `--listen-address` option is defined, which defaults to `0.0.0.0:9540`. This default setting, combined with the lack of authentication in `prometheus_client.start_http_server`, directly leads to the vulnerability if the exporter is deployed in an environment where this port is publicly accessible.
    ```python
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
    - The `README.md` provides instructions on deployment and usage but lacks essential security guidance regarding the protection of the metrics endpoint, further exacerbating the risk.

- **Security Test Case:**
    1. **Deployment:** Deploy the `celery-exporter` using Docker or a manual setup, ensuring it's configured with default settings and connected to a running Celery application that generates metrics. Expose port `9540` of the container or host to the network for external access.
        ```bash
        docker run -d -p 9540:9540 ovalmoney/celery-exporter
        ```
    2. **Obtain Public IP:** Identify the public IP address or hostname of the machine or instance where the `celery-exporter` is running.
    3. **Access Metrics Endpoint (Attacker's Perspective):** From an attacker machine with network access to the deployed `celery-exporter`, use `curl` or a web browser to attempt to access the metrics endpoint.
        ```bash
        curl http://<public-ip-or-hostname>:9540/metrics
        ```
    4. **Verify Unauthenticated Access:** Observe the HTTP response. If the vulnerability exists, the server will respond with HTTP status code `200 OK` and the body will contain Prometheus metrics data. No authentication challenge (like HTTP `401 Unauthorized` or a login prompt) should be presented.
    5. **Analyze Metrics Data:** Examine the returned Prometheus metrics data. Confirm that it includes sensitive information such as:
        ```
        # HELP celery_workers Number of alive workers
        # TYPE celery_workers gauge
        celery_workers{namespace="celery"} 1.0
        # HELP celery_tasks_total Number of tasks per state
        # TYPE celery_tasks_total gauge
        celery_tasks_total{name="my_app.tasks.calculate_something",namespace="celery",queue="celery",state="RECEIVED"} 0.0
        celery_tasks_total{name="my_app.tasks.calculate_something",namespace="celery",queue="celery",state="PENDING"} 0.0
        ...
        ```
    6. **Confirmation:** Successful retrieval of Prometheus metrics without any authentication demonstrates the vulnerability, confirming that the metrics endpoint is publicly accessible and exposes sensitive operational information about the Celery application.