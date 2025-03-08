### 1. Unprotected Metrics Endpoint

- **Description:**
An attacker can access the Prometheus metrics endpoint without any authentication or authorization. The Celery Exporter exposes metrics at the `/metrics` endpoint on the address and port specified by the `--listen-address` option (default `0.0.0.0:9540`). By default, there are no security mechanisms in place to restrict access to this endpoint. An attacker can simply send an HTTP GET request to this endpoint to retrieve sensitive information about the Celery application.

Steps to trigger the vulnerability:
1. Deploy the Celery Exporter and make the metrics port (default `9540`) publicly accessible.
2. An attacker identifies the public IP address or hostname where the Celery Exporter is running and the metrics port.
3. The attacker sends an HTTP GET request to `http://<exporter-address>:<metrics-port>/metrics`.
4. The exporter responds with the metrics data in Prometheus format, which includes information about tasks, workers, and queues of the Celery application.

- **Impact:**
Exposure of sensitive information about the Celery application. This information includes:
    - Number of Celery workers (`celery_workers`).
    - Number of tasks in different states (received, pending, started, retry, failure, revoked, success) labeled by task name, state, queue, and namespace (`celery_tasks_total`).
    - Task runtime histograms labeled by task name and queue (`celery_tasks_runtime_seconds`).
    - Task latency histograms labeled by task name and queue (`celery_tasks_latency_seconds`).
    - Queue lengths (`celery_queue_length`) if queue monitoring is enabled.

This information can be used by an attacker to:
    - Gain insights into the application's functionality and task processing logic by analyzing task names.
    - Monitor the application's performance and identify potential bottlenecks.
    - Gather information for further attacks by understanding the application's internal state and workload.
    - Potentially identify sensitive task names or queue names that reveal business logic or data handling processes.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - None. The Celery Exporter does not implement any authentication or authorization mechanisms for the metrics endpoint.

- **Missing Mitigations:**
    - **Authentication:** Implement authentication to verify the identity of clients accessing the metrics endpoint. Basic authentication or API keys could be used.
    - **Authorization:** Implement authorization to control which clients are allowed to access the metrics endpoint. This could be based on IP address whitelisting or more sophisticated role-based access control.
    - **Network Access Control:** Document and recommend the use of network firewalls or security groups to restrict access to the metrics endpoint to trusted networks or IP ranges. This is mentioned in the initial description of the vulnerability but not explicitly in the README.

- **Preconditions:**
    - The Celery Exporter is deployed with the metrics port exposed to a network accessible by the attacker.
    - No network access control or authentication is configured to protect the metrics endpoint.

- **Source Code Analysis:**
    - In `/code/celery_exporter/core.py`, the `CeleryExporter` class in the `_start_httpd` method uses `prometheus_client.start_http_server(int(port), host)` to start the HTTP server.
    ```python
    def _start_httpd(self):  # pragma: no cover
        """
        Starts the exposing HTTPD using the addr provided in a separate
        thread.
        """
        host, port = self._listen_address.split(":")
        logger.info(f"Starting HTTPD on {host}:{port}")
        prometheus_client.start_http_server(int(port), host)
    ```
    - The `prometheus_client.start_http_server` function, as used here, does not provide any built-in options for authentication or authorization. It simply starts an HTTP server that serves the Prometheus metrics on the `/metrics` endpoint.
    - Examining the `__main__.py` file, the `--listen-address` option is used to configure the address for the HTTP server, but there are no options related to authentication or authorization.
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
    - The `README.md` provides instructions on how to install and run the exporter but lacks any security guidance on protecting the metrics endpoint.

- **Security Test Case:**
    1. Deploy the `celery-exporter` using Docker: `docker run -d -p 9540:9540 ovalmoney/celery-exporter`.
    2. Obtain the public IP address of the machine where the Docker container is running (e.g., `http://<public-ip>:9540/metrics`).
    3. Use `curl` or a web browser to access the metrics endpoint without any authentication: `curl http://<public-ip>:9540/metrics`.
    4. Verify that the response contains Prometheus metrics, including `celery_workers`, `celery_tasks_total`, `celery_tasks_runtime_seconds`, and `celery_tasks_latency_seconds`.
    5. Example of expected output (partial):
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
    6. This confirms that the metrics endpoint is publicly accessible without authentication, exposing sensitive information.