### Vulnerability List:

- Vulnerability Name: Unauthenticated Prometheus Metrics Endpoint
- Description:
    - The Celery Exporter exposes Prometheus metrics in Prometheus format via an HTTP endpoint.
    - By default, this endpoint is served on all network interfaces (0.0.0.0:9540) without any form of authentication or authorization.
    - An attacker who can reach this endpoint over the network can access and retrieve all exported metrics.
    - These metrics include sensitive information about the Celery application, such as:
        - `celery_tasks_total`: Number of tasks per state, labeled by task name, state, queue, and namespace.
        - `celery_tasks_runtime_seconds`: Task runtime histogram, labeled by task name, queue, and namespace.
        - `celery_tasks_latency_seconds`: Task latency histogram.
        - `celery_workers`: Number of alive workers.
    - This information can reveal details about the application's tasks, performance, internal architecture, and potentially business logic depending on the task names.
- Impact:
    - Information Disclosure: An attacker can gain unauthorized access to sensitive operational data about the Celery application.
    - Monitoring Eavesdropping: Attackers can continuously monitor the metrics to understand application behavior, performance bottlenecks, and task processing patterns.
    - Potential for Further Attacks: Exposed metrics can provide valuable insights for attackers to plan more targeted attacks, such as identifying critical tasks or understanding system load.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations:
    - None. The application does not implement any authentication or authorization mechanisms for the metrics endpoint.
- Missing Mitigations:
    - Authentication: Implement authentication to restrict access to the metrics endpoint to authorized users or systems. Basic authentication, API key authentication, or integration with an external authentication provider could be considered.
    - Network Segmentation: Deploy the Celery Exporter in a secured network segment, isolated from public access. Use firewalls or network policies to restrict access to the metrics endpoint from untrusted networks.
- Preconditions:
    - The Celery Exporter is deployed and running.
    - The HTTP metrics endpoint (default port 9540) is reachable over the network by the attacker. This is especially critical if the exporter is exposed to the public internet or an untrusted network.
- Source Code Analysis:
    - `celery_exporter/__main__.py`:
        - The `main` function uses `click` to parse command-line arguments, including `--listen-address` which defaults to `0.0.0.0:9540`.
        - This address is passed to the `CeleryExporter` class in `celery_exporter/core.py`.
    - `celery_exporter/core.py`:
        - The `CeleryExporter` class's `__init__` method stores the `listen_address`.
        - The `start` method calls `self._start_httpd()`.
        - The `_start_httpd` method:
            - Splits the `self._listen_address` into host and port.
            - Calls `prometheus_client.start_http_server(int(port), host)` to start the Prometheus HTTP server.
        - The `prometheus_client.start_http_server` function from the `prometheus-client` library, used here, does not include any built-in authentication or authorization mechanisms. It simply starts an HTTP server that exposes the registered metrics on the `/metrics` path.

    ```python
    # celery_exporter/core.py - _start_httpd method
    def _start_httpd(self):  # pragma: no cover
        """
        Starts the exposing HTTPD using the addr provided in a separate
        thread.
        """
        host, port = self._listen_address.split(":")
        logger.info(f"Starting HTTPD on {host}:{port}")
        prometheus_client.start_http_server(int(port), host) # Vulnerable line - no authentication
    ```

- Security Test Case:
    1. Deploy and run the Celery Exporter using the default configuration, allowing it to listen on `0.0.0.0:9540`. Ensure that Celery is running and generating tasks so that metrics are populated.
    2. From an attacker machine that has network access to the deployed Celery Exporter, use `curl` or a web browser to access the metrics endpoint. For example, if the exporter is running on IP address `192.168.1.100`, the attacker would execute:
        ```bash
        curl http://192.168.1.100:9540/metrics
        ```
    3. Observe the response from the server.
    4. Verify that the response contains Prometheus metrics data, including metrics like `celery_tasks_total`, `celery_tasks_runtime_seconds`, `celery_tasks_latency_seconds`, and `celery_workers`.
    5. Confirm that no authentication was required to access these metrics, demonstrating the vulnerability.