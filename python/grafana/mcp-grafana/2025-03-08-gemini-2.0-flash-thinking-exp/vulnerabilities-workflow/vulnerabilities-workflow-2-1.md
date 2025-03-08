- Vulnerability Name: PromQL Injection in `query_prometheus` tool
- Description:
    - A malicious user can exploit the `query_prometheus` tool by crafting a PromQL expression (`expr` parameter) that, when executed, can extract sensitive information from Prometheus or manipulate data beyond the intended scope of the Grafana user's permissions.
    - Step 1: The attacker uses the `query_prometheus` tool and provides a crafted PromQL query as the `expr` parameter.
    - Step 2: The `query_prometheus` function in `src/mcp_grafana/tools/prometheus.py` directly passes this user-supplied `expr` to the `grafana_client.query` function without any sanitization or validation.
    - Step 3: The `grafana_client.query` function in `src/mcp_grafana/client.py` then sends this unsanitized PromQL query to the Grafana API.
    - Step 4: Grafana executes the PromQL query against the configured Prometheus datasource.
    - Step 5: If the crafted PromQL query contains malicious or unintended logic, it will be executed by Prometheus, potentially leading to information disclosure or other unintended consequences.
- Impact:
    - Sensitive information disclosure: An attacker could craft PromQL queries to access metrics and labels beyond the intended scope, potentially exposing sensitive data monitored by Prometheus.
    - Data manipulation (potential, depending on Prometheus configuration): While less likely in a read-only context, if the Prometheus datasource is misconfigured or if future features allow write operations, a successful injection could potentially lead to data manipulation within Prometheus.
    - Unauthorized access to Prometheus data: Circumventing intended access controls within Grafana and directly querying Prometheus data.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The code directly passes the user-provided PromQL expression to the Grafana API without any sanitization or validation.
- Missing Mitigations:
    - Input sanitization: Sanitize the PromQL expression to remove or escape potentially harmful characters or PromQL functions before sending it to the Grafana API.
    - Input validation: Validate the PromQL expression against a whitelist of allowed functions and syntax to ensure it conforms to expected and safe queries.
    - Principle of least privilege: Ensure that the Grafana service account used by the MCP server has the minimum necessary permissions in Grafana and Prometheus to limit the impact of a potential injection.
- Preconditions:
    - The `query_prometheus` tool must be enabled in the MCP server configuration.
    - An attacker must have access to the MCP server and the ability to use the `query_prometheus` tool.
    - The Grafana instance must be configured with a Prometheus datasource.
- Source Code Analysis:
    - File: `/code/src/mcp_grafana/tools/prometheus.py`
    ```python
    async def query_prometheus(
        datasource_uid: str,
        expr: str, # User-provided PromQL expression
        start_rfc3339: str,
        end_rfc3339: str | None = None,
        step_seconds: int | None = None,
        query_type: PrometheusQueryType = "range",
    ) -> DSQueryResponse:
        # ... (omitted validation of other parameters) ...
        query = Query(
            refId="A",
            datasource=DatasourceRef(
                uid=datasource_uid,
                type="prometheus",
            ),
            queryType=query_type,
            expr=expr,  # Directly using user-provided expr
            intervalMs=interval_ms,
        )
        response = await grafana_client.query(start, end, [query]) # Passing the query to client
        return DSQueryResponse.model_validate_json(response)
    ```
    - The `query_prometheus` function takes the `expr` argument directly from the user input and incorporates it into the `Query` object without any checks.
    - File: `/code/src/mcp_grafana/client.py`
    ```python
    class GrafanaClient:
        # ... (omitted constructor and other methods) ...
        async def query(self, _from: datetime, to: datetime, queries: list[Query]) -> bytes:
            body = {
                "from": str(math.floor(_from.timestamp() * 1000)),
                "to": str(math.floor(to.timestamp() * 1000)),
                "queries": query_list.dump_python(queries, by_alias=True),
            }
            return await self.post("/api/ds/query", json=body) # Sending POST request to /api/ds/query with queries in body
    ```
    - The `grafana_client.query` function receives the `Query` object (which contains the unsanitized `expr`) and sends it in a POST request to the `/api/ds/query` endpoint of the Grafana API.
    - There is no input validation or sanitization performed on the `expr` at any point in the code before it reaches the Grafana API. This allows for direct PromQL injection.

- Security Test Case:
    - Pre-requisites:
        - A running Grafana instance accessible at `http://localhost:3000` with a Prometheus datasource named "Robust Perception" (as configured in `docker-compose.yaml` and `tests/provisioning/datasources/datasources.yaml`).
        - The MCP server is running and accessible.
        - The `query_prometheus` tool is enabled.
    - Steps:
        - Step 1: Send a request to the MCP server to execute the `query_prometheus` tool.
        - Step 2: In the request, provide the datasource UID as "robustperception".
        - Step 3: For the `expr` parameter, inject a PromQL query designed to extract sensitive label values. For example, use `up{__name__=~".*"}` to retrieve all label values for the `up` metric, which could include internal job names or instance details not intended for public exposure. A more targeted example to potentially leak service names could be `up{job!=""}`. A more aggressive query to list all metrics: `{__name__!=""}`. For testing purposes, to demonstrate injection without leaking sensitive info from public demo Prometheus, use a query that should return a valid but different result than intended, like `up + 0`. If the original query was intended to just get `up`, this will modify the output.
        - Step 4: Set `query_type` to "instant", and provide a valid `start_rfc3339` time (e.g., current time in ISO format). `end_rfc3339` and `step_seconds` are not needed for instant queries.
        - Step 5: Send the request to the MCP server and observe the response.
        - Step 6: Verify that the response from the MCP server contains the results of the injected PromQL query (e.g., for `up{job!=""}`, it returns label values for `job` label associated with `up` metric, or for `up + 0`, the values are modified). If you used `{__name__!=""}`, the response will contain a large amount of metric data, indicating successful data extraction beyond the intended scope of a simple `up` query.

This test case demonstrates that a malicious user can inject arbitrary PromQL queries through the `query_prometheus` tool and potentially extract sensitive information from the Prometheus datasource.