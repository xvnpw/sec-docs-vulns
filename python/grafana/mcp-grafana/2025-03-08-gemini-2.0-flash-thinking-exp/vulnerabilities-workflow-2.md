## Combined Vulnerability List

This document outlines the identified vulnerabilities within the Grafana MCP server project. Each vulnerability is detailed below, including its description, potential impact, severity ranking, current mitigations, missing mitigations, preconditions for exploitation, source code analysis, and a security test case to demonstrate its existence.

### 1. PromQL Injection in `query_prometheus` tool

- **Description:**
    - A malicious user can exploit the `query_prometheus` tool by crafting a PromQL expression (`expr` parameter) that, when executed, can extract sensitive information from Prometheus or manipulate data beyond the intended scope of the Grafana user's permissions.
    - Step 1: The attacker uses the `query_prometheus` tool and provides a crafted PromQL query as the `expr` parameter.
    - Step 2: The `query_prometheus` function in `src/mcp_grafana/tools/prometheus.py` directly passes this user-supplied `expr` to the `grafana_client.query` function without any sanitization or validation.
    - Step 3: The `grafana_client.query` function in `src/mcp_grafana/client.py` then sends this unsanitized PromQL query to the Grafana API.
    - Step 4: Grafana executes the PromQL query against the configured Prometheus datasource.
    - Step 5: If the crafted PromQL query contains malicious or unintended logic, it will be executed by Prometheus, potentially leading to information disclosure or other unintended consequences.

- **Impact:**
    - Sensitive information disclosure: An attacker could craft PromQL queries to access metrics and labels beyond the intended scope, potentially exposing sensitive data monitored by Prometheus.
    - Data manipulation (potential, depending on Prometheus configuration): While less likely in a read-only context, if the Prometheus datasource is misconfigured or if future features allow write operations, a successful injection could potentially lead to data manipulation within Prometheus.
    - Unauthorized access to Prometheus data: Circumventing intended access controls within Grafana and directly querying Prometheus data.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - None. The code directly passes the user-provided PromQL expression to the Grafana API without any sanitization or validation.

- **Missing Mitigations:**
    - Input sanitization: Sanitize the PromQL expression to remove or escape potentially harmful characters or PromQL functions before sending it to the Grafana API.
    - Input validation: Validate the PromQL expression against a whitelist of allowed functions and syntax to ensure it conforms to expected and safe queries.
    - Principle of least privilege: Ensure that the Grafana service account used by the MCP server has the minimum necessary permissions in Grafana and Prometheus to limit the impact of a potential injection.

- **Preconditions:**
    - The `query_prometheus` tool must be enabled in the MCP server configuration.
    - An attacker must have access to the MCP server and the ability to use the `query_prometheus` tool.
    - The Grafana instance must be configured with a Prometheus datasource.

- **Source Code Analysis:**
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

- **Security Test Case:**
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

### 2. API Key Exposure through Environment Variables

- **Description:**
    - The Grafana MCP server application uses the `GRAFANA_API_KEY` environment variable to authenticate with the Grafana API.
    - Environment variables are a common way to configure applications, but they can be vulnerable to exposure if the server environment is compromised or misconfigured.
    - An attacker who gains access to the server environment (e.g., through a server breach, insider threat, or misconfigured access controls) can potentially read the `GRAFANA_API_KEY` environment variable.
    - Once the attacker obtains the `GRAFANA_API_KEY`, they can use it to make unauthorized requests to the Grafana API, bypassing normal authentication mechanisms.

- **Impact:**
    - Successful exploitation of this vulnerability allows an attacker to gain unauthorized access to the Grafana instance.
    - The level of access depends on the permissions associated with the Grafana API key. An attacker could potentially:
        - View sensitive dashboards and data sources.
        - Access and modify Grafana configurations.
        - View and manipulate incidents.
        - Potentially gain further access to systems integrated with Grafana, depending on the Grafana instance's configuration and network setup.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - The project documentation (File: `/code/README.md`) recommends creating a Grafana service account with limited permissions. This is a good practice to reduce the potential impact of a compromised API key by limiting the actions an attacker can perform even if they obtain the key. This mitigation is documented in the "Usage" section of the README.md file.

- **Missing Mitigations:**
    - **Secure Storage for API Key:** The API key is currently read directly from environment variables, which are not a secure storage mechanism. Missing mitigations include:
        - Using a secrets management system (like HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, or Google Secret Manager) to store and retrieve the API key.
        - Encrypting the configuration file where the API key is stored, although this is less secure than a dedicated secrets manager.
        - Avoiding storing the API key directly in environment variables in production environments.
    - **Input Validation and Sanitization:** While less directly related to exposure, the application does not perform any validation or sanitization on the API key itself. Although in this scenario the API key is treated as a bearer token by `httpx`, validating the format of the key could add a layer of defense in depth.

- **Preconditions:**
    - The Grafana MCP server must be deployed and configured to use a `GRAFANA_API_KEY` environment variable for authentication.
    - An attacker must gain unauthorized access to the environment where the Grafana MCP server is running. This could be through various means, such as:
        - Exploiting vulnerabilities in the server's operating system or other software.
        - Gaining access through compromised credentials (e.g., SSH keys, passwords).
        - Insider threat.
        - Misconfiguration of cloud environment or container orchestration platform, leading to unintended exposure of environment variables.

- **Source Code Analysis:**
    1. **Configuration Loading (`/code/src/mcp_grafana/settings.py`):**
        ```python
        class GrafanaSettings(BaseSettings):
            model_config: SettingsConfigDict = SettingsConfigDict(
                env_prefix="GRAFANA_", env_file=".env", env_nested_delimiter="__"
            )

            ...
            api_key: str | None = Field(
                default=None,
                description="A Grafana API key or service account token with the necessary permissions to use the tools.",
            )
        ```
        This code snippet from `src/mcp_grafana/settings.py` shows that the `GrafanaSettings` class, which is responsible for loading configuration, is set up to read environment variables with the prefix `GRAFANA_`. Specifically, the `api_key` field is intended to be populated from the `GRAFANA_API_KEY` environment variable.

    2. **Client Authentication (`/code/src/mcp_grafana/client.py`):**
        ```python
        class GrafanaClient:
            def __init__(self, url: str, api_key: str | None = None) -> None:
                auth = BearerAuth(api_key) if api_key is not None else None
                self.c = httpx.AsyncClient(
                    base_url=url, auth=auth, timeout=httpx.Timeout(timeout=30.0)
                )
        ```
        ```python
        grafana_client = GrafanaClient(grafana_settings.url, api_key=grafana_settings.api_key)
        ```
        In `src/mcp_grafana/client.py`, the `GrafanaClient` class initializes an `httpx.AsyncClient`. If an `api_key` is provided during `GrafanaClient` instantiation, a `BearerAuth` object is created and used for authentication. The `grafana_client` instance is created using settings loaded by `GrafanaSettings`, including the `api_key` from the environment variable.

    3. **Bearer Authentication Class (`/code/src/mcp_grafana/client.py`):**
        ```python
        class BearerAuth(httpx.Auth):
            def __init__(self, api_key: str):
                self.api_key = api_key

            def auth_flow(self, request):
                request.headers["Authorization"] = f"Bearer {self.api_key}"
                yield request
        ```
        The `BearerAuth` class in `src/mcp_grafana/client.py` explicitly sets the `Authorization` header with the `Bearer` scheme and the provided `api_key`. This confirms that the `GRAFANA_API_KEY` environment variable is directly used as the API key for authenticating requests to the Grafana API.

    **Visualization:**

    ```
    Environment Variable (GRAFANA_API_KEY) --> GrafanaSettings (api_key) --> GrafanaClient (api_key) --> BearerAuth --> HTTP Request (Authorization Header) --> Grafana API
    ```

    This flow clearly shows how the API key from the environment variable is used to authenticate with Grafana. If an attacker can access the environment variables, they can retrieve the `GRAFANA_API_KEY` and impersonate the MCP server.

- **Security Test Case:**
    1. **Prerequisites:**
        - Deploy a Grafana instance (e.g., using Docker Compose as described in `/code/docker-compose.yaml`).
        - Build and run the `mcp-grafana` server (e.g., using Docker as described in `/code/Dockerfile` and `/code/README.md`).
        - Set the `GRAFANA_URL` environment variable to point to your Grafana instance (e.g., `http://localhost:3000`).
        - **Crucially, set the `GRAFANA_API_KEY` environment variable to a valid Grafana API key or service account token.** For testing purposes, you can create a temporary API key in Grafana with admin privileges to fully demonstrate the impact. **Remember to revoke this key after testing.**
    2. **Attacker Access Simulation:** Assume the attacker has gained access to the running container or server where the `mcp-grafana` application is deployed. For example, if using Docker, the attacker could execute a shell inside the running container:
        ```bash
        docker exec -it <container_name> /bin/bash
        ```
    3. **Retrieve API Key:** Inside the container/server environment, the attacker attempts to read the `GRAFANA_API_KEY` environment variable:
        ```bash
        printenv GRAFANA_API_KEY
        # Or:
        echo $GRAFANA_API_KEY
        ```
        The command will output the value of the `GRAFANA_API_KEY`, which is the Grafana API key used by the MCP server.
    4. **Unauthorized Grafana API Access:** The attacker now uses the retrieved API key to make a direct request to the Grafana API from their own machine (outside the server environment). Using `curl` as an example:
        ```bash
        API_KEY="<retrieved_api_key>"
        GRAFANA_URL="http://localhost:3000" # Or your deployed Grafana URL
        curl -H "Authorization: Bearer ${API_KEY}" "${GRAFANA_URL}/api/datasources"
        ```
        - Replace `<retrieved_api_key>` with the API key obtained in the previous step.
        - Replace `http://localhost:3000` with the actual URL of your Grafana instance if different.
    5. **Verification:**
        - If the API key is valid and the vulnerability is successfully exploited, the `curl` command will return a JSON response containing a list of Grafana datasources. This confirms that the attacker has successfully used the exposed API key to access the Grafana API without proper authorization checks on the MCP server itself.
        - Examine the Grafana server logs (if available) to further confirm that the API request originated from outside the MCP server and was authenticated using the compromised API key.

This test case demonstrates that an attacker who gains access to the server environment can easily retrieve the `GRAFANA_API_KEY` and use it to directly access the Grafana API, bypassing the MCP server application entirely and gaining unauthorized access to Grafana.

### 3. Grafana API Key Exposure through Server Logs

- **Description:**
    - The Grafana MCP server application reads the Grafana API key from the environment variable `GRAFANA_API_KEY` as configured in `src/mcp_grafana/settings.py`.
    - The application initializes logging with `log_level="DEBUG"` in `src/mcp_grafana/__init__.py`.
    - If any part of the application or underlying libraries logs the configuration or HTTP requests in debug mode, the Grafana API key, which is part of the authorization header, could be inadvertently logged.
    - An attacker with access to the server logs could potentially extract the Grafana API key.

- **Impact:**
    - High. If the Grafana API key is exposed, an attacker can gain unauthorized access to the Grafana instance with the privileges associated with the service account linked to the API key. This could lead to data breaches, unauthorized modifications of dashboards and configurations, and potentially further compromise of systems integrated with Grafana.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - None in the provided code. The application uses `log_level="DEBUG"` which increases the risk of logging sensitive information.

- **Missing Mitigations:**
    - **Reduce Logging Level in Production:** The default `log_level` should be set to a less verbose level (e.g., INFO, WARNING, ERROR) in production environments to minimize the risk of logging sensitive data. Debug level logging should only be used during development and debugging.
    - **Sensitive Data Scrubbing in Logs:** Implement mechanisms to scrub or mask sensitive information like API keys from log messages before they are written to logs. This can involve intercepting log messages and applying redaction rules.
    - **Secure Log Storage and Access Control:** Ensure that server logs are stored securely with appropriate access controls to prevent unauthorized access. Regularly review and monitor log access.

- **Preconditions:**
    1. The Grafana MCP server is running with `log_level` set to `DEBUG` or a level that logs HTTP request headers or configuration details.
    2. An attacker gains access to the server logs. This could be through various means depending on the server environment (e.g., compromised logging service, access to server filesystem if logs are stored locally, etc.).

- **Source Code Analysis:**
    1. **`src/mcp_grafana/__init__.py`**:
        ```python
        from mcp.server import FastMCP
        from .tools import add_tools

        # Create an MCP server
        mcp = FastMCP("Grafana", log_level="DEBUG") # Vulnerable line: log_level is set to DEBUG
        add_tools(mcp)
        ```
        This line initializes the MCP server with `log_level="DEBUG"`. This setting is very verbose and might cause sensitive information to be logged.

    2. **`src/mcp_grafana/client.py`**:
        ```python
        class BearerAuth(httpx.Auth):
            def __init__(self, api_key: str):
                self.api_key = api_key

            def auth_flow(self, request):
                request.headers["Authorization"] = f"Bearer {self.api_key}" # API key is added to headers
                yield request

        class GrafanaClient:
            def __init__(self, url: str, api_key: str | None = None) -> None:
                auth = BearerAuth(api_key) if api_key is not None else None
                self.c = httpx.AsyncClient(
                    base_url=url, auth=auth, timeout=httpx.Timeout(timeout=30.0)
                )
        ```
        The `BearerAuth` class correctly adds the API key to the `Authorization` header. However, if HTTP request headers are logged (which is common in DEBUG level logging), this header, including the API key, could be logged.

    3. **`src/mcp_grafana/settings.py`**:
        ```python
        class GrafanaSettings(BaseSettings):
            model_config: SettingsConfigDict = SettingsConfigDict(
                env_prefix="GRAFANA_", env_file=".env", env_nested_delimiter="__"
            )

            url: str = Field(
                default="http://localhost:3000", description="The URL of the Grafana instance."
            )
            api_key: str | None = Field(
                default=None,
                description="A Grafana API key or service account token with the necessary permissions to use the tools.",
            )
        ```
        This code confirms that `api_key` is read from environment variables, which is standard practice, but the risk arises when this key is used in HTTP requests and logging is enabled.

    **Visualization:**

    ```
    [Environment Variable GRAFANA_API_KEY] --> (src/mcp_grafana/settings.py) GrafanaSettings.api_key
                                                    |
                                                    V
    (src/mcp_grafana/client.py) GrafanaClient ----> BearerAuth ----> [HTTP Request Header "Authorization: Bearer <API_KEY>"]
                                                    |
    (src/mcp_grafana/__init__.py) FastMCP (log_level="DEBUG") ----> [Server Logs] (Potential API Key Exposure)
    ```

- **Security Test Case:**
    1. **Setup:**
        - Deploy the Grafana MCP server in a test environment.
        - Configure the server with `log_level="DEBUG"` (either by modifying `src/mcp_grafana/__init__.py` or through environment configuration if possible).
        - Set the `GRAFANA_API_KEY` environment variable to a known API key for a test Grafana instance.
        - Start the Grafana MCP server.
        - Ensure that server logs are being captured and can be accessed for review.
    2. **Trigger Log Generation:**
        - Use a MCP client to send a request to the Grafana MCP server that will trigger an HTTP request to the Grafana API. For example, use the `search_dashboards` tool with any query.
    3. **Analyze Server Logs:**
        - Inspect the server logs for the Grafana MCP server.
        - Search for log entries related to the outgoing HTTP request made by `GrafanaClient`.
        - Check if the `Authorization` header is logged in the request details.
        - Verify if the Grafana API key is present in the logged `Authorization` header.
    4. **Expected Result:**
        - If the logging framework used by `FastMCP` or `httpx` (or any underlying library) logs HTTP request headers in DEBUG mode, you should find log entries containing the `Authorization` header with the Grafana API key visible in the server logs.
    5. **Cleanup:**
        - Stop the Grafana MCP server.
        - Remove or secure the server logs.

This test case will demonstrate that running the server in DEBUG mode can lead to the Grafana API key being logged, confirming the vulnerability.

### 4. Grafana API Key Exposure in Client-Side Configuration

- **Description:**
    - The Grafana MCP server is designed to be used with a Grafana API key.
    - The README.md instructs users to store this Grafana API key directly within the client-side configuration file (e.g., `Claude Desktop` configuration).
    - This client-side configuration file is typically stored on the user's local machine or within the client application's settings.
    - An attacker who gains unauthorized access to the user's machine or the client application's configuration files can retrieve the Grafana API key.
    - With the Grafana API key, the attacker can then directly interact with the Grafana API, bypassing the intended access controls of the MCP server and potentially gaining full control over Grafana resources accessible to the service account associated with the API key.
    - Alternatively, the attacker could use the compromised API key to authenticate with the MCP server itself (if the MCP server has any authentication mechanism, which is not evident in the provided code, but is a theoretical possibility for future extensions), and leverage the server's tools to access Grafana resources in an unintended way.

- **Impact:**
    - **High:** If an attacker obtains the Grafana API key, they can gain unauthorized access to the Grafana instance with the privileges of the service account associated with the key. This could lead to:
        - **Data Breach:** Access to sensitive dashboard data, datasource configurations, and incident information.
        - **Data Manipulation:** Modification or deletion of dashboards, datasources, and incidents.
        - **Operational Disruption:** Disruption of monitoring and incident management workflows by manipulating Grafana resources.
        - **Lateral Movement:** Potential to use compromised Grafana access to pivot to other systems or data accessible via Grafana datasources.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - **None:** The provided code and documentation do not include any mitigations for the risk of API key exposure in client-side configurations. The README explicitly instructs users to store the API key in plaintext in the client configuration.

- **Missing Mitigations:**
    - **Secure Key Storage on Client-Side:** Clients should employ secure methods for storing sensitive credentials like API keys, such as using operating system credential managers, encrypted storage, or secure enclaves.
    - **Principle of Least Privilege for Service Account:** The Grafana service account associated with the API key should be granted only the minimum necessary permissions required for the MCP server to function. This limits the impact if the API key is compromised.
    - **API Key Rotation:** Implement a mechanism for regularly rotating the Grafana API key to limit the window of opportunity for an attacker if a key is compromised.
    - **Warning in Documentation:** At a minimum, the documentation should strongly warn users about the security risks of storing API keys in client-side configuration files and recommend more secure alternatives.

- **Preconditions:**
    1. The user must have configured the Grafana MCP server as instructed in the README, including storing the Grafana API key in the client-side configuration.
    2. An attacker must gain unauthorized access to the user's machine or the client application's configuration files where the API key is stored.

- **Source Code Analysis:**
    1. **`File: /code/README.md`**: The "Usage" section clearly instructs users to:
        ```json
        {
          "mcpServers": {
            "grafana": {
              "command": "uvx",
              "args": [
                "mcp-grafana"
              ],
              "env": {
                "GRAFANA_URL": "http://localhost:3000",
                "GRAFANA_API_KEY": "<your service account token>"
              }
            }
          }
        }
        ```
        This explicitly shows how to embed the `GRAFANA_API_KEY` directly in the client configuration as an environment variable. This configuration is client-side, making it vulnerable to access if the client system is compromised.
    2. **`File: /code/src/mcp_grafana/settings.py`**: The `GrafanaSettings` class loads the `api_key` from the environment variable `GRAFANA_API_KEY`:
        ```python
        class GrafanaSettings(BaseSettings):
            model_config: SettingsConfigDict = SettingsConfigDict(
                env_prefix="GRAFANA_", env_file=".env", env_nested_delimiter="__"
            )

            ...
            api_key: str | None = Field(
                default=None,
                description="A Grafana API key or service account token with the necessary permissions to use the tools.",
            )
        ```
        This confirms that the application is designed to retrieve the API key from environment variables, which, as per the README, are set in the client configuration.
    3. **`File: /code/src/mcp_grafana/client.py`**: The `GrafanaClient` class uses the API key for authentication:
        ```python
        class BearerAuth(httpx.Auth):
            def __init__(self, api_key: str):
                self.api_key = api_key

            def auth_flow(self, request):
                request.headers["Authorization"] = f"Bearer {self.api_key}"
                yield request


        class GrafanaClient:
            def __init__(self, url: str, api_key: str | None = None) -> None:
                auth = BearerAuth(api_key) if api_key is not None else None
                self.c = httpx.AsyncClient(
                    base_url=url, auth=auth, timeout=httpx.Timeout(timeout=30.0)
                )
        ```
        This code shows that the `GrafanaClient` correctly uses the provided `api_key` to set the `Authorization` header with a Bearer token for all requests to the Grafana API.

**Visualization:**

```
[Client Machine] --> [Client Configuration File (GRAFANA_API_KEY)] --> [MCP Client (reads API Key)] --> [MCP Server] --> [Grafana API (authenticated with API Key)]
                                    ^
                                    |
[Attacker Accesses Client Machine/Config]
```

- **Security Test Case:**
    1. **Precondition:** Set up the Grafana MCP server and configure a client (e.g., Claude Desktop) as described in the README, including setting the `GRAFANA_API_KEY` in the client's configuration file.
    2. **Access Client Configuration:** Simulate an attacker gaining access to the client machine or the client application's configuration files. The method to achieve this depends on the client application and OS, but could involve techniques like:
        - **Local File System Access:** If the configuration is stored in a file, access the file directly (e.g., using `cat`, `type`, or file explorer).
        - **Process Memory Dump:** If the client application stores the key in memory, attempt to dump the process memory and search for the API key.
        - **Client Application Vulnerability:** Exploit a vulnerability in the client application to extract configuration data.
    3. **Extract API Key:** Retrieve the plaintext `GRAFANA_API_KEY` from the client configuration.
    4. **Direct Grafana API Access:** Using a tool like `curl` or `Postman`, make a direct API request to the Grafana instance specified by `GRAFANA_URL`, using the extracted `GRAFANA_API_KEY` for authentication. For example:
        ```bash
        curl -H "Authorization: Bearer <extracted_api_key>" "<GRAFANA_URL>/api/datasources"
        ```
    5. **Verify Unauthorized Access:** Check if the direct Grafana API request is successful and returns data (e.g., a list of datasources). If successful, this confirms that the attacker, by obtaining the API key from the client configuration, can bypass the MCP server and directly access Grafana resources.
    6. **Cleanup:** Remove the API key from the client configuration and revoke the API key in Grafana to mitigate the exposed credential.

This test case demonstrates that an attacker gaining access to the client's configuration can extract the Grafana API key and use it for unauthorized access to the Grafana API, confirming the vulnerability.