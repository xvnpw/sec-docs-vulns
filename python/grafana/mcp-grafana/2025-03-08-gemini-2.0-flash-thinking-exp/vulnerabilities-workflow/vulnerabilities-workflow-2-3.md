- Vulnerability Name: **Grafana API Key Exposure through Server Logs**
- Description:
    1. The Grafana MCP server application reads the Grafana API key from the environment variable `GRAFANA_API_KEY` as configured in `src/mcp_grafana/settings.py`.
    2. The application initializes logging with `log_level="DEBUG"` in `src/mcp_grafana/__init__.py`.
    3. If any part of the application or underlying libraries logs the configuration or HTTP requests in debug mode, the Grafana API key, which is part of the authorization header, could be inadvertently logged.
    4. An attacker with access to the server logs could potentially extract the Grafana API key.
- Impact:
    - High. If the Grafana API key is exposed, an attacker can gain unauthorized access to the Grafana instance with the privileges associated with the service account linked to the API key. This could lead to data breaches, unauthorized modifications of dashboards and configurations, and potentially further compromise of systems integrated with Grafana.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None in the provided code. The application uses `log_level="DEBUG"` which increases the risk of logging sensitive information.
- Missing Mitigations:
    - **Reduce Logging Level in Production:** The default `log_level` should be set to a less verbose level (e.g., INFO, WARNING, ERROR) in production environments to minimize the risk of logging sensitive data. Debug level logging should only be used during development and debugging.
    - **Sensitive Data Scrubbing in Logs:** Implement mechanisms to scrub or mask sensitive information like API keys from log messages before they are written to logs. This can involve intercepting log messages and applying redaction rules.
    - **Secure Log Storage and Access Control:** Ensure that server logs are stored securely with appropriate access controls to prevent unauthorized access. Regularly review and monitor log access.
- Preconditions:
    1. The Grafana MCP server is running with `log_level` set to `DEBUG` or a level that logs HTTP request headers or configuration details.
    2. An attacker gains access to the server logs. This could be through various means depending on the server environment (e.g., compromised logging service, access to server filesystem if logs are stored locally, etc.).
- Source Code Analysis:
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

- Security Test Case:
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