- **Vulnerability Name:** Grafana API Key Exposure in Client-Side Configuration

- **Description:**
    1. The Grafana MCP server is designed to be used with a Grafana API key.
    2. The README.md instructs users to store this Grafana API key directly within the client-side configuration file (e.g., `Claude Desktop` configuration).
    3. This client-side configuration file is typically stored on the user's local machine or within the client application's settings.
    4. An attacker who gains unauthorized access to the user's machine or the client application's configuration files can retrieve the Grafana API key.
    5. With the Grafana API key, the attacker can then directly interact with the Grafana API, bypassing the intended access controls of the MCP server and potentially gaining full control over Grafana resources accessible to the service account associated with the API key.
    6. Alternatively, the attacker could use the compromised API key to authenticate with the MCP server itself (if the MCP server has any authentication mechanism, which is not evident in the provided code, but is a theoretical possibility for future extensions), and leverage the server's tools to access Grafana resources in an unintended way.

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