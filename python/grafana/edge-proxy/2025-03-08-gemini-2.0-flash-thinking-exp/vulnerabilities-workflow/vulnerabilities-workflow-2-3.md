- Vulnerability name: Insecure HTTP Communication with Flagsmith API

- Description:
  1. The Flagsmith Edge Proxy is configured via a `config.json` file or environment variables, which includes the `api_url` setting. This setting defines the URL of the Flagsmith API server to connect to.
  2. The `api_url` setting, while defaulting to `https://edge.api.flagsmith.com/api/v1`, can be modified by the user to use `http://` instead of `https://`.
  3. If a user configures the `api_url` to use `http://`, the communication between the Edge Proxy and the Flagsmith API will occur over unencrypted HTTP.
  4. A man-in-the-middle attacker on the network path between the Edge Proxy and the Flagsmith API server can intercept this unencrypted traffic.
  5. The attacker can then modify the API responses from the Flagsmith API server before they reach the Edge Proxy.
  6. By modifying these responses, the attacker can manipulate feature flag evaluations within the Edge Proxy.
  7. This manipulation can lead to the Edge Proxy providing incorrect feature flag evaluations to client applications.

- Impact:
  An attacker can successfully manipulate feature flag evaluations by intercepting and modifying unencrypted HTTP traffic. This can result in:
    - Unauthorized access to features that should be disabled.
    - Disabling features that should be enabled.
    - Altering the behavior of the application based on manipulated flag values.
    - Potential data breaches or other security compromises, depending on how feature flags are used to control application logic and access.

- Vulnerability rank: High

- Currently implemented mitigations:
  - None. The application does not enforce HTTPS for communication with the Flagsmith API.
  - The default value for `api_url` in the settings is `https://edge.api.flagsmith.com/api/v1`, which encourages secure configuration by default.

- Missing mitigations:
  - Enforce HTTPS for the `api_url` setting. This could be done by:
    - Validating the scheme of the `api_url` in the configuration and rejecting HTTP URLs.
    - Providing a separate boolean setting to enforce HTTPS and validating the `api_url` scheme based on this setting.
  - Improve documentation to strongly recommend the use of HTTPS for `api_url` and highlight the security risks of using HTTP.

- Preconditions:
  - The user must misconfigure the Edge Proxy by setting the `api_url` in `config.json` or via the `CONFIG_PATH` environment variable to start with `http://` instead of `https://`.
  - A man-in-the-middle attacker must be positioned on the network path between the Edge Proxy instance and the Flagsmith API server to intercept network traffic.

- Source code analysis:
  - File: `/code/src/settings.py`
    ```python
    from pydantic import BaseModel, BaseSettings, HttpUrl

    class Settings(BaseSettings):
        environment_key_pairs: List[EnvironmentKeyPair]
        api_url: HttpUrl = "https://edge.api.flagsmith.com/api/v1"
        # ...
    ```
    - The `api_url` is defined as `HttpUrl` from pydantic. While `HttpUrl` ensures a valid URL format, it does not enforce the HTTPS scheme. It defaults to `https`, but allows `http` as well.
  - File: `/code/src/environments.py`
    ```python
    import httpx

    class EnvironmentService:
        def __init__(
            self,
            cache: BaseEnvironmentsCache = None,
            client: httpx.AsyncClient = None,
            settings: Settings = None,
        ):
            # ...
            self._client = client or httpx.AsyncClient(timeout=settings.api_poll_timeout)

        async def _fetch_document(self, server_side_key: str) -> dict[str, typing.Any]:
            response = await self._client.get(
                url=f"{self.settings.api_url}/environment-document/",
                headers={"X-Environment-Key": server_side_key},
            )
            # ...
    ```
    - The `EnvironmentService` uses `httpx.AsyncClient` to make requests to the Flagsmith API.
    - The `_fetch_document` method constructs the URL using `self.settings.api_url` directly and passes it to `self._client.get()`.
    - If `self.settings.api_url` is configured to use `http://`, `httpx` will use HTTP for the request, resulting in unencrypted communication. There is no explicit check or enforcement of HTTPS in the code.

- Security test case:
  1. **Setup MITM Proxy:** Install and configure a man-in-the-middle proxy tool like `mitmproxy`.
  2. **Configure Edge Proxy for HTTP:** Modify the `config.json` file used by the Edge Proxy and set the `api_url` to use `http`:
     ```json
     {
       "environment_key_pairs": [{"server_side_key": "YOUR_SERVER_SIDE_KEY", "client_side_key": "YOUR_CLIENT_SIDE_KEY"}],
       "api_url": "http://edge.api.flagsmith.com/api/v1"
     }
     ```
  3. **Run Edge Proxy with MITM Proxy:** Start the Edge Proxy, ensuring that network traffic from the Edge Proxy is routed through the MITM proxy. This might involve setting proxy environment variables for the Docker container or the host system where the Edge Proxy is running.
  4. **Send Request to Edge Proxy:** Use a client (like `curl` or a browser) to send a request to the Edge Proxy to fetch feature flags. For example:
     ```bash
     curl -H "X-Environment-Key: YOUR_CLIENT_SIDE_KEY" http://localhost:8000/api/v1/flags
     ```
  5. **Intercept and Modify Response with MITM Proxy:** In the MITM proxy interface, intercept the HTTP request made by the Edge Proxy to `edge.api.flagsmith.com/api/v1/environment-document/`.
  6. **Modify Feature Flag Data:** In the intercepted response from `edge.api.flagsmith.com`, modify the JSON payload to alter a feature flag value. For instance, change the `feature_state_value` of a specific feature or enable/disable a feature.
  7. **Forward Modified Response:** Allow the MITM proxy to forward the modified response to the Edge Proxy.
  8. **Verify Modified Flags from Edge Proxy:** Check the response from the Edge Proxy (from step 4). The feature flags returned by the Edge Proxy should now reflect the modifications made in the MITM proxy, demonstrating successful manipulation of feature flag evaluations due to insecure HTTP communication.