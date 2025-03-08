## Vulnerability List

### 1. Insecure Authentication via Client-Side API Key

*   **Description:**
    The Edge Proxy uses a client-side API key (`client_side_key`) for authentication in its API endpoints (`/api/v1/flags/`, `/api/v1/identities/`). This key is intended for client-side applications and is less sensitive than the server-side key. However, the Edge Proxy configuration (`config.json`) requires both `server_side_key` and `client_side_key` to be configured together in `environment_key_pairs`. The proxy then uses the `client_side_key` to authenticate incoming requests.  An attacker who obtains a valid `client_side_key` can bypass intended feature controls by directly querying the Edge Proxy API and manipulating feature flag configurations as evaluated by the proxy.

    **Steps to trigger:**
    1.  Obtain a valid `client_side_key` from a legitimate source (e.g., exposed in client-side application code or configuration, or through insider access).
    2.  Send a request to the `/api/v1/flags/` or `/api/v1/identities/` endpoint of the Edge Proxy, including the obtained `client_side_key` in the `X-Environment-Key` header.
    3.  The Edge Proxy will authenticate the request using the `client_side_key` and return feature flag configurations.
    4.  By crafting requests with different parameters (e.g., different identity identifiers or traits), the attacker can explore and potentially manipulate the feature flag evaluations for various scenarios.

*   **Impact:**
    *   **High:** An attacker with a `client_side_key` can retrieve and potentially manipulate feature flag configurations as evaluated by the Edge Proxy. This could lead to bypassing intended feature controls, accessing features not meant for them, or disrupting the intended application behavior. While the client-side key is intended to be less privileged than a server-side key, its use for authentication in the proxy still grants significant access to feature flag logic.

*   **Vulnerability Rank:** High

*   **Currently Implemented Mitigations:**
    *   None in the Edge Proxy itself. The project relies on the intended security model of Flagsmith, where client-side keys are considered less sensitive but still provide access to feature flags.

*   **Missing Mitigations:**
    *   **API Key Scope Limitation:** The Edge Proxy should ideally authenticate requests using a more restricted key or mechanism, separate from the client-side keys intended for broader distribution. It should not directly expose endpoints authenticated by the client-side key.
    *   **Rate Limiting and Monitoring:** Implement rate limiting on API endpoints to mitigate brute-force key guessing or excessive querying. Monitoring access logs for suspicious activity related to API key usage would also be beneficial.
    *   **Consider Server-Side Key Authentication:**  For more secure authentication of requests to the Edge Proxy, especially for sensitive operations (if any were to be added in the future), consider using server-side keys or a more robust authentication method.

*   **Preconditions:**
    *   The attacker must obtain a valid `client_side_key`. This key might be exposed in client-side applications or configurations, or accessible through insider threats.
    *   The Edge Proxy must be configured with the `environment_key_pairs` including the `client_side_key` associated with the obtained key.

*   **Source Code Analysis:**
    1.  **`src/main.py`:** The `flags` and `identity` endpoints are defined, both using `x_environment_key: str = Header(None)` for authentication.
    2.  **`src/environments.py`:** The `EnvironmentService.get_flags_response_data` and `EnvironmentService.get_identity_response_data` methods are called, which in turn use `self.get_environment(environment_key)` to retrieve the environment configuration based on the provided key.
    3.  **`src/environments.py`:** `EnvironmentService.get_environment` retrieves the environment document from the cache using the provided `client_side_key`. If not found, it raises `FlagsmithUnknownKeyError`.
    4.  **`src/cache.py`:** `LocalMemEnvironmentsCache` stores environment documents in a dictionary keyed by the environment API key, which in this case is the `client_side_key`.
    5.  **`src/settings.py`:** The `Settings` model defines `environment_key_pairs` as a list of `EnvironmentKeyPair` objects, each containing both `server_side_key` and `client_side_key`. The configuration loading logic reads these key pairs from `config.json`.

    **Code Snippet from `src/main.py` (Authentication in API Endpoints):**
    ```python
    @app.get("/api/v1/flags/", response_class=ORJSONResponse)
    async def flags(feature: str = None, x_environment_key: str = Header(None)):
        try:
            data = environment_service.get_flags_response_data(x_environment_key, feature)
        except FeatureNotFoundError:
            return ORJSONResponse( ... )
        return ORJSONResponse(data)

    @app.post("/api/v1/identities/", response_class=ORJSONResponse)
    async def identity(
        input_data: IdentityWithTraits,
        x_environment_key: str = Header(None),
    ):
        data = environment_service.get_identity_response_data(input_data, x_environment_key)
        return ORJSONResponse(data)
    ```
    The code directly uses the `x_environment_key` header, which is expected to be the `client_side_key` as configured, to authenticate requests to these API endpoints.

*   **Security Test Case:**
    1.  **Setup:** Deploy the Edge Proxy instance with a `config.json` that includes at least one `environment_key_pair` with a known `client_side_key` (e.g., 'test_client_key').
    2.  **Action:** Using a tool like `curl` or `Postman`, send a GET request to the `/api/v1/flags/` endpoint of the deployed Edge Proxy instance. Include the known `client_side_key` in the `X-Environment-Key` header. For example:

        ```bash
        curl -H "X-Environment-Key: test_client_key" http://<edge-proxy-host>:<port>/api/v1/flags/
        ```
    3.  **Expected Result:** The request should return a successful HTTP 200 response with a JSON payload containing the feature flag configurations for the environment associated with `test_client_key`. This confirms that the `client_side_key` is accepted as a valid authentication token for accessing the API.
    4.  **Verification:** Examine the response body to ensure it contains valid feature flag data, indicating successful retrieval of environment configurations using the `client_side_key` for authentication.