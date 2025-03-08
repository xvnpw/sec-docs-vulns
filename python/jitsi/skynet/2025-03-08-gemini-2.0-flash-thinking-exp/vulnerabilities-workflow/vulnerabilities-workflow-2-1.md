- Vulnerability Name: Authorization Bypass via `BYPASS_AUTHORIZATION` Environment Variable
- Description:
    - An authorization bypass vulnerability exists due to the use of the `BYPASS_AUTHORIZATION` environment variable.
    - Developers can set this variable to `true` or `1` to disable JWT-based authentication for all API endpoints.
    - If `BYPASS_AUTHORIZATION` is enabled in a production environment, the application will not enforce any authorization checks.
    - This allows any unauthenticated user to access and utilize all API functionalities, including summarization, live transcriptions, and RAG assistant.
    - An attacker can directly send requests to any API endpoint without needing a valid JWT token.
- Impact:
    - **Unauthorized Access:** Complete bypass of the intended authorization mechanism, granting unrestricted access to all API endpoints.
    - **Data Breach:** Potential exposure of sensitive data processed by AI services (summaries, transcriptions, RAG data) to unauthorized individuals.
    - **Resource Misuse:** Attackers could abuse AI services, leading to increased operational costs and potential denial of service for legitimate users due to resource exhaustion.
    - **Unauthorized Actions:** Ability for attackers to perform actions through the API, such as creating or deleting RAG databases or initiating AI processing tasks, without proper authorization.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - **Documentation:** The `README.md`, `docs/summaries_module.md`, and `docs/streaming_whisper_module.md` mention the `BYPASS_AUTHORIZATION` variable as a way to disable authorization for development and quickstart purposes, implying it's not intended for production use. However, this is just documentation and doesn't prevent misuse in production.
- Missing Mitigations:
    - **Remove or Deprecate `BYPASS_AUTHORIZATION` for Production:**  The most effective mitigation is to remove this functionality entirely from production builds or strongly discourage its use and provide prominent warnings about the security risks.
    - **Production Environment Check:** Implement a startup check that verifies if `BYPASS_AUTHORIZATION` is enabled. If it is enabled in a non-development environment (e.g., based on environment variables like `ENVIRONMENT=production`), the application should refuse to start and log a critical error.
    - **Security Hardening Documentation:**  Clearly document in `docs/auth.md` and `docs/env_vars.md` the severe security implications of enabling `BYPASS_AUTHORIZATION` in production, emphasizing that it should ONLY be used for local development and testing.
- Preconditions:
    - The Skynet application is deployed in a production environment.
    - The `BYPASS_AUTHORIZATION` environment variable is set to `true` or `1` during deployment or runtime configuration.
- Source Code Analysis:
    - File: `/code/skynet/env.py`
        ```python
        bypass_auth = tobool(os.environ.get('BYPASS_AUTHORIZATION'))
        ```
        - The `BYPASS_AUTHORIZATION` environment variable is read and converted to a boolean value, stored in the `bypass_auth` variable.
    - File: `/code/skynet/utils.py`
        ```python
        dependencies = [] if bypass_auth else [Depends(JWTBearer())]
        responses = (
            {}
            if bypass_auth
            else {401: {"description": "Invalid or expired token"}, 403: {"description": "Not enough permissions"}}
        )

        def get_router() -> APIRouter:
            return APIRouter(dependencies=dependencies, responses=responses)
        ```
        - The `bypass_auth` variable directly controls whether the `JWTBearer()` dependency is included in the API routers created by `get_router()`.
        - When `bypass_auth` is `true`, the `dependencies` list is empty, meaning no authentication middleware (`JWTBearer`) is applied to routes using this router.
        - Consequently, any endpoint defined using `get_router()` will be publicly accessible without JWT authentication if `BYPASS_AUTHORIZATION` is enabled.
- Security Test Case:
    1. **Environment Setup:** Deploy a Skynet instance, ensuring that the `BYPASS_AUTHORIZATION` environment variable is set to `true` or `1`.
    2. **Access API without JWT:** Use a tool like `curl` or a browser to send a request to a protected API endpoint, such as the summary creation endpoint: `http://<skynet-instance-address>:8000/summaries/v1/summary`. Do **not** include any `Authorization` header in the request.
    3. **Request Body:** Include a valid JSON request body for the endpoint, for example:
        ```json
        {
          "text": "This is a test text for summarization.",
          "hint": "text"
        }
        ```
    4. **Verify Unauthorized Access:** Observe the HTTP response.
        - **Vulnerable Result:** If the vulnerability exists, the server will respond with a `200 OK` status code and the summarized text in the response body. This indicates successful processing of the request without any authorization check.
        - **Expected Secure Result:** If the authorization is correctly enforced (which is not the case when `BYPASS_AUTHORIZATION=true`), the server should respond with a `401 Unauthorized` or `403 Forbidden` status code, indicating that authentication is required.
    5. **Test other endpoints:** Repeat steps 2-4 for other API endpoints, such as RAG assistant endpoints (`/assistant/v1/rag`, `/assistant/v1/assist`) and streaming whisper websocket endpoint (`ws://<skynet-instance-address>:8000/streaming-whisper/ws/{meeting_id}`). Verify that all endpoints are accessible without authorization.