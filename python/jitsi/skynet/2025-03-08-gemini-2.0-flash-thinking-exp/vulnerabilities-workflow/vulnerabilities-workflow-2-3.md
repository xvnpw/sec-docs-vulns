### Vulnerability List

- Vulnerability Name: Bypass Authorization via `BYPASS_AUTHORIZATION` environment variable
- Description:
    1. The Skynet API server uses JWT-based authentication for API access.
    2. The project provides an environment variable `BYPASS_AUTHORIZATION`.
    3. When `BYPASS_AUTHORIZATION` is set to `true` or `1`, the JWT authentication check is completely bypassed for all API endpoints.
    4. If an administrator mistakenly sets `BYPASS_AUTHORIZATION=true` in a production environment, or if it is unintentionally left enabled from development/testing, any attacker can access all API endpoints without any authentication.
    5. This allows unauthorized users to utilize all AI services (summarization, live transcription, RAG assistant) and potentially access or manipulate data processed by Skynet.
- Impact:
    - Critical.
    - Complete bypass of authentication allows unauthorized access to all Skynet API functionalities.
    - Attackers can use AI services for free, potentially incurring costs for the service provider.
    - Sensitive data processed by AI services could be exposed to unauthorized parties.
    - Potential for malicious use of AI services leading to reputational damage or further attacks.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - The documentation clearly mentions that `BYPASS_AUTHORIZATION` disables authorization and should not be used in production (e.g., `/code/docs/auth.md`, `/code/docs/summaries_module.md`, `/code/docs/assistant.md`).
    - The default value for `BYPASS_AUTHORIZATION` is `false` in `/code/docs/env_vars.md` and implicitly in `/code/skynet/env.py`.
- Missing Mitigations:
    - **Stronger warnings/validation:**  The application could log a very prominent warning message at startup if `BYPASS_AUTHORIZATION` is enabled, emphasizing that it's insecure for production.
    - **Removal of feature in production builds:** Consider removing or significantly restricting the functionality of `BYPASS_AUTHORIZATION` in production builds to prevent accidental enabling. Alternatively, rename the variable to something extremely explicit like `DANGEROUSLY_DISABLE_AUTHORIZATION_FOR_DEBUGGING_ONLY` to deter production use.
    - **Infrastructure level enforcement:**  Deployment scripts or infrastructure configurations should explicitly ensure this variable is not set in production environments, possibly through configuration management tools or CI/CD pipelines.
- Preconditions:
    - `BYPASS_AUTHORIZATION` environment variable is set to `true` or `1` when running the Skynet API server.
- Source Code Analysis:
    1. File: `/code/skynet/env.py`
    ```python
    bypass_auth = tobool(os.environ.get('BYPASS_AUTHORIZATION'))
    ```
    - The `bypass_auth` variable is directly controlled by the `BYPASS_AUTHORIZATION` environment variable.
    2. File: `/code/skynet/utils.py`
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
    - The `dependencies` for API routes are conditionally set based on `bypass_auth`. If `bypass_auth` is true, no authentication dependency (`JWTBearer`) is added, effectively disabling authentication for all routes using `get_router()`.
    3. File: `/code/skynet/auth/bearer.py`
    ```python
    class JWTBearer(HTTPBearer):
        # ...
        async def __call__(self, request: Request):
            if request.headers.get('X-Skynet-UUID') == app_uuid:
                return None

            credentials: HTTPAuthorizationCredentials = await super().__call__(request)

            request.state.decoded_jwt = await authorize(credentials.credentials)

            return credentials.credentials
    ```
    - `JWTBearer` is the class responsible for JWT authentication. It is bypassed when `bypass_auth` is true in `utils.py`.

- Security Test Case:
    1. **Precondition:** Deploy Skynet with `BYPASS_AUTHORIZATION=true`.
    2. **Action:** Send a request to any Skynet API endpoint (e.g., `/summaries/v1/summary`) without any `Authorization` header.
    3. **Expected Result:** The request is successfully processed by the API endpoint, and a response is returned, indicating successful access without authentication. For example, for the summary endpoint, provide a text payload and expect a summary to be generated and returned.
    4. **Verification:** Observe the server logs - there should be no authentication-related logs or errors, confirming that the authentication check was bypassed.

- Vulnerability Name: JWT Authorization Misconfiguration
- Description:
    1. Skynet uses JWT (JSON Web Tokens) for API authorization.
    2. The JWT verification process relies on fetching public keys from a remote URL (`ASAP_PUB_KEYS_REPO_URL`) based on the `kid` (Key ID) in the JWT header.
    3. Several environment variables configure this process, including `ASAP_PUB_KEYS_REPO_URL`, `ASAP_PUB_KEYS_FOLDER`, `ASAP_PUB_KEYS_AUDS`, `ASAP_PUB_KEYS_MAX_CACHE_SIZE`.
    4. Misconfiguration in any of these variables can lead to authentication bypass or denial of service:
        - **Incorrect `ASAP_PUB_KEYS_REPO_URL` or `ASAP_PUB_KEYS_FOLDER`:** If the URL or folder path is wrong, the server will fail to fetch public keys. If fallback folder is configured incorrectly as well, authentication will fail for all valid JWTs, causing denial of service. If attacker can control this URL (e.g., via environment variable injection in some misconfigured deployments), they can provide their own public key and bypass authentication.
        - **Incorrect `ASAP_PUB_KEYS_AUDS`:** If the allowed audiences are not correctly configured, valid JWTs with legitimate audiences might be rejected, causing denial of service for authorized users. Conversely, overly permissive audience configurations could allow JWTs intended for other services to be accepted by Skynet, leading to unauthorized access.
    5.  Furthermore, if the public key infrastructure is compromised (e.g., attacker gains access to the web server hosting public keys), attackers can replace legitimate public keys with their own, allowing them to forge valid JWTs and completely bypass authentication.
- Impact:
    - Medium to High (depending on the misconfiguration).
    - **Authentication Bypass:** If `ASAP_PUB_KEYS_REPO_URL` is attacker-controlled or if public key infrastructure is compromised, attackers can forge JWTs and gain unauthorized access.
    - **Denial of Service:** Incorrect `ASAP_PUB_KEYS_REPO_URL`, `ASAP_PUB_KEYS_FOLDER`, or `ASAP_PUB_KEYS_AUDS` can cause the server to reject all valid JWTs, resulting in denial of service for legitimate users.
    - **Data Exposure and Unauthorized Usage:** Successful bypass allows attackers to utilize AI services and potentially access/manipulate data.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - JWT verification logic in `/code/skynet/auth/jwt.py` verifies signature and audience.
    - Public key caching (`alru_cache`) in `/code/skynet/auth/jwt.py` to reduce public key fetching frequency.
- Missing Mitigations:
    - **Input Validation for Configuration Variables:** Validate the format and validity of `ASAP_PUB_KEYS_REPO_URL` (e.g., ensure it's a valid URL) and `ASAP_PUB_KEYS_FOLDER` (e.g., ensure it's a valid path format) at startup.
    - **Error Handling and Fallback for Public Key Retrieval:** Improve error handling for public key retrieval failures. While a fallback folder (`ASAP_PUB_KEYS_FALLBACK_FOLDER`) is present, ensure robust error logging and alerting if public key retrieval consistently fails from both primary and fallback locations.
    - **Public Key Infrastructure Security Guidance:** Provide clear documentation and best practices for securing the public key infrastructure, including secure storage, access control, and monitoring of the public key server. Emphasize the importance of HTTPS for `ASAP_PUB_KEYS_REPO_URL` to prevent man-in-the-middle attacks during key retrieval.
    - **Key Rotation Strategy Documentation:** Document a recommended key rotation strategy and mechanisms to ensure keys are rotated periodically and securely.
- Preconditions:
    - Skynet is deployed with JWT authentication enabled (default).
    - Misconfiguration of `ASAP_PUB_KEYS_REPO_URL`, `ASAP_PUB_KEYS_FOLDER`, or `ASAP_PUB_KEYS_AUDS` environment variables, or compromise of the public key infrastructure.
- Source Code Analysis:
    1. File: `/code/skynet/auth/jwt.py`
    ```python
    @alru_cache(maxsize=asap_pub_keys_max_cache_size)
    async def get_public_key(kid: str) -> str:
        encoded_pub_key_name = sha256(kid.encode('UTF-8')).hexdigest()
        pub_key_remote_filename = f'{encoded_pub_key_name}.pem'

        url = f'{asap_pub_keys_url}/{asap_pub_keys_folder}/{pub_key_remote_filename}'

        response = await http_client.request('GET', url)

        if response.status != 200:
            error = f'Failed to retrieve public key {kid}'

            if asap_pub_keys_fallback_folder:
                url = f'{asap_pub_keys_url}/{asap_pub_keys_fallback_folder}/{pub_key_remote_filename}'
                response = await http_client.request('GET', url)

                if response.status != 200:
                    raise Exception(error)
            else:
                raise Exception(error)
        return await response.text()


    async def authorize(jwt_incoming: str) -> dict:
        # ...
        try:
            public_key = await get_public_key(kid)
        except Exception as ex:
            raise HTTPException(status_code=401, detail=str(ex))

        try:
            decoded = jwt.decode(jwt_incoming, public_key, algorithms=['RS256', 'HS512'], audience=asap_pub_keys_auds)
            # ...
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Expired token.")
        except Exception:
            raise HTTPException(status_code=401, detail=f'Failed decoding JWT with public key {kid}')
    ```
    - The `get_public_key` function fetches public keys from the configured URL and folder. Failure to fetch (due to incorrect URL/folder) will cause authentication to fail.
    - The `authorize` function uses `get_public_key` and `jwt.decode` to verify the JWT signature and audience. Incorrect `asap_pub_keys_auds` will lead to rejection of valid tokens.

- Security Test Case:
    1. **Precondition:** Deploy Skynet with JWT authentication enabled and a valid JWT setup.
    2. **Action 1 (Incorrect `ASAP_PUB_KEYS_REPO_URL`):** Modify the `ASAP_PUB_KEYS_REPO_URL` environment variable to an invalid or unreachable URL. Send a valid JWT with a request to any API endpoint.
    3. **Expected Result 1:** The request should be rejected with a 401 Unauthorized error, and the server logs should indicate failure to fetch the public key.
    4. **Verification 1:** Check server logs for errors related to public key retrieval.
    5. **Action 2 (Incorrect `ASAP_PUB_KEYS_AUDS`):** Modify the `ASAP_PUB_KEYS_AUDS` environment variable to an audience that does not match the audience in the valid JWT being used. Send the same valid JWT with a request to any API endpoint.
    6. **Expected Result 2:** The request should be rejected with a 401 Unauthorized error, and the server logs should indicate an audience mismatch during JWT verification.
    7. **Verification 2:** Check server logs for errors related to JWT audience verification.
    8. **Action 3 (Compromised Public Key - Theoretical):**  *(This test is for demonstration and should be performed in a controlled, non-production environment)* Replace the legitimate public key on the public key server with a public key from an attacker-controlled key pair. Forge a JWT using the corresponding attacker's private key, ensuring the `kid` matches the replaced public key's ID. Send this forged JWT with a request to any API endpoint.
    9. **Expected Result 3:** The request should be accepted, demonstrating successful authentication bypass due to compromised public key infrastructure. *(Note: this is a highly sensitive test and should be performed with extreme caution)*
    10. **Verification 3:** Observe server logs indicating successful JWT verification, despite the JWT being forged.

- Vulnerability Name: Insecure JWT Transmission via GET Parameter in Streaming Whisper Module
- Description:
    1. The Streaming Whisper module (`/streaming-whisper`) allows clients to connect via WebSockets.
    2. For authenticated access to the WebSocket endpoint, the documentation (`/code/docs/streaming_whisper_module.md`) specifies that the JWT `auth_token` can be passed as a GET parameter in the WebSocket connection string: `wss|ws://{DOMAIN}:8000/streaming-whisper/ws/{UNIQUE_MEETING_ID}?auth_token={short-lived JWT}`.
    3. Passing sensitive authentication tokens like JWTs in GET parameters is inherently insecure.
    4. **Exposure in Logs and History:** GET parameters are often logged in web server access logs, proxy logs, browser history, and potentially network monitoring tools. This exposes the JWT to unintended parties.
    5. **Referer Header Leakage:** The JWT in the GET parameter can also be leaked through the `Referer` header when the browser or client makes subsequent requests to other resources.
    6. **Increased Risk of Man-in-the-Middle Attacks:** While HTTPS encrypts the connection, the JWT in the URL is still visible to anyone with access to the network traffic at the endpoints (e.g., network administrators, compromised network devices).
    7. **Long-Lived JWTs Amplification:** The documentation advises making JWTs short-lived, but if administrators fail to do so and use longer-lived JWTs in GET parameters, the impact of exposure is significantly amplified, as the compromised JWT remains valid for a longer period.
- Impact:
    - Medium.
    - **Token Exposure:** JWTs passed in GET parameters are at risk of being exposed through various logging mechanisms, browser history, and network monitoring.
    - **Unauthorized Access (if JWT is compromised):** If a JWT is compromised due to GET parameter exposure, attackers can reuse it to gain unauthorized access to the Streaming Whisper service and potentially other Skynet API endpoints (depending on JWT scope and configuration).
- Vulnerability Rank: Medium
- Currently Implemented Mitigations:
    - The documentation in `/code/docs/streaming_whisper_module.md` recommends making the JWT "very short-lived" when using the GET parameter method.
- Missing Mitigations:
    - **Enforce JWT Transmission via Headers/Cookies:**  Completely remove or strongly discourage the use of JWTs in GET parameters for the Streaming Whisper WebSocket connection. Enforce JWT transmission only via the `Authorization` header or secure cookies, which are designed for transmitting sensitive tokens.
    - **Warning in Logs for GET Parameter JWT Usage:** If GET parameter JWT transmission is still supported for backward compatibility or specific use cases, log a prominent warning message whenever a WebSocket connection is established using a JWT in the GET parameter, strongly advising against this practice and recommending header-based authentication.
    - **Security Best Practices Documentation:** Update the documentation to explicitly highlight the security risks of using JWTs in GET parameters and strongly recommend header-based authentication as the preferred and secure method for the Streaming Whisper module. Provide clear instructions and code examples for header-based JWT authentication for WebSocket connections.
- Preconditions:
    - Skynet is deployed with JWT authentication enabled for the Streaming Whisper module.
    - Clients are configured to pass JWTs as GET parameters in the WebSocket connection string for the Streaming Whisper service.
- Source Code Analysis:
    1. File: `/code/docs/streaming_whisper_module.md`
    ```markdown
    wss|ws://{DOMAIN}:8000/streaming-whisper/ws/{UNIQUE_MEETING_ID}?auth_token={short-lived JWT}
    ```
    - Documentation explicitly shows JWT being passed as a GET parameter `auth_token`.
    2. File: `/code/skynet/modules/stt/streaming_whisper/app.py`
    ```python
    @app.websocket('/ws/{meeting_id}')
    async def websocket_endpoint(websocket: WebSocket, meeting_id: str, auth_token: str | None = None):
        await ws_connection_manager.connect(websocket, meeting_id, auth_token)
        # ...
    ```
    - The `websocket_endpoint` function in `app.py` accepts `auth_token` as an optional query parameter, confirming that JWT can be passed via GET.
    3. File: `/code/skynet/modules/stt/streaming_whisper/connection_manager.py`
    ```python
    class ConnectionManager:
        # ...
        async def connect(self, websocket: WebSocket, meeting_id: str, auth_token: str | None):
            if not bypass_auth:
                jwt_token = utils.get_jwt(websocket.headers, auth_token)
                authorized = await authorize(jwt_token)
                if not authorized:
                    await websocket.close(401, 'Bad JWT token')
                    return
            await websocket.accept()
            # ...
    ```
    - The `connect` function in `connection_manager.py` retrieves the JWT using `utils.get_jwt`, which checks both headers and the `auth_token` parameter.

- Security Test Case:
    1. **Precondition:** Deploy Skynet with JWT authentication enabled for Streaming Whisper.
    2. **Action:** Initiate a WebSocket connection to the Streaming Whisper endpoint, passing a valid JWT as a GET parameter `auth_token` in the connection string: `wss://<skynet-host>/streaming-whisper/ws/<meeting_id>?auth_token=<your_jwt>`.
    3. **Expected Result:** The WebSocket connection is successfully established, and the streaming transcription service is accessible.
    4. **Verification:**
        - **Server Access Logs:** Check the web server access logs for the Skynet instance. The logs should contain the WebSocket connection request, including the JWT in the GET parameter within the URL.
        - **Browser History (if testing from a browser):** Examine the browser history. The WebSocket connection URL, including the JWT in the GET parameter, will be recorded in the history.
        - **Network Monitoring (using tools like Wireshark or browser developer tools):** Capture network traffic during the WebSocket handshake. The initial HTTP GET request for WebSocket upgrade will reveal the JWT in the URL if the traffic is not HTTPS, or visible to someone with access to the network if HTTPS is used at the endpoints.