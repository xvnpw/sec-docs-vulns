## Combined Vulnerability List

### Vulnerability Name: Authorization Bypass via `BYPASS_AUTHORIZATION` Environment Variable

- **Description:**
    - An authorization bypass vulnerability exists due to the use of the `BYPASS_AUTHORIZATION` environment variable.
    - Developers can set this variable to `true` or `1` to disable JWT-based authentication for all API endpoints.
    - If `BYPASS_AUTHORIZATION` is enabled in a production environment, the application will not enforce any authorization checks.
    - This allows any unauthenticated user to access and utilize all API functionalities, including summarization, live transcriptions, and RAG assistant.
    - An attacker can directly send requests to any API endpoint without needing a valid JWT token.

- **Impact:**
    - **Unauthorized Access:** Complete bypass of the intended authorization mechanism, granting unrestricted access to all API endpoints.
    - **Data Breach:** Potential exposure of sensitive data processed by AI services (summaries, transcriptions, RAG data) to unauthorized individuals.
    - **Resource Misuse:** Attackers could abuse AI services, leading to increased operational costs and potential denial of service for legitimate users due to resource exhaustion.
    - **Unauthorized Actions:** Ability for attackers to perform actions through the API, such as creating or deleting RAG databases or initiating AI processing tasks, without proper authorization.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - **Documentation:** The `README.md`, `docs/summaries_module.md`, and `docs/streaming_whisper_module.md` mention the `BYPASS_AUTHORIZATION` variable as a way to disable authorization for development and quickstart purposes, implying it's not intended for production use. However, this is just documentation and doesn't prevent misuse in production.

- **Missing Mitigations:**
    - **Remove or Deprecate `BYPASS_AUTHORIZATION` for Production:**  The most effective mitigation is to remove this functionality entirely from production builds or strongly discourage its use and provide prominent warnings about the security risks.
    - **Production Environment Check:** Implement a startup check that verifies if `BYPASS_AUTHORIZATION` is enabled. If it is enabled in a non-development environment (e.g., based on environment variables like `ENVIRONMENT=production`), the application should refuse to start and log a critical error.
    - **Security Hardening Documentation:**  Clearly document in `docs/auth.md` and `docs/env_vars.md` the severe security implications of enabling `BYPASS_AUTHORIZATION` in production, emphasizing that it should ONLY be used for local development and testing.

- **Preconditions:**
    - The Skynet application is deployed in a production environment.
    - The `BYPASS_AUTHORIZATION` environment variable is set to `true` or `1` during deployment or runtime configuration.

- **Source Code Analysis:**
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

- **Security Test Case:**
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

### Vulnerability Name: JWT Authorization Misconfiguration

- **Description:**
    1. Skynet uses JWT (JSON Web Tokens) for API authorization.
    2. The JWT verification process relies on fetching public keys from a remote URL (`ASAP_PUB_KEYS_REPO_URL`) based on the `kid` (Key ID) in the JWT header.
    3. Several environment variables configure this process, including `ASAP_PUB_KEYS_REPO_URL`, `ASAP_PUB_KEYS_FOLDER`, `ASAP_PUB_KEYS_AUDS`, `ASAP_PUB_KEYS_MAX_CACHE_SIZE`.
    4. Misconfiguration in any of these variables can lead to authentication bypass or denial of service:
        - **Incorrect `ASAP_PUB_KEYS_REPO_URL` or `ASAP_PUB_KEYS_FOLDER`:** If the URL or folder path is wrong, the server will fail to fetch public keys. If fallback folder is configured incorrectly as well, authentication will fail for all valid JWTs, causing denial of service. If attacker can control this URL (e.g., via environment variable injection in some misconfigured deployments), they can provide their own public key and bypass authentication.
        - **Incorrect `ASAP_PUB_KEYS_AUDS`:** If the allowed audiences are not correctly configured, valid JWTs with legitimate audiences might be rejected, causing denial of service for authorized users. Conversely, overly permissive audience configurations could allow JWTs intended for other services to be accepted by Skynet, leading to unauthorized access.
    5.  Furthermore, if the public key infrastructure is compromised (e.g., attacker gains access to the web server hosting public keys), attackers can replace legitimate public keys with their own, allowing them to forge valid JWTs and completely bypass authentication.

- **Impact:**
    - **Medium to High** (depending on the misconfiguration).
    - **Authentication Bypass:** If `ASAP_PUB_KEYS_REPO_URL` is attacker-controlled or if public key infrastructure is compromised, attackers can forge JWTs and gain unauthorized access.
    - **Denial of Service:** Incorrect `ASAP_PUB_KEYS_REPO_URL`, `ASAP_PUB_KEYS_FOLDER`, or `ASAP_PUB_KEYS_AUDS` can cause the server to reject all valid JWTs, resulting in denial of service for legitimate users.
    - **Data Exposure and Unauthorized Usage:** Successful bypass allows attackers to utilize AI services and potentially access/manipulate data.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - JWT verification logic in `/code/skynet/auth/jwt.py` verifies signature and audience.
    - Public key caching (`alru_cache`) in `/code/skynet/auth/jwt.py` to reduce public key fetching frequency.

- **Missing Mitigations:**
    - **Input Validation for Configuration Variables:** Validate the format and validity of `ASAP_PUB_KEYS_REPO_URL` (e.g., ensure it's a valid URL) and `ASAP_PUB_KEYS_FOLDER` (e.g., ensure it's a valid path format) at startup.
    - **Error Handling and Fallback for Public Key Retrieval:** Improve error handling for public key retrieval failures. While a fallback folder (`ASAP_PUB_KEYS_FALLBACK_FOLDER`) is present, ensure robust error logging and alerting if public key retrieval consistently fails from both primary and fallback locations.
    - **Public Key Infrastructure Security Guidance:** Provide clear documentation and best practices for securing the public key infrastructure, including secure storage, access control, and monitoring of the public key server. Emphasize the importance of HTTPS for `ASAP_PUB_KEYS_REPO_URL` to prevent man-in-the-middle attacks during key retrieval.
    - **Key Rotation Strategy Documentation:** Document a recommended key rotation strategy and mechanisms to ensure keys are rotated periodically and securely.

- **Preconditions:**
    - Skynet is deployed with JWT authentication enabled (default).
    - Misconfiguration of `ASAP_PUB_KEYS_REPO_URL`, `ASAP_PUB_KEYS_FOLDER`, or `ASAP_PUB_KEYS_AUDS` environment variables, or compromise of the public key infrastructure.

- **Source Code Analysis:**
    - File: `/code/skynet/auth/jwt.py`
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

- **Security Test Case:**
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