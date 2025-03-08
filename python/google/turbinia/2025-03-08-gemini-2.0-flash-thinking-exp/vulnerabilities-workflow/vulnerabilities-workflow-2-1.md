- vulnerability name: Exposed Debug Ports in Docker Compose and Dockerfile
  description: |
    Debug ports for the Turbinia API server (port 30000), Turbinia Server (port 20000), and Turbinia Worker (port 10000) are exposed in `docker-compose.yml`, `docker-compose-dind.yml`, and `skaffold.yaml`. Additionally, the API server Dockerfile exposes port 30000, and the worker Dockerfile exposes port 10000.

    Step-by-step trigger:
    1. Deploy Turbinia using Docker Compose or Skaffold with default configurations.
    2. Use a tool like `nmap` or `telnet` to scan the exposed ports on the host machine where Turbinia is deployed.
    3. Observe that ports 30000, 20000, and 10000 are open and accessible.
  impact: |
    Exposure of debug ports can allow an attacker to connect to the debugging interface and potentially gain access to sensitive information, control the application, or execute arbitrary code. While the debuggers may require authentication, misconfigurations or vulnerabilities in the debugger itself could be exploited.
  vulnerability rank: medium
  currently implemented mitigations: No specific mitigations are implemented in the project.
  missing mitigations: |
    - Remove debug port exposure from production Docker Compose and Dockerfile configurations.
    - Ensure debug ports are only exposed in development environments and are properly secured (e.g., using network policies or firewalls to restrict access).
  preconditions: |
    - Turbinia deployed using Docker Compose or Skaffold with default configurations.
    - Network access to the deployed Turbinia instance.
  source code analysis: |
    - **File: /code/docker/local/docker-compose.yml, /code/docker/local/docker-compose-dind.yml, /code/skaffold.yaml:**
      - These files explicitly define port mappings that expose debug ports to the host:
        ```yaml
        ports:
          - 127.0.0.1:30000:30000 # API Server debug port
        ports:
          - 127.0.0.1:20000:20000 # Server debug port
        ports:
          - 127.0.0.1:10000:10000 # Worker debug port
        ```
    - **File: /code/docker/api_server/Dockerfile, /code/docker/worker/Dockerfile:**
      - These Dockerfiles EXPOSE debug ports:
        ```dockerfile
        EXPOSE 30000/tcp # API Server debug port
        EXPOSE 10000/tcp # Worker debug port
        ```
  security test case: |
    1. Deploy Turbinia locally using `docker-compose -f ./docker/local/docker-compose.yml up`.
    2. On the host machine, use `nmap` to scan for open ports: `nmap -p30000,20000,10000 localhost`.
    3. Verify that ports 30000, 20000, and 10000 are listed as open.

- vulnerability name: Insecure Configuration via Base64 Encoded Environment Variables
  description: |
    The Turbinia API server, controller, worker, and oauth2-proxy Docker images use shell scripts (`start.sh`) to base64 decode configuration files from environment variables (`TURBINIA_CONF`, `OAUTH2_CONF`, `OAUTH2_AUTH_EMAILS`). If these environment variables are compromised or not securely managed, attackers could inject malicious configurations.

    Step-by-step trigger:
    1. Deploy Turbinia using Docker, setting a malicious base64 encoded string to the `TURBINIA_CONF` environment variable.
    2. Start the Turbinia API server using the Docker image.
    3. Observe that the API server loads the malicious configuration from the environment variable.
  impact: |
    An attacker who can control the environment variables of the Turbinia containers could inject arbitrary and malicious configurations, potentially leading to:
    - Unauthorized access to the Turbinia API server or other components.
    - Data exfiltration or manipulation.
    - Execution of arbitrary code within Turbinia workers or server.
  vulnerability rank: high
  currently implemented mitigations: No specific mitigations are implemented in the project.
  missing mitigations: |
    - Avoid passing sensitive configurations via environment variables, even if base64 encoded.
    - Implement more secure configuration management practices, such as using secrets management systems or configuration files with restricted permissions.
    - Validate and sanitize configurations loaded from environment variables to prevent injection attacks.
  preconditions: |
    - Ability to set environment variables for the Turbinia Docker containers during deployment or runtime.
  source code analysis: |
    - **File: /code/docker/api_server/start.sh, /code/docker/controller/start.sh, /code/docker/server/start.sh, /code/docker/worker/start.sh, /code/docker/oauth2_proxy/start.sh:**
      - These scripts contain code that decodes environment variables using base64:
        ```bash
        if [ ! -z "$TURBINIA_CONF" ] && [ ! -s /etc/turbinia/turbinia.conf ]
        then
            echo "${TURBINIA_CONF}" | base64 -d > /etc/turbinia/turbinia.conf
        fi
        ```
        ```bash
        if [ ! -z "$OAUTH2_CONF" ] && [ ! -s /etc/turbinia/oauth2.conf ]
        then
            echo "${OAUTH2_CONF}" | base64 -d > /etc/turbinia/oauth2.conf
        fi
        ```
        ```bash
        if [ ! -z "$OAUTH2_AUTH_EMAILS" ] && [ ! -s /etc/turbinia/auth.txt ]
        then
            echo "${OAUTH2_AUTH_EMAILS}" | base64 -d > /etc/turbinia/auth.txt
        fi
        ```
  security test case: |
    1. Create a malicious `turbinia.conf` file with a backdoor or harmful settings.
    2. Base64 encode the malicious configuration: `base64 -w 0 malicious_turbinia.conf`.
    3. Deploy Turbinia locally using Docker Compose, setting the `TURBINIA_CONF` environment variable to the base64 encoded malicious configuration:
       ```bash
       docker run -ti -e TURBINIA_CONF="<base64_encoded_malicious_config>" turbinia-api-server:dev
       ```
    4. Verify that the Turbinia API server is running with the injected malicious configuration (e.g., by observing unexpected behavior or checking loaded settings).

- vulnerability name: Potential Authentication Bypass or Privilege Escalation via API Authorization Flaws
  description: |
    The documentation mentions that the Turbinia API server uses OAuth2 for authentication and authorization. However, the provided files do not contain source code for the API server itself, so it's impossible to verify if authorization is correctly implemented and enforced for all API endpoints. A potential vulnerability could exist if certain API endpoints lack proper authorization checks, allowing unauthorized users to access sensitive functionalities or data.

    Step-by-step trigger:
    1. Identify API endpoints from `/code/turbinia/api/client/docs/` that seem critical or sensitive (e.g., endpoints related to request creation, evidence download, task management).
    2. Attempt to access these endpoints without valid OAuth2 credentials or with credentials of a user who should not have access.
    3. Observe if the API server correctly denies access or if it allows unauthorized actions.
  impact: |
    If authentication or authorization is flawed, an attacker could:
    - Gain unauthorized access to Turbinia API server functionalities.
    - Submit malicious forensic processing requests.
    - Access sensitive forensic evidence or results.
    - Potentially compromise the entire Turbinia deployment and the forensic process.
  vulnerability rank: critical
  currently implemented mitigations: |
    - The documentation states that OAuth2-proxy is used for authentication, suggesting that authentication is intended to be enforced. However, the implementation details are not in the provided files.
  missing mitigations: |
    - **Source code review and security audit:** Thoroughly review the API server source code to confirm that authentication and authorization are correctly implemented for all API endpoints.
    - **Security testing:** Perform penetration testing and security assessments to identify any authorization bypass vulnerabilities.
    - **Enforce RBAC (Role-Based Access Control):** Implement RBAC to control access to different API endpoints and functionalities based on user roles and permissions.
  preconditions: |
    - Publicly accessible Turbinia API server instance.
    - Lack of proper authentication and authorization enforcement in the API server code.
  source code analysis: |
    - **File: /code/turbinia/api/client/docs/TurbiniaRequestsApi.md, /code/turbinia/api/client/docs/TurbiniaTasksApi.md, /code/turbinia/api/client/docs/TurbiniaConfigurationApi.md, /code/turbinia/api/client/docs/TurbiniaEvidenceApi.md, /code/turbinia/api/client/docs/TurbiniaLogsApi.md, /code/turbinia/api/client/docs/TurbiniaJobsApi.md, /code/turbinia/api/client/docs/TurbiniaRequestResultsApi.md:**
      - These files are OpenAPI client documentation and indicate the existence of various API endpoints related to requests, tasks, evidence, configuration, jobs, and logs.
      - The documentation mentions "OAuth Authentication (oAuth2)" and "Authorization: [oAuth2](../README.md#oAuth2)" for API endpoints, suggesting that authentication is intended.
      - However, the actual server-side code implementing these endpoints and enforcing authorization is not provided in the PROJECT FILES, making it impossible to verify the security implementation.
  security test case: |
    1. Deploy a Turbinia instance with API server enabled.
    2. Identify a sensitive API endpoint (e.g., `/api/request/`, `/api/evidence/upload`).
    3. Attempt to send a request to this endpoint without providing any OAuth2 access token in the `Authorization` header.
    4. Observe if the API server returns a 401 Unauthorized or 403 Forbidden error, indicating that authentication is enforced.
    5. If the API server allows the request without authentication, it indicates an authentication bypass vulnerability.
    6. If authentication is enforced, attempt to use a valid OAuth2 access token but for a user who should not have permission to access the endpoint (e.g., a regular user trying to access admin-level functionalities).
    7. Observe if the API server correctly denies access based on authorization policies.
    8. If the API server allows unauthorized access, it indicates an authorization flaw.