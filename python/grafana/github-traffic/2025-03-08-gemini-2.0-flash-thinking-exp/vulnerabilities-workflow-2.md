### Vulnerability List

#### Unsecured Prometheus Metrics Endpoint
- **Vulnerability Name:** Unsecured Prometheus Metrics Endpoint
- **Description:** The `github-traffic` application exposes a Prometheus metrics endpoint at `/metrics` without any authentication or authorization. This endpoint provides detailed information about GitHub repository traffic, including views, unique views, clones, unique clones, top paths, top referrers, and stargazers count for repositories within a specified organization or user. An attacker can access this endpoint without any credentials as long as the `github-traffic` instance is reachable over the network. By accessing this endpoint, an attacker can gain unauthorized insights into the traffic patterns of the targeted organization's or user's repositories.
- **Impact:** Exposure of sensitive repository traffic data. This data can reveal insights into the popularity and usage of specific repositories, potentially including sensitive projects. Attackers could use this information to understand development activity, identify popular resources, or gain a competitive advantage by understanding a target organization's focus and interests based on repository usage patterns.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:** None. The application exposes the `/metrics` endpoint without any form of access control.
- **Missing Mitigations:** Implement authentication and authorization mechanisms for the `/metrics` endpoint. This could involve:
    - Basic authentication: Require username and password to access the endpoint.
    - API key authentication: Require a valid API key in the request header or query parameters.
    - Network-based access control: Restrict access to the endpoint based on IP address or network range.
    - Integration with an authentication and authorization service: Use existing organizational authentication infrastructure to control access.
- **Preconditions:**
    - A `github-traffic` instance is running and accessible over the network.
    - The attacker knows or can discover the IP address or hostname and port (default: 8001) of the running `github-traffic` instance.
- **Source Code Analysis:**
    1. In the file `/code/github-traffic.py`, the application initializes and starts an HTTP server to expose Prometheus metrics using the line `start_http_server(8001)`.
    2. The `start_http_server` function from the `prometheus_client` library, by default, exposes the metrics endpoint on the specified port (8001 in this case) without any built-in authentication or authorization.
    3. The application logic within the `job_function` periodically fetches repository traffic data from GitHub using the PyGitHub library and updates Prometheus metrics gauges (e.g., `gh_traffic_views`, `gh_traffic_clones`, `gh_traffic_top_paths`).
    4. These metrics are then served by the HTTP server at the `/metrics` endpoint.
    5. There is no code in `github-traffic.py` or any other provided configuration files that implements any form of authentication or access control for the `/metrics` endpoint. Anyone who can reach the application on port 8001 can access the `/metrics` endpoint and retrieve the exposed data.

- **Security Test Case:**
    1. Deploy the `github-traffic` application using Docker Compose as described in the `README.md` and `docker-compose.yaml` files. Ensure that the `.env` file is configured with a valid `GITHUB_TOKEN` and either `ORG_NAME` or `USER_NAME`.
    2. Once the application is running, identify the IP address or hostname of the machine where `github-traffic` is deployed. If running locally, this would typically be `localhost` or `127.0.0.1`.
    3. Open a web browser or use a command-line tool like `curl` or `wget`.
    4. Access the metrics endpoint by navigating to `http://<github-traffic-instance-ip>:8001/metrics`.
    5. Observe the output. You should see a plaintext output containing Prometheus metrics, including `github_traffic_views`, `github_traffic_clones`, `github_traffic_top_paths`, `github_traffic_top_referrers`, and other metrics related to repository traffic.
    6. Verify that there is no prompt for username, password, API key, or any other form of authentication.
    7. This confirms that the `/metrics` endpoint is publicly accessible without any authentication, and an attacker can retrieve sensitive repository traffic data by simply accessing this URL.

#### Exposure of GitHub API Token via Environment Variable
- **Vulnerability Name:** Exposure of GitHub API Token via Environment Variable
- **Description:**
  The github-traffic application uses a GitHub API token (`GITHUB_TOKEN`) to authenticate with the GitHub API. This token is configured through an environment variable, which is commonly loaded from a `.env` file or directly set in the Docker environment. If this environment variable is exposed, for example, through a leaked `.env` file, a misconfigured environment, or other means, an attacker can gain unauthorized access to the GitHub API using the leaked token.
- **Impact:**
  Unauthorized access to the GitHub API. The severity of the impact depends on the scope of the leaked `GITHUB_TOKEN`. A token with broad permissions could allow an attacker to:
    - Read private repositories.
    - Modify repository settings.
    - Create or delete repositories.
    - Access organization information.
    - Perform other actions depending on the token's scope.

  Even with a token intended for read-only access for traffic data, an attacker could potentially:
    - Gather sensitive information about the organization's repositories and activities beyond just traffic data.
    - Potentially escalate privileges if the token has broader than intended scope.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
  None. The project documentation suggests using a `.env` file for configuration, which is a common practice but does not inherently mitigate the risk of token exposure.
- **Missing Mitigations:**
  - **Secret Management:** Implement a secure secret management solution instead of relying solely on environment variables, especially not `.env` files in version control. Examples include:
    - HashiCorp Vault
    - AWS Secrets Manager
    - Kubernetes Secrets
  - **Principle of Least Privilege for Tokens:**  Clearly document and recommend creating GitHub API tokens with the minimal necessary scope required for the application to function (ideally read-only access to repository traffic data). Specify the required scopes in the documentation.
  - **Environment Variable Security Best Practices Documentation:** Enhance the documentation to include best practices for securely handling environment variables in Docker and Kubernetes environments. Emphasize:
    - Never commit `.env` files containing secrets to version control.
    - Utilize secure secret injection methods provided by container orchestration platforms instead of relying on simple environment variables where possible.
- **Preconditions:**
  - The github-traffic application must be deployed and configured to use a `GITHUB_TOKEN` environment variable for accessing the GitHub API.
  - An attacker needs to gain access to the environment where the application is running or to the configuration files (like `.env` if used insecurely) that contain the `GITHUB_TOKEN`. This access could be achieved through various means, such as:
    - Leaking the `.env` file (e.g., accidentally committing it to a public repository).
    - Exploiting a misconfiguration in the deployment environment that exposes environment variables.
    - Gaining unauthorized access to the server or container where the application is running.
- **Source Code Analysis:**
  - In `/code/github-traffic.py`:
    - Line 13: `GITHUB_TOKEN = config('GITHUB_TOKEN')` - The application reads the `GITHUB_TOKEN` from environment variables using the `python-decouple` library. This is a common way to configure applications, but it introduces security risks if environment variables are not handled properly.
    - Line 15: `github = Github(GITHUB_TOKEN)` - The retrieved `GITHUB_TOKEN` is directly used to instantiate the `Github` client from the `PyGithub` library. This client is then used throughout the script to interact with the GitHub API.
    - The application logic within the `job_function` uses this `github` object to fetch repository data using API calls like `repo.get_views_traffic`, `repo.get_clones_traffic`, etc. These operations are authenticated using the provided `GITHUB_TOKEN`.

  - **Vulnerability Flow:**
    1.  The application starts and reads the `GITHUB_TOKEN` from the environment.
    2.  The `GITHUB_TOKEN` is used to authenticate API requests to GitHub.
    3.  If the environment where the application runs is compromised, or if the `.env` file (if used) is exposed, the `GITHUB_TOKEN` can be easily retrieved by an attacker.
    4.  With the leaked `GITHUB_TOKEN`, the attacker can directly authenticate to the GitHub API and perform actions based on the token's permissions, potentially causing significant harm.

- **Security Test Case:**
  1. **Setup:**
     - Deploy the `github-traffic` application locally using Docker Compose, following the instructions in the `README.md`.
     - Create a `.env` file in the `/code` directory (or project root if deploying outside Docker) and include a dummy `GITHUB_TOKEN` and other required variables like `ORG_NAME` or `USER_NAME`. For testing the vulnerability, the actual validity of the `GITHUB_TOKEN` is not strictly necessary initially to demonstrate exposure, but for full verification, use a real token.
     - Start the application using `docker-compose up -d`.
     - Verify the application is running and accessible at `http://localhost:8001/metrics`.

  2. **Simulate Token Exposure by Accessing Container Environment:**
     - Identify the running container name for the `traffic` service using `docker ps`. It will likely be named something like `github-traffic_traffic_1`.
     - Execute the following command to access the environment variables inside the running container:
       ```bash
       docker exec -it github-traffic_traffic_1 env
       ```
     - Examine the output for the `GITHUB_TOKEN` environment variable. It should be listed along with other environment variables.

  3. **Extract and Verify Token:**
     - From the output of the previous command, manually copy the value of the `GITHUB_TOKEN` environment variable.
     - Use `curl` or a similar HTTP client to make a request to the GitHub API, authenticating with the extracted token. For example, to get information about the authenticated user (note: scope might limit access to certain endpoints, adjust API endpoint based on expected token scope):
       ```bash
       curl -H "Authorization: token <extracted_token>" https://api.github.com/user
       ```
       Replace `<extracted_token>` with the `GITHUB_TOKEN` value you extracted from the container environment.

  4. **Analyze Results:**
     - If the `curl` command to the GitHub API is successful (returns a 200 OK status code and a JSON response containing user information or other API data), it confirms that the extracted `GITHUB_TOKEN` is valid and can be used to authenticate with the GitHub API.
     - This demonstrates that an attacker who gains access to the container's environment (even with limited privileges to view environment variables) can retrieve the sensitive `GITHUB_TOKEN` and potentially misuse it to access GitHub resources, confirming the vulnerability.

  5. **Cleanup:**
     - Stop and remove the Docker containers using `docker-compose down`.

#### GitHub API Token Exposure in Logs
- **Vulnerability Name:** GitHub API Token Exposure in Logs
- **Description:**
    * The application uses the `GITHUB_TOKEN` environment variable to authenticate with the GitHub API.
    * The application uses `logfmt_logger` for logging purposes.
    * If an error occurs during the application's execution, especially during GitHub API interactions or during the initialization of the GitHub client, the error message might inadvertently include sensitive information, such as the `GITHUB_TOKEN`.
    * If application logs are not securely managed and are accessible to unauthorized users or systems (e.g., if logs are inadvertently exposed through Prometheus metrics or accessible log files), the `GITHUB_TOKEN` could be compromised.
    * An attacker with access to these logs could extract the `GITHUB_TOKEN`.

- **Impact:**
    * If the GitHub API token is exposed, an attacker can gain unauthorized access to the GitHub repositories accessible by the token.
    * Depending on the token's permissions, the attacker could:
        * Read private repository content.
        * Modify code, including adding backdoors or malicious code.
        * Access sensitive data and secrets stored in the repositories.
        * Perform actions on GitHub on behalf of the token owner, such as creating or deleting repositories, managing issues and pull requests, etc.
        * Potentially pivot to other systems or resources accessible through the compromised GitHub account.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    * None in the provided code explicitly prevent the token from being logged. The application relies on environment variables for configuration, which is a standard practice for security, but it doesn't inherently prevent logging of sensitive values.

- **Missing Mitigations:**
    * **Secure Logging Practices**: Implement secure logging practices to prevent sensitive information like API tokens from being included in log messages. This can be achieved by:
        * **Error Handling with Sanitization**: Ensure error handling routines sanitize error messages to remove sensitive data before logging.
        * **Logging Level Configuration**: Configure logging levels appropriately for production environments. Avoid debug or verbose logging levels that might output sensitive information. Use error or warning levels for operational logs.
        * **Token Masking/Redaction**: Implement token masking or redaction techniques in the logging mechanism to replace sensitive parts of the token with placeholder characters (e.g., `GITHUB_TOKEN=ghp_********************`).
    * **Secure Log Storage and Access Control**: Ensure that application logs are stored securely and access is restricted to authorized personnel only. Avoid exposing logs publicly or through insecure channels.
    * **Regular Log Review**: Implement regular log review processes to detect and respond to any potential security incidents, including accidental token exposure in logs.

- **Preconditions:**
    * Application logs are accessible to an attacker. This could be due to:
        * Misconfigured logging infrastructure.
        * Logs being written to publicly accessible storage.
        * Logs being inadvertently exposed through other monitoring systems.
    * An error condition occurs within the application that leads to the logging of the `GITHUB_TOKEN` or information that includes the token. This could be triggered by:
        * Invalid `GITHUB_TOKEN` configuration.
        * Network connectivity issues preventing API calls.
        * Rate limiting by the GitHub API.
        * Internal application errors during API interaction.

- **Source Code Analysis:**
    * The application uses `decouple` library to read `GITHUB_TOKEN` from environment variables in `github-traffic.py`:
    ```python
    GITHUB_TOKEN = config('GITHUB_TOKEN')
    github = Github(GITHUB_TOKEN)
    logger = getLogger("github_traffic")
    ```
    * The `Github` client initialization with the token happens at the start of the script. If the `GITHUB_TOKEN` is invalid or missing, the `pygithub` library might raise an exception.
    * The `logfmt_logger` is used for logging throughout the application using `logger.info`, `logger.error`.
    * Within the `job_function`, various API calls are made to GitHub. Exceptions during these calls are caught and logged using `logger.error`:
    ```python
    except Exception as e:
        logger.error(f"Failed to extract views on {repo_name}: {e}")
    ```
    * The exception `e` in the `logger.error` call could potentially contain sensitive information depending on the nature of the exception and how `pygithub` and `requests` libraries handle error reporting. If an authentication error occurs because of an invalid token, the error message might include details that could reveal parts of the token or indicate that token authentication failed, indirectly confirming the token's value or format in logs.
    * The `logfmt_logger` configuration is not provided in the project files, so it is assumed to be using default settings which might log error details verbosely.
    * The Prometheus metrics themselves do not directly expose the token, but if logs are scraped and exposed as metrics (which is not standard but technically possible depending on monitoring setup), then token exposure through logs could indirectly lead to exposure in metrics dashboards if not handled carefully.

- **Security Test Case:**
    1. **Setup**: Deploy the application using Docker as described in the `README.md` and `docker-compose.yaml`. Create a `.env` file.
    2. **Invalid Token**: In the `.env` file, set an intentionally invalid `GITHUB_TOKEN` (e.g., `GITHUB_TOKEN=invalid-token`). Ensure other necessary variables like `ORG_NAME` or `USER_NAME` are also set appropriately for the application to attempt GitHub API calls.
    3. **Run Application**: Start the application using `docker-compose up -d` or `docker run --env-file .env -it -p 8001:8001 ghcr.io/grafana/github-traffic`.
    4. **Inspect Logs**: Check the Docker container logs. You can use `docker logs <container_id>` (replace `<container_id>` with the actual container ID of the `traffic` service). Alternatively, if using docker-compose, use `docker-compose logs traffic`.
    5. **Analyze Logs for Token Exposure**: Examine the logs for any error messages that might contain the `GITHUB_TOKEN` or parts of it. Specifically, look for error messages related to authentication or API connection failures that might include the token in their details or context. For example, error messages from `pygithub` or `requests` libraries related to invalid authentication could potentially log sensitive information.
    6. **Expected Result**: The logs should ideally not contain the `GITHUB_TOKEN`. However, if the vulnerability exists, error logs might inadvertently include the token or parts of it when authentication fails due to the invalid token. If the token or any part of it is found in the logs, the vulnerability is confirmed.
    7. **Remediation Verification**: After implementing mitigations (like sanitizing log messages and using appropriate logging levels), repeat the test to ensure that the token is no longer exposed in the logs when using an invalid `GITHUB_TOKEN`.