## Combined Vulnerability Report

### Server-Side Request Forgery (SSRF) via Unvalidated URLs in Parts

- **Description:**
    - An attacker can inject malicious URLs into the `parts` dictionaries when calling the `create_job` function in the `watchbot-progress-py` library.
    - The `create_job` function processes the `parts` list and sends SNS messages to worker processes. These messages include the parts data, effectively distributing the potentially malicious URLs.
    - When a worker process receives an SNS message, it is expected to use the `Part` context manager and process the data, including the 'url' from the message, within a user-implemented function like `process_url`.
    - If the user's processing code, specifically the `process_url` function, naively uses the `url` from the `message` (derived from `parts`) without proper validation and sanitization, it becomes vulnerable to Server-Side Request Forgery (SSRF).
    - For example, if the `process_url` function fetches content from the URL specified in `message['url']` using libraries like `requests.get(message['url'])` without sanitization, an attacker can control this URL to point to internal resources or external malicious sites.
    - When the `process_url` code executes, it will make a request to the attacker-controlled URL from the server's perspective, potentially exposing internal services or data, or performing actions on behalf of the server.

- **Impact:**
    - An attacker can potentially scan internal network resources that are not publicly accessible, bypassing firewalls and network segmentation.
    - Access sensitive data from internal services, such as configuration files, internal APIs, databases, or administrative interfaces. This could lead to information disclosure.
    - Coerce the server into interacting with external systems on behalf of the attacker. This could be used to conduct port scanning of external networks, or to relay malicious requests to other servers.
    - In some cases, depending on the nature of the internal resources exposed and the capabilities of the `process_url` function, it might be possible to achieve more severe attacks like Remote Code Execution by interacting with vulnerable internal services.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - None. The `watchbot-progress-py` library itself does not implement any input validation or sanitization for the `parts` data, including URLs.
    - The README.md file mentions the possibility of SSRF as a warning, stating that "if parts contain URLs processed without sanitization" SSRF is possible and that "The most likely attack vector is through injecting malicious URLs into the `parts` list, which are then processed by the user-implemented `process_url` function, potentially leading to vulnerabilities like Server-Side Request Forgery if this function is not properly secured." This serves as a documentation-level warning but is not a code-level mitigation.

- **Missing Mitigations:**
    - **Input Validation and Sanitization:** The primary missing mitigation is the lack of enforced input validation and sanitization for URLs within the `parts` list. While the library might not directly implement validation, it should provide:
        - **Strong Documentation and Guidelines:**  The documentation should be significantly enhanced to explicitly and prominently highlight the SSRF vulnerability. It should provide clear guidelines and mandatory examples on how users MUST securely handle URLs within their `process_url` function. This includes recommendations and code examples for URL validation, allow-listing of safe domains, and preventing redirects to unexpected domains.
        - **Utility Functions (Optional):**  Consider providing utility functions within the library to assist users with common URL validation tasks, making it easier for them to implement secure URL handling.

- **Preconditions:**
    - The application using `watchbot-progress-py` must process URLs or interact with external resources based on data provided in the `parts` dictionaries. Specifically, the user must implement a `process_url` function that processes the 'url' from the message and makes HTTP requests.
    - The processing code (`process_url` function) must naively use URLs from the `parts` without implementing proper validation or sanitization.
    - An attacker needs to have the ability to influence or control the `parts` list that is provided as input to the `create_job` function. This could occur if the `parts` data is derived from external, untrusted sources or user-provided input.

- **Source Code Analysis:**
    - **`watchbot_progress/main.py`:**
        ```python
        def create_job(parts, jobid=None, workers=25, progress=None, metadata=None):
            # ...
            annotated_parts = []
            for partid, original_part in enumerate(parts):
                part = original_part.copy()
                part.update(partid=partid)
                part.update(jobid=jobid)
                part.update(metadata=metadata)
                annotated_parts.append(part)
            # ...
        ```
        - The `create_job` function in `/code/watchbot_progress/main.py` accepts a `parts` list as an argument.
        - It iterates through the provided `parts` list and enriches each part with `partid`, `jobid`, and `metadata`. Critically, it directly uses the content of the `parts` list without any validation or sanitization. The library trusts that the input `parts` are safe.
        - The `Part` context manager is used in user-implemented processing code to handle each part. For example, as shown in the README.md:
        ```python
        with Part(jobid, partid):
            # The context block
            process_url(message['url'])
        ```
        - The `Part` context manager in `/code/watchbot_progress/main.py` itself is focused on progress tracking and does not interact with or validate the content of `message['url']`.
        - The responsibility of processing the `message['url']` and ensuring its security is entirely delegated to the user-implemented `process_url` function, which is outside the scope of the `watchbot-progress-py` library's code.

    - **Visualization of Data Flow:**
        ```
        [Attacker Controlled Input: parts list with malicious URLs] --> create_job()
                                                                    |
                                                                    v
        [SNS Messages with parts data (including malicious URLs)] --> SNS Topic
                                                                    |
                                                                    v
        [Worker Process receives SNS message] --> User-Implemented process_url(message['url'])
                                                    [Vulnerable if no URL validation] --> SSRF
        ```

- **Security Test Case:**
    1. **Setup:**
        - Deploy the `watchbot-progress-py` library in a test environment.
        - Create a dummy worker process that subscribes to the SNS topic used by `watchbot-progress-py`.
        - Implement a vulnerable `process_url` function within the worker process. This function will take a URL as input and directly make an HTTP GET request to it using a library like `requests` without any validation:
        ```python
        import requests
        def process_url(url):
            requests.get(url) # Vulnerable: No URL validation
        ```
        - Configure the worker process to use the `Part` context manager from `watchbot-progress-py` and call the vulnerable `process_url` function within it, as shown in the README example.
    2. **Craft Malicious Input:**
        - Create a `parts` list that includes a malicious URL pointing to a publicly accessible request interception service like `https://webhook.site` or `https://requestbin.net`. For example:
        ```python
        parts = [{'url': 'https://[YOUR-UNIQUE-REQUESTBIN-URL].requestbin.net/ssrf-test'}]
        ```
        Replace `[YOUR-UNIQUE-REQUESTBIN-URL].requestbin.net` with your actual RequestBin URL to observe incoming requests.
    3. **Trigger Job Creation:**
        - Execute the `create_job` function, providing the crafted `parts` list as input:
        ```python
        from watchbot_progress import create_job
        jobid = create_job(parts)
        print(f"Job ID: {jobid}")
        ```
    4. **Observe SSRF:**
        - Monitor the RequestBin URL (`https://[YOUR-UNIQUE-REQUESTBIN-URL].requestbin.net/ssrf-test`).
        - After the worker process receives the SNS message and executes the `process_url` function, you should observe an HTTP GET request appearing in your RequestBin.
        - The request will originate from the IP address of the worker process, confirming that the server-side `process_url` function made a request to the attacker-specified URL.
    5. **Verification:**
        - The successful reception of the request on the attacker-controlled RequestBin demonstrates the SSRF vulnerability. An attacker can control the server's outbound requests by injecting malicious URLs into the `parts` list, which are then processed by the vulnerable `process_url` function.