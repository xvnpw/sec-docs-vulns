### Vulnerability List

- Vulnerability Name: Server-Side Request Forgery (SSRF) in User-Implemented `process_url`
- Description:
    1. An attacker can control the `parts` list provided as input to the `create_job` function.
    2. The `parts` list can contain dictionaries with a 'url' key, designed to be processed by the user-implemented `process_url` function. For example: `parts = [{'url': 'http://malicious.attacker.com'}]`.
    3. The `create_job` function, after processing the `parts` list, sends SNS messages to worker processes. These messages include the parts data, effectively distributing the potentially malicious URLs.
    4. In the worker process, the user is expected to implement a `process_url` function. This function is intended to process the 'url' extracted from the SNS message received for each part.
    5. If the user's `process_url` function directly makes HTTP requests using the 'url' from the message without proper validation and sanitization, it becomes vulnerable to Server-Side Request Forgery (SSRF).
    6. By injecting a malicious URL (e.g., pointing to internal resources or external attacker-controlled servers), an attacker can force the server to make unintended requests.
- Impact:
    - **Access to Internal Resources:** An attacker could potentially bypass firewalls and access internal services or resources that are not meant to be publicly accessible, such as internal databases, configuration files, or administrative interfaces.
    - **Information Disclosure:** By making requests to internal resources, the attacker might be able to extract sensitive information contained within these resources.
    - **Interaction with External Systems:** The server could be coerced into interacting with external systems on behalf of the attacker. This could be used to conduct port scanning of external networks, or to relay malicious requests to other servers.
    - **Potential for Further Exploitation:** In some scenarios, SSRF can be a stepping stone to more severe vulnerabilities, such as Remote Code Execution, depending on the nature of the internal resources exposed and the capabilities of the `process_url` function.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The `watchbot-progress-py` library itself does not implement any input validation or sanitization for the `url` within the `parts` list.
    - The README.md file implicitly mentions this potential vulnerability by stating "The most likely attack vector is through injecting malicious URLs into the `parts` list, which are then processed by the user-implemented `process_url` function, potentially leading to vulnerabilities like Server-Side Request Forgery if this function is not properly secured." This serves as a documentation-level warning but is not a code-level mitigation.
- Missing Mitigations:
    - **Input Validation and Sanitization:** The primary missing mitigation is the lack of input validation and sanitization for URLs within the `parts` list. This validation should ideally be implemented by the user within their `process_url` function, as the library itself is designed to be agnostic to the specific processing logic. However, stronger warnings and guidelines within the documentation are needed to emphasize this requirement.
    - **Documentation Enhancement:** The documentation should be improved to explicitly and prominently highlight the SSRF vulnerability. It should provide clear guidelines and examples on how users can securely handle URLs within their `process_url` function, including recommendations for URL validation, allow-listing, and preventing redirects to unexpected domains.
- Preconditions:
    - **Vulnerable `process_url` Implementation:** The user must implement a `process_url` function that processes the 'url' from the message and makes HTTP requests without proper security measures (i.e., without input validation and sanitization).
    - **Attacker Control over `parts` Input:** An attacker needs to have the ability to influence or control the `parts` list that is provided as input to the `create_job` function. This could occur if the `parts` data is derived from external, untrusted sources or user-provided input.
- Source Code Analysis:
    - The `create_job` function in `/code/watchbot_progress/main.py` accepts a `parts` list as an argument:
    ```python
    def create_job(parts, jobid=None, workers=25, progress=None, metadata=None):
        ...
        annotated_parts = []
        for partid, original_part in enumerate(parts):
            part = original_part.copy()
            part.update(partid=partid)
            part.update(jobid=jobid)
            part.update(metadata=metadata)
            annotated_parts.append(part)
        ...
    ```
    - This code iterates through the provided `parts` list and enriches each part with `partid`, `jobid`, and `metadata`. Critically, it directly uses the content of the `parts` list without any validation.
    - The `Part` context manager is used in the example in `README.md` to process each part:
    ```python
    with Part(jobid, partid):
        # The context block
        process_url(message['url'])
    ```
    - The `Part` context manager in `/code/watchbot_progress/main.py` itself does not interact with or validate the content of `message['url']`. It is designed to manage the progress tracking aspect of the job.
    - The responsibility of processing the `message['url']` and ensuring its security is entirely delegated to the user-implemented `process_url` function, which is outside the scope of the `watchbot-progress-py` library.
    - **Visualization:**
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
- Security Test Case:
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