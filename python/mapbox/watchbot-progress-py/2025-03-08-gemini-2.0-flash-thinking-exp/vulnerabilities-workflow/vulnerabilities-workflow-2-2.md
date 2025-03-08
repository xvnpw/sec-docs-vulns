- Vulnerability Name: Server-Side Request Forgery (SSRF) via Unvalidated URLs in Parts
- Description:
    - An attacker can inject malicious URLs into the `parts` dictionaries when calling the `create_job` function.
    - If the user's processing code, which runs within the `Part` context manager, naively uses the `url` from the `message` (derived from `parts`) without proper validation, it can lead to Server-Side Request Forgery (SSRF).
    - For example, if the processing code fetches content from the URL specified in `message['url']` without sanitization, an attacker can control this URL to point to internal resources or external malicious sites.
    - When the processing code executes, it will make a request to the attacker-controlled URL from the server's perspective, potentially exposing internal services or data, or performing actions on behalf of the server.
- Impact:
    - An attacker can potentially scan internal network resources that are not publicly accessible.
    - Access sensitive data from internal services, such as configuration files or internal APIs.
    - In some cases, depending on the internal services and how URLs are processed, it might be possible to achieve remote code execution or other more severe attacks by interacting with vulnerable internal services.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The library itself does not implement any input validation or sanitization for the `parts` data.
    - The README.md mentions that "if parts contain URLs processed without sanitization" SSRF is possible, which is more of a warning in documentation than a mitigation.
- Missing Mitigations:
    - Input validation: The `watchbot-progress-py` library should provide mechanisms or guidelines for validating the `parts` data, especially URLs, before they are processed. This could include:
        -  Documentation strongly recommending URL validation and sanitization in user's processing code.
        -  Potentially utility functions within the library to assist with common URL validation tasks.
- Preconditions:
    - The application using `watchbot-progress-py` must process URLs or interact with external resources based on data provided in the `parts` dictionaries.
    - The processing code must naively use URLs from the `parts` without implementing proper validation or sanitization.
- Source Code Analysis:
    - `watchbot_progress/main.py`:
        - The `create_job` function accepts a `parts` argument, which is a list of dictionaries.
        - It iterates through the `parts`, adds `partid`, `jobid`, and `metadata` to each part dictionary.
        - It sends SNS messages with these enriched part dictionaries.
        - The `Part` context manager is designed to be used in the processing code that receives these SNS messages.
        - The library itself does not validate or sanitize the contents of the `parts` dictionaries at any point. It simply passes the provided data through the SNS messaging system.
    - `README.md`:
        - The "Usage" section demonstrates how to create `parts` dictionaries, and one example shows parts containing a `url` key:
        ```python
        parts = [
            {'url': 'https://a.com'},
            {'url': 'https://b.com'},
            {'url': 'https://c.com'}]
        ```
        - The example processing code in README.md shows how to access the `url` from the message and pass it to `process_url`:
        ```python
        with Part(jobid, partid):
            # The context block
            process_url(message['url'])
        ```
        - The responsibility of validating and sanitizing `message['url']` is entirely left to the user-implemented `process_url` function. If this function naively processes the URL without validation, SSRF is possible.
- Security Test Case:
    1. **Setup:**
        - Deploy an instance of an application that uses `watchbot-progress-py` to manage map-reduce jobs.
        - Ensure this application processes the `url` field from the `parts` data within the `Part` context manager by making HTTP requests to the provided URL. For example, the processing code could use the `requests` library to fetch the content of `message['url']`.
        - Assume the application is set up to receive SNS messages triggered by `watchbot-progress-py`.
    2. **Craft Malicious Input:**
        - Prepare a malicious `parts` list that includes a part dictionary with a `url` pointing to an internal resource that should not be directly accessible from the outside. For example:
        ```python
        malicious_parts = [
            {'url': 'http://localhost/internal-admin-panel'} # Points to a hypothetical internal admin panel
        ]
        ```
    3. **Trigger Job Creation:**
        - Use the application's interface or directly call the `create_job` function with the `malicious_parts` list.
        ```python
        from watchbot_progress import create_job
        jobid = create_job(malicious_parts)
        ```
    4. **Observe Server-Side Request:**
        - Monitor the network traffic or logs of the application server.
        - Observe if the application server makes an HTTP request to `http://localhost/internal-admin-panel` (or the internal URL you specified) when processing the part created from `malicious_parts`.
    5. **Verification:**
        - If the server makes a request to the internal resource, it confirms the SSRF vulnerability. An attacker could potentially use this to access internal services, scan the internal network, or potentially exploit vulnerabilities in those internal services.
        - The successful request to the internal resource demonstrates that the application naively processes URLs from the `parts` without proper validation, leading to SSRF.