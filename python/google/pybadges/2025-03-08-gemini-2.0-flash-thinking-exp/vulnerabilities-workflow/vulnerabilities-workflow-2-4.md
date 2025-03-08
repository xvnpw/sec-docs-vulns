### Vulnerability List for pybadges Project

* Vulnerability Name: Server-Side Request Forgery (SSRF) in Logo URL Parameter

* Description:
    1. The pybadges library allows users to specify a URL for the logo parameter, which is used to embed an image in the generated badge.
    2. When the `--embed-logo` option is used or when the library is used in a server context that accepts user-provided logo URLs, the `_embed_image` function in `pybadges/__init__.py` fetches the image from the provided URL using the `requests` library.
    3. This function does not perform any validation or sanitization of the provided URL.
    4. An attacker can provide a malicious URL pointing to internal resources or external services that are not intended to be publicly accessible.
    5. If a server is deployed using pybadges and exposes the `logo` parameter to user input, an attacker can exploit this SSRF vulnerability by providing a malicious URL.
    6. This can lead to information disclosure by accessing internal resources, or trigger unintended actions on other servers if the attacker crafts specific URLs.

* Impact:
    - **Information Disclosure:** An attacker could potentially access sensitive information from internal resources that are not publicly accessible, such as configuration files, internal services, or monitoring dashboards.
    - **Internal Network Scanning:** The attacker can use the vulnerable server to scan internal networks and identify open ports and services.
    - **Denial of Service (Indirect):** In some scenarios, an attacker might be able to overload internal services or external websites by making the vulnerable server send a large number of requests to them. Although this is classified as SSRF, and not directly a DoS of the pybadges service itself.
    - **Data Exfiltration:** In more complex scenarios, depending on the internal network configuration, an attacker might be able to exfiltrate data from internal systems by sending it back through the vulnerable server to an attacker-controlled external server.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - None. The code directly fetches and embeds images from user-provided URLs without any validation or sanitization.

* Missing Mitigations:
    - **URL Validation and Sanitization:** Implement strict validation and sanitization of the logo URL to ensure it points to a safe and expected resource. This could include:
        - Whitelisting allowed URL schemes (e.g., only `http` and `https`).
        - Blacklisting or whitelisting domains or IP addresses.
        - Checking for private IP address ranges to prevent access to internal networks.
    - **Content-Type Validation:** Verify that the Content-Type of the fetched resource is indeed an image type before embedding it. This is partially done in `_embed_image` but can be made stricter.
    - **Error Handling and Logging:** Implement proper error handling for URL fetching and embedding, and log potential SSRF attempts for monitoring and incident response.
    - **Disable URL fetching for logo by default:** Consider making URL fetching for logos an opt-in feature, or provide a configuration option to disable it completely in server deployments.
    - **Input validation in server example:** In `server-example/app.py`, implement input validation to restrict the allowed values for the `logo` parameter, or remove it entirely from user-controlled parameters if SSRF is a concern.

* Preconditions:
    - The `pybadges` library is used in a server application or command-line interface where users can control the `logo` parameter, especially when the `--embed-logo` option is enabled or implicitly used in server-side embedding.
    - The server or command-line tool using pybadges has network access to internal resources or external services that the attacker wants to target.

* Source Code Analysis:

    1. **Entry Point:** The vulnerability is triggered when the `badge()` function in `pybadges/__init__.py` is called with a `logo` parameter that is a URL and `embed_logo` is True (or implicitly true in server context).

    2. **`badge()` function:**
       ```python
       def badge(..., logo: Optional[str] = None, embed_logo: bool = False, ...):
           ...
           if logo and embed_logo:
               logo = _embed_image(logo)
           ...
       ```
       - This part of the `badge()` function checks if a `logo` URL is provided and if `embed_logo` is True. If both conditions are met, it calls the `_embed_image()` function to process the logo URL.

    3. **`_embed_image()` function:**
       ```python
       def _embed_image(url: str) -> str:
           parsed_url = urllib.parse.urlparse(url)

           if parsed_url.scheme == 'data':
               return url
           elif parsed_url.scheme.startswith('http'):
               r = requests.get(url) # Vulnerable line: No URL validation
               r.raise_for_status()
               ...
           ...
       ```
       - The `_embed_image()` function takes the `url` as input.
       - It checks if the URL is a data URL, and if so, returns it directly.
       - If the URL scheme starts with 'http', it uses `requests.get(url)` to fetch the content from the URL. **Crucially, there is no URL validation or sanitization before making the request.**
       - `r.raise_for_status()` checks for HTTP errors, but this doesn't prevent SSRF.
       - The function then proceeds to check the `Content-Type` header and encode the image data.

    4. **Vulnerability Flow:**
       - User provides a malicious URL as the `logo` parameter (e.g., `http://internal.example.com/sensitive-data`).
       - The `badge()` function calls `_embed_image()` with this malicious URL.
       - `_embed_image()` uses `requests.get()` to fetch content from `http://internal.example.com/sensitive-data` *from the server's perspective*.
       - If `http://internal.example.com/sensitive-data` is an accessible internal resource, its content will be fetched and potentially embedded into the badge (or an error might occur if it's not an image, but the SSRF request is still made).
       - The attacker can observe the response time or error messages to infer information about internal resources, or potentially retrieve the content of these resources if they are served as images or if error messages leak sensitive data.

    **Visualization:**

    ```
    Attacker --> pybadges server --> _embed_image("http://internal.example.com/sensitive-data") --> requests.get("http://internal.example.com/sensitive-data") --> Internal Server
    ```

* Security Test Case:

    1. **Setup:**
        - Deploy the `server-example/app.py` application on a test server. Ensure the server has network access to a resource that is *not* publicly accessible but should be accessible from within the server's network (for example, an internal-only website or service, or even a local file if you can simulate file access in your test environment - though testing against an actual network resource is more realistic for SSRF). For simplicity, in this test case, we will use a request to a local port to simulate an internal service. You will need to have a service running on localhost port 8080 that returns a predictable response. For testing purposes, you can use a simple `netcat` listener or a basic HTTP server on port 8080.

    2. **Craft Malicious URL:**
        - As an attacker, craft a malicious URL for the `logo` parameter that points to the internal resource you want to access. For example, `http://localhost:8080/test-internal-resource`.

    3. **Send HTTP Request to Vulnerable Server:**
        - Send an HTTP GET request to the deployed `server-example` application's `/img` endpoint, including the malicious URL in the `logo` query parameter. For example:
          ```
          GET /img?left_text=test&right_text=ssrf&logo=http://localhost:8080/test-internal-resource HTTP/1.1
          Host: <your-server-ip>:5000
          ```

    4. **Analyze the Response:**
        - Examine the response from the server.
        - If the SSRF is successful, the server will attempt to fetch content from `http://localhost:8080/test-internal-resource`.
        - If the service on port 8080 responds with an image, the badge will be generated with the embedded image (though likely an error if port 8080 does not serve an image). If the service on port 8080 responds with text or HTML, the `_embed_image` function might raise an exception if it cannot determine the image type, but the SSRF attempt is still successful.
        - To confirm SSRF, monitor the requests received by the service running on port 8080. You should see an incoming request originating from the pybadges server.
        - You can also try to access other internal resources or services by changing the malicious URL, and observe the server's behavior and any potential information leakage or errors in the badge generation.

    5. **Expected Outcome:**
        - The test should demonstrate that the pybadges server makes a request to the attacker-specified internal URL (`http://localhost:8080/test-internal-resource` in this example). This confirms the SSRF vulnerability. The generated badge itself might be broken or contain error messages if the target resource is not an image or returns an unexpected response, but the key is the outgoing request from the server to the internal resource.

This vulnerability report details the SSRF vulnerability in the pybadges project, providing a comprehensive analysis, mitigation strategies, and a test case to verify its existence.