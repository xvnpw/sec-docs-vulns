### Vulnerability List

- Vulnerability Name: Lack of Input Validation in File Upload API
- Description: The `post_one_zip` API endpoint in the attacker component allows uploading ZIP files without explicitly validating the file content beyond basic checks like file type. An attacker could upload a ZIP archive containing excessively large files or a large number of files, potentially overwhelming the processing pipeline and leading to resource exhaustion or unexpected behavior. While this might be considered a denial-of-service vulnerability, the competition context focuses on evasion, and large file uploads could be a method to slow down or disrupt the detection process, indirectly aiding evasion attempts.
- Impact: Potential resource exhaustion on the server side, potentially slowing down or disrupting the sample processing pipeline. In the context of the competition, this could hinder the defender's ability to analyze adversarial examples effectively.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations: Rate limiting on ZIP uploads (one ZIP per 60 minutes) is mentioned in `attacker/docs/post_one_zip.md`. This mitigates frequent uploads but doesn't prevent a single malicious large ZIP file from being uploaded.
- Missing Mitigations: Input validation on the size and number of files within the uploaded ZIP archive. Implementing checks to limit the total size of the ZIP, the maximum size of individual files within the ZIP, and the maximum number of files within the ZIP.
- Preconditions: An attacker needs a valid API token, obtainable by registering on the competition website ([https://mlsec.io](https://mlsec.io/myuser/)).
- Source Code Analysis:
    1. The file `/code/attacker/docs/post_one_zip.md` describes the `post_one_zip` API endpoint.
    2. It states that "only one ZIP file may be uploaded every 60 minutes," indicating rate limiting.
    3. The documentation specifies parameters: `api_token`, `name`, and `path`. The `path` parameter indicates the local path of the ZIP file to upload.
    4. There is no mention in the documentation or provided code snippets about validating the content of the ZIP file itself, such as size limits or file count limits.
    5. The example curl command shows how to upload a ZIP file using the API, further demonstrating the lack of explicit size or content validation in the documented API usage.
    ```
    curl -X POST "https://api.mlsec.io/api/post_one_zip/new/?url=%2Fzipfile%2F&api_token=0123456789abcdef0123456789abcdef" --form "name=my_label" --form path=\@test_mlsc.zip
    ```
- Security Test Case:
    1. **Precondition:** Obtain an API token from [https://mlsec.io/myuser/](https://mlsec.io/myuser/).
    2. **Step 1:** Create a ZIP archive (`large_zip.zip`) containing a single very large file (e.g., several GB of random data) or a very large number of small files (e.g., thousands of empty files).
    3. **Step 2:** Use `curl` to upload this ZIP archive using the `post_one_zip` API endpoint, replacing `<API_TOKEN>` with the obtained API token and adjusting the `path` to point to `large_zip.zip`.
    ```bash
    curl -X POST "https://api.mlsec.io/api/post_one_zip/new/?url=%2Fzipfile%2F&api_token=<API_TOKEN>" --form "name=large_zip_test" --form path=@large_zip.zip
    ```
    4. **Step 3:** Monitor the server's resource usage (CPU, memory, disk I/O) after uploading the large ZIP file. Observe if there is a significant increase in resource consumption or a slowdown in processing other requests.
    5. **Step 4:** Check the processing status of the uploaded ZIP file using the `get_one_zip` API endpoint (`attacker/docs/get_one_zip.md`) to see if the system is able to handle the large file or if it encounters errors or timeouts.
    6. **Expected Result:** The server might experience increased resource usage and potentially slower processing of samples. In a more severe case, the system might become unresponsive or crash due to resource exhaustion. The `get_one_zip` API might show a prolonged "processing" status or error messages related to processing the large ZIP file.

- Vulnerability Name: Reliance on Client-Side Rate Limiting for ZIP Uploads
- Description: The documentation for `post_one_zip` API (`/code/attacker/docs/post_one_zip.md`) mentions a rate limit of "only one ZIP file may be uploaded every 60 minutes". However, rate limiting enforced solely on the client-side (or merely documented without server-side enforcement) can be easily bypassed by a malicious attacker. If the rate limiting is not properly implemented and enforced on the server side, an attacker could potentially bypass it and upload ZIP files more frequently than intended, potentially leading to resource exhaustion or other unintended consequences.
- Impact: Circumventing intended rate limits, potentially leading to increased load on the server, resource exhaustion, or abuse of the service.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations: Documentation mentions a 60-minute rate limit. It is unclear from the provided files if this rate limit is actually enforced on the server side.
- Missing Mitigations: Server-side enforcement of the rate limit for ZIP uploads. This should be implemented on the API endpoint handling `post_one_zip` requests to ensure that regardless of client behavior, the rate limit is consistently applied.
- Preconditions: An attacker needs a valid API token.
- Source Code Analysis:
    1. The file `/code/attacker/docs/post_one_zip.md` states: "note that only one ZIP file may be uploaded every 60 minutes."
    2. No code snippets are provided for the server-side API implementation, so it's impossible to verify if server-side rate limiting is implemented based on the provided files alone.
    3. The documentation itself only acts as a client-side guideline, not a guarantee of server-side enforcement.
- Security Test Case:
    1. **Precondition:** Obtain a valid API token.
    2. **Step 1:** Using a script or tool (like `curl` in a loop), attempt to send multiple `post_one_zip` requests in rapid succession, within a 60-minute window. For example, try to upload two ZIP files within a minute.
    3. **Step 2:** Monitor the server's response to these requests. Check if the server rejects requests exceeding the rate limit (e.g., returns a `429 Too Many Requests` error code) or if it processes all the uploads regardless of the documented rate limit.
    4. **Step 3:** Use the `get_all_sample` or `get_one_zip` API endpoints to verify if all uploaded ZIP files were successfully received and are being processed by the server, even if uploaded in rapid succession.
    5. **Expected Result:** If the rate limiting is only client-side or not properly enforced server-side, the attacker will be able to upload ZIP files more frequently than the documented 60-minute limit. The server will process these uploads without rejecting them due to rate limiting, demonstrating the vulnerability. If server-side rate limiting is in place, the server should reject subsequent upload requests within the 60-minute window, typically with a `429` error.