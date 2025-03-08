### Vulnerability List

- Vulnerability Name: Path Traversal in File Upload
- Description:
    1. An attacker sends a POST request to the `/file/<filename>` endpoint on the web server (`web_server.py`).
    2. In the URL, the attacker crafts a malicious filename that includes path traversal sequences (e.g., `../../`). For example, the URL could be `/file/../../../../tmp/evil.txt`.
    3. The `web_server.py` backend, in the `do_POST` method, extracts the filename directly from the URL path without any sanitization or validation.
    4. The code uses `os.path.join('target', self.path[6:])` to construct the file path for saving the uploaded file. Due to the lack of sanitization, the path traversal sequences in the filename are preserved.
    5. The `open(file_name, 'wb')` function then creates and writes the uploaded file to the attacker-controlled path, potentially outside the intended 'target' directory.
- Impact:
    - Arbitrary File Write: An attacker can write files to arbitrary locations on the server's filesystem, limited by the permissions of the web server process.
    - Overwrite Sensitive Files: An attacker could overwrite critical system files, configuration files, or other sensitive data, leading to system instability or data corruption.
    - Malicious Code Injection: An attacker could upload and potentially execute malicious scripts (e.g., web shells) if the web server's environment allows for execution of uploaded files.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None in `web_server.py`.
    - `web_server_flask.py` uses a temporary file and the `TargetLib.new_build` function, which renames the file to a standardized name and location, thus mitigating this specific path traversal vulnerability. However, `web_server.py` remains vulnerable.
- Missing Mitigations:
    - Input Validation and Sanitization: The filename provided in the URL path (`self.path[6:]` in `web_server.py`) should be rigorously validated and sanitized.
    - Path Traversal Prevention: Implement checks to ensure that the constructed file path remains within the intended 'target' directory. Use secure path manipulation functions that prevent traversal outside of allowed paths.
    - Filename Restrictions: Restrict allowed characters in filenames to a safe subset and reject filenames containing path traversal sequences like `../` or absolute paths.
- Preconditions:
    - The `web_server.py` application must be running and accessible to the attacker.
    - The attacker needs to be able to send POST requests to the `/file/<filename>` endpoint.
- Source Code Analysis:
    - File: `/code/web_server.py`
    - Method: `RequestHandler.do_POST`

    ```python
    def do_POST(self):
        if self.path.startswith('/file'):
            file_name = os.path.join('target', self.path[6:]) # Vulnerable line
            file_length = int(self.headers['Content-Length'])
            with open(file_name, 'wb') as output_file: # File is opened at attacker controlled path
                # ... (file upload logic) ...
    ```

    - **Visualization:**

    ```
    Attacker URL: /file/../../../../tmp/evil.txt  -->  self.path = "/file/../../../../tmp/evil.txt"
    self.path[6:] = "../../../../tmp/evil.txt"
    file_name = os.path.join('target', "../../../../tmp/evil.txt")
              = 'target/../../../../tmp/evil.txt'
              = '../../../../tmp/evil.txt' (after path normalization)
    open(file_name, 'wb')  --> Opens file at '../../../../tmp/evil.txt' which resolves to /tmp/evil.txt
    ```

    - The `os.path.join` and subsequent `open` calls, without prior sanitization of `self.path[6:]`, allow path traversal. The `file_name` can resolve to a path outside the 'target' directory, enabling arbitrary file write.

- Security Test Case:
    1. Deploy and run the `web_server.py` application on a test server. Ensure the 'target' directory exists in the same directory as `web_server.py`.
    2. Open a terminal and use `curl` to send a POST request to the `/file` endpoint with a path traversal filename.

    ```bash
    curl -X POST \
         -H "Content-Type: multipart/form-data" \
         -F "file=@/dev/urandom" \
         "http://<server_ip>:8000/file/../../../../tmp/evil.txt"
    ```
    Replace `<server_ip>` with the actual IP address or hostname where `web_server.py` is running. `/dev/urandom` is used as a dummy file for upload content.

    3. After executing the `curl` command, log in to the test server using SSH or console access.
    4. Check if the file `evil.txt` has been created in the `/tmp` directory.

    ```bash
    ls -l /tmp/evil.txt
    ```

    5. If the file `/tmp/evil.txt` exists, it confirms the path traversal vulnerability, as the attacker was able to write a file outside the intended 'target' directory.