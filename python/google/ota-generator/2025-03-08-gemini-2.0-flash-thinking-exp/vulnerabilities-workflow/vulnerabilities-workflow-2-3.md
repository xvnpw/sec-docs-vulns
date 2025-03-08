### Vulnerability 1

- Vulnerability Name: Path Traversal in File Upload (`web_server.py`)
- Description:
    1. An attacker sends a POST request to the `/file/<filename>` endpoint, where `<filename>` is maliciously crafted to include path traversal sequences like `../../`.
    2. The backend server, implemented in `web_server.py`, extracts the filename directly from the URL path without proper validation using `self.path[6:]`.
    3. The server then uses `os.path.join('target', self.path[6:])` to construct the file path. Due to the lack of sanitization, the path traversal sequences in the filename are preserved, allowing the constructed path to escape the intended 'target' directory.
    4. The server proceeds to open and write the content of the uploaded file to this potentially manipulated path. This enables an attacker to write files to arbitrary locations on the server's filesystem, outside the designated 'target' directory.
- Impact:
    - File Write: An attacker can write arbitrary files to the server's filesystem. This can lead to:
        - Overwriting critical system files, potentially causing system instability or denial of service.
        - Uploading malicious executable files or scripts, which could be executed by the server or other users, leading to remote code execution.
        - Modifying application configuration files to alter the application's behavior or gain unauthorized access.
    - Remote Code Execution: By strategically overwriting executable files or application-specific files, the attacker may be able to achieve remote code execution on the server.
- Vulnerability Rank: High
- Currently Implemented Mitigations: None. The application lacks any input sanitization or path validation to prevent path traversal during file uploads in `web_server.py`.
- Missing Mitigations:
    - Input Sanitization: Implement robust input sanitization on the filename extracted from the URL. This should involve removing or replacing path traversal characters such as `..`, `.` and directory separators (`/`, `\`).
    - Path Validation: After constructing the file path using `os.path.join`, validate that the resulting path is still within the intended 'target' directory. This can be achieved by using functions like `os.path.abspath` and checking if the absolute path starts with the absolute path of the 'target' directory.
    - Secure File Handling Practices: Employ secure file handling practices such as:
        - Using temporary files for uploads and moving them to the final destination after thorough validation.
        - Implementing access control mechanisms to restrict write access to sensitive directories.
- Preconditions:
    - The `web_server.py` server must be running and accessible over the network.
    - An attacker must be able to send POST requests to the `/file/<filename>` endpoint.
- Source Code Analysis:
    - File: `/code/web_server.py`
    - Function: `RequestHandler.do_POST`
    - Vulnerable Code Snippet:
      ```python
      elif self.path.startswith('/file'):
          file_name = os.path.join('target', self.path[6:])
          file_length = int(self.headers['Content-Length'])
          with open(file_name, 'wb') as output_file:
              # ... file writing operations ...
      ```
    - Analysis:
        - `self.path` contains the URL path requested by the client, including the filename part after `/file/`.
        - `self.path[6:]` extracts the filename directly from the URL, starting from the 7th character (index 6). This extracted filename is used without any sanitization or validation.
        - `os.path.join('target', self.path[6:])` constructs the file path by joining the 'target' directory with the user-provided filename. If the filename contains path traversal sequences (e.g., `../../../evil.txt`), `os.path.join` will resolve them, leading to a path outside the 'target' directory (e.g., `/evil.txt`).
        - `open(file_name, 'wb')` opens the file at the potentially traversed path in write binary mode (`wb`). This allows the attacker to write arbitrary content to the file at the manipulated location.
- Security Test Case:
    1. Prerequisites:
        - Ensure you have `curl` installed or a similar HTTP client.
        - Start the `web_server.py` server. You can run it using `python3 web_server.py &` from the `/code` directory.
        - Create a test file named `test.txt` with the content "This is a test file." in your current working directory (which should be outside the `/code` directory for clarity).
    2. Execute the exploit:
        - Run the following `curl` command to send a POST request to the `/file` endpoint with a path traversal filename:
          ```bash
          curl -X POST -H "Content-Type: multipart/form-data" -F "file=@test.txt;filename=../../../evil.txt" http://localhost:8000/file/../../../evil.txt
          ```
          - `-X POST`: Specifies the HTTP method as POST.
          - `-H "Content-Type: multipart/form-data"`: Sets the Content-Type header to multipart/form-data, which is typically used for file uploads via forms.
          - `-F "file=@test.txt;filename=../../../evil.txt"`:  This is the crucial part. It uses `curl`'s `-F` option to simulate a form file upload.
              - `file=@test.txt`:  Specifies that the content of the file `test.txt` will be uploaded.
              - `;filename=../../../evil.txt`: This part attempts to set the filename of the uploaded file to `../../../evil.txt`. This is the path traversal payload intended to write the file outside the 'target' directory.
          - `http://localhost:8000/file/../../../evil.txt`: The target URL of the POST request. The path `../../../evil.txt` is appended to `/file/` in the URL, mirroring the filename attempt in the `-F` parameter.
    3. Verify successful exploitation:
        - After executing the `curl` command, check for a file named `evil.txt` in the root directory of the server's filesystem (or the directory from where you started the `web_server.py` server, depending on the server's working directory and the path traversal).
        - Examine the content of the `evil.txt` file. It should contain the text "This is a test file.", which is the content of the `test.txt` file you uploaded.
    4. Expected result:
        - If the file `evil.txt` is created in the root directory (or outside the 'target' directory) and contains the expected content, this confirms the path traversal vulnerability. The attacker has successfully written a file outside of the intended upload directory due to the vulnerability.