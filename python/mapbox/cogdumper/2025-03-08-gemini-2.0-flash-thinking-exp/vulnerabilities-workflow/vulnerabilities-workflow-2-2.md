### Vulnerability List

- Vulnerability Name: HTTP Path Traversal
- Description:
    1. The `cogdumper http` command allows users to specify the server, path, and resource for accessing Cloud Optimized GeoTIFF files over HTTP.
    2. The application constructs the URL by directly concatenating the provided `--server`, `--path`, and `--resource` parameters without proper sanitization.
    3. An attacker can manipulate the `--path` parameter to include path traversal sequences like `../`.
    4. When the application makes an HTTP request, the server interprets the path traversal sequences, potentially allowing access to files and directories outside the intended scope on the HTTP server.
    5. For example, an attacker could use a path like `../../../../etc/passwd` to attempt to read the `/etc/passwd` file from the server.
- Impact:
    - An attacker can read arbitrary files from the HTTP server.
    - This could lead to the disclosure of sensitive information, such as configuration files, application source code, or user data, depending on the server's file system permissions and configuration.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The application does not perform any sanitization or validation of the `--path` or `--resource` parameters to prevent path traversal.
- Missing Mitigations:
    - Implement input sanitization for the `--path` and `--resource` parameters in the `cogdumper http` command.
    - Validate the input paths to ensure they do not contain path traversal sequences (e.g., `../`).
    - Consider using secure URL construction methods that properly handle path segments and prevent traversal.
- Preconditions:
    - The target HTTP server must be vulnerable to path traversal, meaning it serves files based on user-provided paths without sufficient security checks.
    - The attacker must have network access to the HTTP server.
    - The COGDumper tool must be used with the `http` command.
- Source Code Analysis:
    1. File: `/code/cogdumper/scripts/cli.py`
    2. Command `http` is defined, taking `--server`, `--path`, and `--resource` options.
    3. No sanitization is applied to `--path` and `--resource` options.
    ```python
    @cogdumper.command(help='COGDumper cli for web hosted dataset.')
    @click.option('--server', required=True, help='server e.g. http://localhost:8080')
    @click.option('--path', default=None, help='server path')
    @click.option('--resource', help='server resource')
    ...
    def http(server, path, resource, output, xyz, verbose):
        ...
        reader = HTTPReader(server, path, resource)
        ...
    ```
    4. File: `/code/cogdumper/httpdumper.py`
    5. In `HTTPReader.__init__`, the URL is constructed using f-strings by directly concatenating `server`, `path`, and `resource`.
    ```python
    class Reader(AbstractReader):
        """Wraps the remote COG."""

        def __init__(self, server, path, resource, user=None, password=None):
            self.server = server
            self.path = path
            self.resource = resource
            if path:
                self.url = f'{server}/{path}/{resource}'
            else:
                self.url = f'{server}/{resource}'
            ...
    ```
    6. This direct concatenation allows path traversal characters in `--path` or `--resource` to be passed to the HTTP server without any checks.

- Security Test Case:
    1. Step 1: Set up a simple HTTP server (e.g., using Python's `http.server` module) serving files from a directory.
    ```bash
    mkdir test_server_root
    echo "This is sensitive data" > test_server_root/sensitive_data.txt
    python -m http.server 8000 --directory test_server_root
    ```
    2. Step 2: Run the `cogdumper http` command with a path traversal payload in the `--path` parameter to attempt to access `sensitive_data.txt` which is located in `test_server_root`.
    ```bash
    cogdumper http --server http://localhost:8000 --path "../sensitive_data.txt" --resource dummy.tif --xyz 0 0 0 --output output.txt
    ```
    3. Step 3: Examine the `output.txt` file.
    4. Expected Result: If the path traversal is successful, `output.txt` will contain the content of `sensitive_data.txt`, which is "This is sensitive data". This confirms the path traversal vulnerability.