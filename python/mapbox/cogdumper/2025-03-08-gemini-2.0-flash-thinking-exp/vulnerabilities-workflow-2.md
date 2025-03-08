## Vulnerability Report

### Path Traversal in File Command

- **Vulnerability Name:** Path Traversal in File Command

- **Description:**
    1. The `cogdumper file` command takes a `--file` argument, which specifies the path to the input Cloud Optimized GeoTIFF (COG) file.
    2. The `click.Path` type used for the `--file` argument in `cogdumper/scripts/cli.py` only checks if the file exists and is a file, but it does not prevent path traversal.
    3. An attacker can provide a maliciously crafted file path, such as an absolute path like `/etc/passwd` or a path with traversal sequences like `../../../../etc/passwd`, as the value for the `--file` argument.
    4. When the `cogdumper file` command is executed with this malicious path, the application will open and process the file located at the attacker-specified path.
    5. This allows an attacker to read arbitrary files from the local filesystem that the user running the `cogdumper` utility has access to.

- **Impact:**
    - **High:** An attacker can read sensitive files from the server's filesystem, potentially including configuration files, private keys, or user data. This could lead to unauthorized access to sensitive information or further exploitation of the system.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - `click.Path(exists=True, file_okay=True, dir_okay=False)` is used for the `--file` argument. This ensures that the provided path exists and is a file, but it does not prevent path traversal. This mitigation is located in `cogdumper/scripts/cli.py` in the `file` function definition.

- **Missing Mitigations:**
    - **Path Sanitization:** The application should sanitize the input file path to remove or neutralize path traversal sequences (e.g., `../`, `./`).
    - **Restricting File Access:** Ideally, the application should restrict file access to a specific allowed directory. However, given the tool's purpose, this might not be feasible or desired. If restricting access is not possible, then proper warnings and documentation about the security implications should be provided.
    - **Principle of Least Privilege:** Users should be advised to run the `cogdumper` utility with minimal necessary privileges to limit the impact of potential path traversal vulnerabilities.

- **Preconditions:**
    - The attacker needs to have the `cogdumper` utility installed and be able to execute the `cogdumper file` command.
    - The attacker needs to know or guess the path of a file they want to access on the local filesystem.
    - The user running the `cogdumper` utility must have read permissions to the target file.

- **Source Code Analysis:**
    1. **`cogdumper/scripts/cli.py` - `file` command:**
        ```python
        @cogdumper.command(help='COGDumper cli for local dataset.')
        @click.option('--file', required=True, type=click.Path(exists=True, file_okay=True, dir_okay=False), help='input file')
        def file(file, output, xyz, verbose):
            """Read local dataset."""
            with open(file, 'rb') as src: # Vulnerable line
                reader = FileReader(src)
                cog = COGTiff(reader.read)
                # ... rest of the code ...
        ```
        - The `file` function in `cli.py` defines the `file` subcommand.
        - It uses `click.option` to define the `--file` argument.
        - `type=click.Path(exists=True, file_okay=True, dir_okay=False)` is used to validate the path. This only checks if the path exists and is a file.
        - `open(file, 'rb')` opens the file specified by the `--file` argument directly without any further path sanitization or validation against path traversal.
        - The file handle `src` is then passed to `FileReader`.

    2. **`cogdumper/filedumper.py` - `FileReader`:**
        ```python
        class Reader(AbstractReader):
            """Wraps the remote COG."""

            def __init__(self, handle):
                self._handle = handle # File handle is stored

            def read(self, offset, length):
                start = offset
                stop = offset + length - 1
                self._handle.seek(offset) # Seek operation on provided handle
                return self._handle.read(length) # Read operation on provided handle
        ```
        - The `FileReader` class takes a file handle in its constructor and stores it in `self._handle`.
        - The `read` method operates directly on this file handle using `seek` and `read` without any path-related operations.
        - The vulnerability lies in the fact that the `file` path is not validated for path traversal before opening the file handle in `cli.py`. `FileReader` then operates on this potentially malicious file handle.

    **Visualization:**

    ```
    Attacker Input (--file argument) --> cogdumper file command (cli.py) --> click.Path (exists=True, file_okay=True) --> open(file, 'rb') --> FileReader (filedumper.py) --> File System Access (Potentially Traversed Path)
    ```

- **Security Test Case:**
    1. **Prepare Test Environment:**
        - Ensure you have `cogdumper` installed in a test environment.
        - Create a sensitive file in your test environment that the user running `cogdumper` can access, for example, a file named `sensitive_data.txt` in the `/tmp` directory with content "This is sensitive information.".
        - Create a dummy COG file (can be an empty file with `.tif` extension) in the current directory, for example `dummy.tif`. This is needed to satisfy the `--file` argument's requirement of a file path, even though we will be traversing to access another file.

    2. **Execute `cogdumper file` command with path traversal:**
        ```bash
        cogdumper file --file "/tmp/sensitive_data.txt" --xyz 0 0 0
        ```
        or using relative path traversal if `cogdumper` is executed from a subdirectory:
        ```bash
        cogdumper file --file "../../../tmp/sensitive_data.txt" --xyz 0 0 0
        ```
        (Adjust the number of `../` based on your current working directory and the location of `/tmp/sensitive_data.txt`)

    3. **Verify Vulnerability:**
        - After executing the command, check the output file generated (e.g., `file_0_0_0.txt` or similar based on mime type guessing).
        - Examine the content of the output file. If the path traversal is successful, the output file should contain the content of `/tmp/sensitive_data.txt` (i.e., "This is sensitive information.").
        - If the output file contains the content of `sensitive_data.txt`, it confirms that the path traversal vulnerability exists, and the attacker was able to read the contents of an arbitrary file using the `cogdumper file` command.

---

### HTTP Path Traversal

- **Vulnerability Name:** HTTP Path Traversal

- **Description:**
    1. The `cogdumper http` command allows users to specify the server, path, and resource for accessing Cloud Optimized GeoTIFF files over HTTP.
    2. The application constructs the URL by directly concatenating the provided `--server`, `--path`, and `--resource` parameters without proper sanitization.
    3. An attacker can manipulate the `--path` parameter to include path traversal sequences like `../`.
    4. When the application makes an HTTP request, the server interprets the path traversal sequences, potentially allowing access to files and directories outside the intended scope on the HTTP server.
    5. For example, an attacker could use a path like `../../../../etc/passwd` to attempt to read the `/etc/passwd` file from the server.

- **Impact:**
    - **High:** An attacker can read arbitrary files from the HTTP server.
    - This could lead to the disclosure of sensitive information, such as configuration files, application source code, or user data, depending on the server's file system permissions and configuration.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - None. The application does not perform any sanitization or validation of the `--path` or `--resource` parameters to prevent path traversal.

- **Missing Mitigations:**
    - Implement input sanitization for the `--path` and `--resource` parameters in the `cogdumper http` command.
    - Validate the input paths to ensure they do not contain path traversal sequences (e.g., `../`).
    - Consider using secure URL construction methods that properly handle path segments and prevent traversal.

- **Preconditions:**
    - The target HTTP server must be vulnerable to path traversal, meaning it serves files based on user-provided paths without sufficient security checks.
    - The attacker must have network access to the HTTP server.
    - The COGDumper tool must be used with the `http` command.

- **Source Code Analysis:**
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

- **Security Test Case:**
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