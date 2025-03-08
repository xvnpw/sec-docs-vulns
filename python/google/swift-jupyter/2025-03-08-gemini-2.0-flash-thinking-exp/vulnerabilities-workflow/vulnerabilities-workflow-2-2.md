### Vulnerability List

- Vulnerability Name: Unrestricted System Command Execution via `%system` directive
- Description: The Swift-Jupyter kernel allows execution of arbitrary system commands through the `%system` directive within a notebook cell. When a cell starting with `%system` is executed, the kernel directly passes the rest of the line to `subprocess.Popen` with `shell=True`. This allows a malicious user to inject and execute arbitrary shell commands on the server running the Jupyter Notebook.
- Impact: Complete compromise of the user's machine running the Jupyter Notebook. An attacker can execute any command with the privileges of the Jupyter kernel process, potentially leading to data theft, malware installation, system takeover, or denial of service.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations: None. The code directly executes the provided command.
- Missing Mitigations: The `%system` directive should be removed entirely. If system command execution is absolutely necessary, it must be re-implemented with extreme security measures, such as:
    - Removing `shell=True` from `subprocess.Popen`.
    - Implementing a strict whitelist of allowed commands and arguments.
    - Carefully sanitizing and validating any user-provided input before executing commands.
    However, even with these mitigations, allowing arbitrary system command execution from a notebook is inherently risky and generally discouraged.
- Preconditions:
    - The victim must open and execute a malicious Jupyter Notebook containing a cell with the `%system` directive.
    - The Swift-Jupyter kernel must be installed and running.
- Source Code Analysis:
    - File: `/code/swift_kernel.py`
    - Function: `_process_system_command_line`
    ```python
    def _process_system_command_line(self, line):
        system_match = re.match(r'^\s*%system (.*)$', line)
        if system_match is None:
            return line

        if hasattr(self, 'debugger'):
            raise PackageInstallException(
                    'System commands can only run in the first cell.')

        rest_of_line = system_match.group(1)
        process = subprocess.Popen(rest_of_line,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            shell=True) # Vulnerable code: shell=True allows command injection
        process.wait()
        command_result = process.stdout.read().decode('utf-8')
        self.send_response(self.iopub_socket, 'stream', {
            'name': 'stdout',
            'text': '%s' % command_result
        })
        return ''
    ```
    - The `subprocess.Popen` call with `shell=True` directly executes the user-provided input as a shell command, without any sanitization or validation.
- Security Test Case:
    1. Setup: Install Swift-Jupyter and run a Jupyter Notebook server with the Swift kernel.
    2. Create a new Swift notebook.
    3. In a cell, enter the following code: `%system touch /tmp/swift_jupyter_pwned`
    4. Execute the cell.
    5. Verification: Check if the file `/tmp/swift_jupyter_pwned` has been created on the server's filesystem. If the file exists, the vulnerability is confirmed.
    6. Advanced Test: In a cell, enter: `%system bash -c "echo 'Exploited!' > /tmp/swift_jupyter_pwned_content"` and execute. Verify that `/tmp/swift_jupyter_pwned_content` contains "Exploited!".

- Vulnerability Name: Local File Inclusion via `%include` directive
- Description: The Swift-Jupyter kernel's `%include` directive allows including code from local files specified by the user in a notebook cell. Although the implementation restricts file inclusion to predefined paths (the directory of `swift_kernel.py` and the current working directory), it lacks proper sanitization of the filename provided in the `%include` directive. This could potentially allow path traversal attacks, enabling an attacker to read files outside the intended directories.
- Impact: Information Disclosure. An attacker could potentially read arbitrary files from the server's filesystem that the Jupyter kernel process has access to, by crafting a malicious notebook with path traversal sequences in the `%include` directive. This could lead to the exposure of sensitive data, configuration files, or source code.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations: The `%include` directive limits the search for include files to two directories: the script's directory and the current working directory.
- Missing Mitigations: The filename within the `%include` directive is not sanitized to prevent path traversal attempts. Input validation should be implemented to reject filenames containing path traversal sequences like `../`.
- Preconditions:
    - The victim must open and execute a malicious Jupyter Notebook containing a cell with a crafted `%include` directive.
    - The attacker needs to know or guess the path to a file they want to access on the server, relative to the Jupyter Notebook's working directory or the kernel script's directory.
- Source Code Analysis:
    - File: `/code/swift_kernel.py`
    - Function: `_read_include`
    ```python
    def _read_include(self, line_index, rest_of_line):
        name_match = re.match(r'^\s*"([^"]+)"\s*$', rest_of_line)
        if name_match is None:
            # ...
        name = name_match.group(1)

        include_paths = [
            os.path.dirname(os.path.realpath(sys.argv[0])),
            os.path.realpath("."),
        ]

        code = None
        for include_path in include_paths:
            try:
                with open(os.path.join(include_path, name), 'r') as f: # Vulnerable code: No sanitization of 'name' for path traversal
                    code = f.read()
            except IOError:
                continue
        # ...
    ```
    - The code uses `os.path.join` to construct the full file path, but it does not sanitize the `name` variable. If `name` contains `../`, `os.path.join` will resolve the path, potentially leading to directory traversal.
- Security Test Case:
    1. Setup: Install Swift-Jupyter and run a Jupyter Notebook server with the Swift kernel. Create a directory `secret_data` in the Jupyter server's home directory, and inside it create a file `sensitive.txt` with some secret content. Ensure the Jupyter process has read access to this file.
    2. Create a new Swift notebook in the Jupyter server's home directory.
    3. In a cell, enter the following code: `%include "../secret_data/sensitive.txt"`
    4. Execute the cell.
    5. Verification: Check the output of the cell. If the output contains the content of `sensitive.txt`, the local file inclusion vulnerability is confirmed.