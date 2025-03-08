## Combined Vulnerability List

Below is a combined list of identified vulnerabilities, with duplicates removed and formatted for clarity.

### 1. Path Traversal in `%include` Directive

- **Vulnerability Name:** Path Traversal in `%include` Directive
- **Description:**
  1. An attacker crafts a Swift notebook containing a cell with the `%include` directive.
  2. The `%include` directive is followed by a filename string.
  3. The attacker provides a filename string that includes path traversal sequences like `../` to navigate to directories outside the intended include paths.
  4. When the Swift kernel processes this cell, the `_read_include` function is called.
  5. The `_read_include` function attempts to open the specified file by joining the provided filename with predefined include paths, which include the directory of `swift_kernel.py` and the current working directory.
  6. Due to the lack of sanitization of the filename, the path traversal sequences are not removed or neutralized.
  7. The `open()` function resolves the path, potentially leading outside the intended directory.
  8. The content of the traversed file is then included in the preprocessed code and sent to the Swift interpreter.
  9. If the attacker includes a Swift file, it can lead to arbitrary code execution when the cell is executed. If a non-Swift file is included, it can lead to arbitrary file reading, as the content might be displayed as output or processed by subsequent Swift code if it's syntactically valid Swift.
- **Impact:**
  - High
  - Arbitrary File Reading: An attacker can read any file on the server's filesystem that the Swift kernel process has access to. This could include sensitive configuration files, source code, or data.
  - Arbitrary Code Execution: If the attacker includes a Swift file containing malicious code, they can execute arbitrary code on the server when the notebook cell is executed. This could lead to complete compromise of the server running the Jupyter kernel.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
  - None. The code directly uses the provided filename in the `%include` directive without any sanitization or validation against path traversal sequences.
- **Missing Mitigations:**
  - Path Sanitization: Implement sanitization of the filename in the `_read_include` function to remove path traversal sequences like `../` and `./`.
  - Path Validation: Validate that the resolved file path is within the intended directory or a set of allowed directories. Use secure path handling functions to resolve paths and check for canonicalization.
  - Restrict Include Paths: Limit the `include_paths` to only necessary directories and ensure the current working directory is not inadvertently exposed if not needed.
- **Preconditions:**
  - The attacker needs to be able to create and execute Swift notebooks on a Swift-Jupyter instance. This is typically the standard access for users of Jupyter environments.
- **Source Code Analysis:**
  1. In `swift_kernel.py`, the `_preprocess_line` function handles line-by-line preprocessing of the code cell.
  2. It uses the regex `r'^\s*%include (.*)$'` to identify lines starting with `%include`.
  ```python
  def _preprocess_line(self, line_index, line):
      include_match = re.match(r'^\s*%include (.*)$', line)
      if include_match is not None:
          return self._read_include(line_index, include_match.group(1))
      # ... other preprocessing directives ...
      return line
  ```
  3. If an `%include` directive is found, the `_read_include` function is called with the rest of the line (filename).
  ```python
  def _read_include(self, line_index, rest_of_line):
      name_match = re.match(r'^\s*"([^"]+)"\s*$', rest_of_line)
      if name_match is None:
          raise PreprocessorException(...)
      name = name_match.group(1)

      include_paths = [
          os.path.dirname(os.path.realpath(sys.argv[0])), # Directory of swift_kernel.py
          os.path.realpath("."), # Current working directory
      ]

      code = None
      for include_path in include_paths:
          try:
              with open(os.path.join(include_path, name), 'r') as f: # Vulnerable path joining
                  code = f.read()
          except IOError:
              continue
      if code is None:
          raise PreprocessorException(...)
      return '\n'.join([
          '#sourceLocation(file: "%s", line: 1)' % name,
          code,
          '#sourceLocation(file: "%s", line: %d)' % (
              self._file_name_for_source_location(), line_index + 1),
          ''
      ])
  ```
  4. The `_read_include` function extracts the filename `name` from the directive.
  5. It defines `include_paths` which include the directory of the `swift_kernel.py` script and the current working directory.
  6. Critically, it uses `os.path.join(include_path, name)` to construct the file path without any validation or sanitization of `name`. If `name` contains `../`, `os.path.join` will resolve the path, potentially leading to directory traversal.
  7. The `open()` function then opens the file at the potentially traversed path.
- **Security Test Case:**
  1. Set up a Swift-Jupyter environment as described in the `README.md`.
  2. Create a new Swift notebook in Jupyter.
  3. In the first cell of the notebook, enter the following code to attempt to read the `/etc/passwd` file (or any other accessible sensitive file on the server):
  ```swift
  %include "../../../../../../../../../../../../etc/passwd"
  ```
  4. Execute the cell.
  5. Observe the output of the cell. If the vulnerability is present, the content of the `/etc/passwd` file (or the target sensitive file) will be displayed as output in the notebook cell. This confirms arbitrary file reading.
  6. To test for potential code execution (if including Swift files from outside), create a simple Swift file with malicious code outside the intended directory, for example, in `/tmp/malicious.swift`:
  ```swift
  import Foundation
  print("Malicious code executed!")
  let task = Process()
  task.executableURL = URL(fileURLWithPath: "/bin/bash")
  task.arguments = ["-c", "touch /tmp/pwned"]
  try! task.run()
  task.waitUntilExit()
  ```
  7. In the Swift notebook, include this file using path traversal:
  ```swift
  %include "../../../../../tmp/malicious.swift"
  ```
  8. Execute this cell and subsequent cells.
  9. Check if the file `/tmp/pwned` is created, indicating code execution from the included file.

### 2. Unrestricted System Command Execution via `%system` directive

- **Vulnerability Name:** Unrestricted System Command Execution via `%system` directive
- **Description:**
  1.  A user opens a Swift notebook using Swift-Jupyter kernel.
  2.  The user, or a malicious actor providing the notebook, includes a code cell that starts with the magic command `%system`.
  3.  Following the `%system` command, the user provides a shell command they wish to execute. For example: `%system touch /tmp/pwned`.
  4.  When this cell is executed, the Swift kernel's `_process_system_command_line` function in `swift_kernel.py` is invoked.
  5.  This function extracts the shell command from the cell's content without any sanitization or validation.
  6.  The extracted command is then directly passed to `subprocess.Popen` with `shell=True`. This is a critical point as `shell=True` allows for shell injection vulnerabilities.
  7.  `subprocess.Popen` executes the provided shell command on the operating system of the machine running the Jupyter kernel.
  8.  In the example `%system touch /tmp/pwned`, this command will create an empty file named `pwned` in the `/tmp/` directory of the server's filesystem.
  9.  A malicious actor can use this to execute arbitrary commands, potentially leading to data theft, system compromise, or denial of service.
- **Impact:**
  - Critical
  - Arbitrary code execution on the server or user's machine running the Swift-Jupyter kernel.
  - Full compromise of the system is possible, including data exfiltration, installation of malware, and unauthorized access.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
  - None. The code directly executes the command provided after the `%system` directive without any checks or sanitization.
- **Missing Mitigations:**
  - **Remove the `%system` directive entirely**: The most secure mitigation is to remove this functionality as it provides a direct and easily exploitable avenue for code execution.
  - **Implement strict command whitelisting**: If system commands are absolutely necessary, implement a very strict whitelist of allowed commands. This is complex and still risky.
  - **Input sanitization**: If whitelisting is not feasible, rigorously sanitize the input to remove or escape any characters that could be used for command injection. However, this is also complex and prone to bypasses.
  - **Disable `shell=True`**: When using `subprocess.Popen`, set `shell=False` and pass the command as a list of arguments. This prevents shell injection but might break intended functionality of the `%system` directive.
- **Preconditions:**
  - The Swift-Jupyter kernel is installed and running.
  - A user opens and executes a Swift notebook that is either crafted by a malicious attacker or unknowingly contains malicious code.
  - The malicious notebook must contain a code cell starting with the `%system` directive followed by a shell command.
- **Source Code Analysis:**
  - File: `/code/swift_kernel.py`
  - Function: `_process_system_command_line(self, line)`
  - Code Snippet:
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
                            shell=True) # Vulnerable line: shell=True and unsanitized input 'rest_of_line'
        process.wait()
        command_result = process.stdout.read().decode('utf-8')
        self.send_response(self.iopub_socket, 'stream', {
            'name': 'stdout',
            'text': '%s' % command_result
        })
        return ''
    ```
  - Visualization:
    ```
    User Input (Notebook Cell with %system command) --> swift_kernel.py (_process_system_command_line) --> subprocess.Popen(shell=True, command) --> System Command Execution
    ```
  - Step-by-step explanation:
    1. The `_process_system_command_line` function is called when a cell starting with `%system` is encountered.
    2. The regular expression `r'^\s*%system (.*)$'` extracts the command from the line and stores it in `rest_of_line`.
    3. `subprocess.Popen(rest_of_line, shell=True, ...)` executes the command. The crucial part is `shell=True`, which interprets `rest_of_line` as a shell command.
    4. Because `rest_of_line` is directly derived from user input without sanitization, it is vulnerable to shell injection. An attacker can craft commands that execute arbitrary code by using shell metacharacters.
- **Security Test Case:**
  1.  Start a Jupyter Notebook server with the Swift kernel installed.
  2.  Create a new Swift notebook.
  3.  In a new code cell, type the following command: `%system touch /tmp/swift_jupyter_pwned`
  4.  Execute the code cell.
  5.  Access the server's shell (e.g., via SSH or through the Docker container's shell if running in Docker).
  6.  Check if the file `/tmp/swift_jupyter_pwned` exists. If the file is present, it confirms that the `%system` command was successfully executed, demonstrating arbitrary command execution vulnerability.
  7.  For a more impactful test, try: `%system bash -c "echo 'pwned' > /tmp/swift_jupyter_pwned.txt"` and verify the content of `/tmp/swift_jupyter_pwned.txt`.