- Vulnerability Name: Unrestricted System Command Execution via `%system` directive
  - Description:
    1.  A user opens a Swift notebook using Swift-Jupyter kernel.
    2.  The user, or a malicious actor providing the notebook, includes a code cell that starts with the magic command `%system`.
    3.  Following the `%system` command, the user provides a shell command they wish to execute. For example: `%system touch /tmp/pwned`.
    4.  When this cell is executed, the Swift kernel's `_process_system_command_line` function in `swift_kernel.py` is invoked.
    5.  This function extracts the shell command from the cell's content without any sanitization or validation.
    6.  The extracted command is then directly passed to `subprocess.Popen` with `shell=True`. This is a critical point as `shell=True` allows for shell injection vulnerabilities.
    7.  `subprocess.Popen` executes the provided shell command on the operating system of the machine running the Jupyter kernel.
    8.  In the example `%system touch /tmp/pwned`, this command will create an empty file named `pwned` in the `/tmp/` directory of the server's filesystem.
    9.  A malicious actor can use this to execute arbitrary commands, potentially leading to data theft, system compromise, or denial of service.
  - Impact:
    - Arbitrary code execution on the server or user's machine running the Swift-Jupyter kernel.
    - Full compromise of the system is possible, including data exfiltration, installation of malware, and unauthorized access.
  - Vulnerability Rank: Critical
  - Currently Implemented Mitigations:
    - None. The code directly executes the command provided after the `%system` directive without any checks or sanitization.
  - Missing Mitigations:
    - **Remove the `%system` directive entirely**: The most secure mitigation is to remove this functionality as it provides a direct and easily exploitable avenue for code execution.
    - **Implement strict command whitelisting**: If system commands are absolutely necessary, implement a very strict whitelist of allowed commands. This is complex and still risky.
    - **Input sanitization**: If whitelisting is not feasible, rigorously sanitize the input to remove or escape any characters that could be used for command injection. However, this is also complex and prone to bypasses.
    - **Disable `shell=True`**: When using `subprocess.Popen`, set `shell=False` and pass the command as a list of arguments. This prevents shell injection but might break intended functionality of the `%system` directive.
  - Preconditions:
    - The Swift-Jupyter kernel is installed and running.
    - A user opens and executes a Swift notebook that is either crafted by a malicious attacker or unknowingly contains malicious code.
    - The malicious notebook must contain a code cell starting with the `%system` directive followed by a shell command.
  - Source Code Analysis:
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
  - Security Test Case:
    1.  Start a Jupyter Notebook server with the Swift kernel installed.
    2.  Create a new Swift notebook.
    3.  In a new code cell, type the following command: `%system touch /tmp/swift_jupyter_pwned`
    4.  Execute the code cell.
    5.  Access the server's shell (e.g., via SSH or through the Docker container's shell if running in Docker).
    6.  Check if the file `/tmp/swift_jupyter_pwned` exists. If the file is present, it confirms that the `%system` command was successfully executed, demonstrating arbitrary command execution vulnerability.
    7.  For a more impactful test, try: `%system bash -c "echo 'pwned' > /tmp/swift_jupyter_pwned.txt"` and verify the content of `/tmp/swift_jupyter_pwned.txt`.