### Vulnerability 1: Command Injection via Malicious Symbol File Filenames

* Vulnerability Name: Command Injection via Malicious Symbol File Filenames
* Description:
    1. An attacker crafts a malicious symbol file (e.g., a modified `vmlinux`) such that when `addr2line` is run against it for a specific address, it returns a filename that contains command injection sequences, like `$(malicious_command)`.
    2. The attacker then crafts a malicious kernel bug report that includes a stack trace with addresses that, when symbolized using the malicious symbol file, trigger the vulnerable filename output from `addr2line`.
    3. A developer, intending to analyze a bug report, uses `symbolizer.py` with the `--linux` option pointing to the directory containing the malicious symbol file and pipes the malicious bug report to `symbolizer.py`'s stdin.
    4. `symbolizer.py` processes the bug report, calls `addr2line` with the malicious symbol file, and `addr2line` returns the malicious filename.
    5. `symbolizer.py` prints the symbolized stack trace, including the malicious filename, to the developer's terminal.
    6. If the developer copies and pastes this symbolized output into a terminal that performs command substitution (e.g., bash), the malicious command embedded in the filename gets executed on the developer's machine.
* Impact: Code execution on the developer's machine.
* Vulnerability Rank: High
* Currently Implemented Mitigations: None
* Missing Mitigations:
    - Input validation for filenames returned by `addr2line`. The script should sanitize or reject filenames that contain shell command injection sequences.
    - Documentation warning to developers about the risks of using symbolizer with untrusted symbol files and to be cautious when copying and pasting output from symbolizer, especially into a terminal.
* Preconditions:
    - Attacker can create a malicious symbol file or a malicious `addr2line` wrapper that makes `addr2line` return malicious filenames.
    - Developer uses `symbolizer.py` with the `--linux` option pointing to a directory containing the malicious symbol file or wrapper.
    - Developer copies and pastes the output of `symbolizer.py` into a terminal that performs command substitution.
* Source Code Analysis:
    - The `print_frame` function in `tools/symbolizer.py` is responsible for printing the symbolized stack frame.
    - It takes `fileline` as input, which is directly obtained from the output of `addr2line` through the `Symbolizer.process` method.
    - The `print_frame` function then prints this `fileline` without any sanitization:
    ```python
    def print_frame(self, inlined, precise, prefix, addr, func, fileline, body):
        ...
        if addr != None:
            print('%s[<%s>] %s%s %s' % (prefix, addr, precise, body, fileline))
        else:
            print('%s%s%s %s' % (prefix, precise, body, fileline))
    ```
    - There is no input validation or sanitization on `fileline` before printing. This allows for the injection of malicious content from `addr2line` output into the terminal output of `symbolizer.py`.
* Security Test Case:
    1. **Prepare Malicious addr2line wrapper:** Create a script named `addr2line` in a directory, say `malicious_tools/`. This script will always output a malicious filename.
       ```bash
       #!/bin/bash
       echo "??:0 $(echo vulnerable_command_executed)"
       echo "??"
       ```
       Make this script executable: `chmod +x malicious_tools/addr2line`.
    2. **Create Malicious Bug Report:** Create a text file `malicious_report.txt` with a stack frame address.
       ```
       [  123.456789]  [<ffffffff88888888>] some_function+0x10/0x20
       ```
    3. **Run symbolizer.py with Malicious Tools Path:** Run `symbolizer.py` with `--linux=./malicious_tools --strip=./malicious_tools < malicious_report.txt`. Ensure that the current directory is the `/code/tools` directory where `symbolizer.py` is located.
    4. **Examine Output:** Check the output of `symbolizer.py`. It will contain a line with the malicious filename, like: `??:0 $(echo vulnerable_command_executed)`.
    5. **Copy and Paste Output to Terminal:** Copy the line containing the malicious filename and paste it into a bash terminal. Observe if the command `echo vulnerable_command_executed` is executed in the terminal. If the message `vulnerable_command_executed` is printed in the terminal after pasting, it confirms the vulnerability.