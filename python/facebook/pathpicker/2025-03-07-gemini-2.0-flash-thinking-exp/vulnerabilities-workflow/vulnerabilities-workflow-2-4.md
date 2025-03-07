### Vulnerability List

- Vulnerability Name: Command Injection via Malicious Filenames
- Description:
    1. An attacker creates a file with a filename crafted to inject shell commands, for example, a filename containing `'file' ; touch injected ; 'file`.
    2. The attacker ensures that this filename appears in the input piped to PathPicker, for instance, by listing the file using `ls` and piping the output to `fpp` (`ls | fpp`).
    3. The user, using PathPicker, selects the line containing the malicious filename.
    4. The user then enters command mode in PathPicker by pressing `c`.
    5. The user types a command that is susceptible to command injection when used with shell metacharacters in filenames, such as `sh -c`, and presses Enter.
    6. PathPicker generates a shell script where the malicious filename is naively quoted with single quotes, which is insufficient to prevent command injection in this case. For the example filename and command `sh -c`, the generated command will be similar to `sh -c '''file'\'' ; touch injected ; \''file'''`, which when executed by `sh -c` will run the injected command `touch injected`.
    7. When the generated shell script is executed, the injected command `touch injected` (or any other command embedded in the filename) will be executed.
- Impact:
    - Critical. Successful exploitation allows arbitrary command execution on the user's system with the privileges of the user running PathPicker. This can lead to complete system compromise, data theft, or denial of service.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - PathPicker encloses the selected filenames in single quotes in the generated shell command within the `compose_file_command` function in `/code/src/pathpicker/output.py`. However, this mitigation is insufficient to prevent command injection when filenames are maliciously crafted to break out of these single quotes.
- Missing Mitigations:
    - Input sanitization of filenames: PathPicker should sanitize filenames to remove or properly escape shell-sensitive characters before including them in shell commands. This could involve using a robust escaping mechanism or disallowing filenames with certain characters.
    - Safer command execution: Instead of constructing shell commands as strings and executing them via `sh -c`, PathPicker should use `subprocess.Popen` with a list of arguments. This approach avoids shell interpretation of filenames and is inherently safer against command injection. Using `shlex.quote` to properly quote filenames before passing them to the shell could also be implemented.
- Preconditions:
    - An attacker must be able to create files with arbitrary filenames that can be listed and processed by PathPicker.
    - The user must pipe input to PathPicker that includes the malicious filename and must select this filename.
    - The user must then enter a command in PathPicker that is vulnerable to command injection (e.g., `sh -c`, `bash -c`, `eval`, or commands that process arguments through a shell interpreter).
- Source Code Analysis:
    - Vulnerable code is located in `/code/src/pathpicker/output.py` within the `compose_file_command` function.
    - Step-by-step analysis:
        1. The `compose_file_command` function takes a `command` string and a list of `LineMatch` objects as input.
        2. It iterates through the `line_objs` and extracts the file path using `line_obj.get_path()`.
        3. For each file path, it creates a string by enclosing the path in single quotes using an f-string: `f"'{line_obj.get_path()}'`.
        4. These quoted path strings are collected into a list and then joined into a single string `path_str` with spaces in between.
        5. If the original `command` string contains the token `$F`, it is replaced with the `path_str`. Otherwise, the `path_str` is appended to the `command`.
        6. The resulting command string is returned and later written to a shell script for execution.
    - Visualization:
        ```
        User Input (Malicious Filename) --> PathPicker Input Parsing --> LineMatch Object (with malicious path)
        User Command (e.g., sh -c) --> compose_file_command
        compose_file_command:
            For each LineMatch:
                path = line_obj.get_path()  // Malicious filename is retrieved
                quoted_path = f"'{path}'"   // Naive single quote quoting
                paths.append(quoted_path)
            path_str = " ".join(paths)
            command = command.replace("$F", path_str) or command + " " + path_str
        Generated Shell Script --> Execution by User's Shell --> Command Injection
        ```
- Security Test Case:
    1. Create a malicious file using the following command in a bash shell:
    ```bash
    touch $'file\' ; touch injected ; \'file'
    ```
    2. List the files in the current directory, which should include the malicious file:
    ```bash
    ls > files.txt
    ```
    3. Pipe the output of `cat files.txt` to PathPicker:
    ```bash
    cat files.txt | ./fpp
    ```
    4. In PathPicker, locate and select the line that lists the malicious file `'file' ; touch injected ; 'file`. Use the `f` key to select the line.
    5. Press `c` to enter command mode.
    6. Type the command `sh -c` and press Enter.
    7. After PathPicker closes, check if a file named `injected` has been created in the current directory:
    ```bash
    ls injected
    ```
    8. If the `ls injected` command shows the `injected` file, it confirms successful command injection. If the command fails with "ls: cannot access 'injected': No such file or directory", then the vulnerability is not exploitable with this test case in the current environment. (Based on analysis, the vulnerability IS exploitable)