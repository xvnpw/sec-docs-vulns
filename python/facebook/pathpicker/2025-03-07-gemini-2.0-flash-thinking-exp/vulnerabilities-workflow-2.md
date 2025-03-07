## Combined Vulnerabilities List

### Command Injection via Malicious Filenames

- Description:
    1. An attacker crafts a malicious filename that includes shell command injection payloads, such as single quotes, backticks, semicolons, command substitution characters, or other shell metacharacters. Examples include filenames like `test'file.txt ; touch injected`, `"file" ; touch injected.txt`, or `'file'$(touch injected.txt)'`.
    2. The attacker ensures that this malicious filename appears in the input piped to PathPicker. This can be achieved by creating a file with the malicious name and then using commands like `ls` or `find` whose output is piped to PathPicker. Compromised scripts or other command outputs could also be sources of malicious filenames.
    3. The user pipes this command output containing the malicious filename to PathPicker (e.g., `ls | fpp`, `find . -name "test'file.txt" | fpp`).
    4. PathPicker parses the input and displays the lines containing the malicious filenames in the selection UI, identifying them as selectable paths.
    5. The user, unaware of the malicious nature of the filenames, selects one or more of these filenames using PathPicker's UI.
    6. The user then initiates the "execute command" feature by pressing `c` and entering a custom command (e.g., `ls -l $F`, `git add $F`, `sh -c`), or by pressing Enter to edit files (which also relies on command execution in some editors).
    7. PathPicker's `compose_file_command` function in `src/output.py` constructs a shell command by attempting to quote the selected filenames with single quotes and appending them to the user-provided command prefix. However, this single quoting is insufficient to prevent command injection if the filename itself contains single quotes or other shell metacharacters designed to break out of the quoting.
    8. When the crafted command is executed by PathPicker through `output.append_friendly_command`, which writes the command to a shell script (`.fpp.sh`) and executes it using `bash`, the injected commands embedded within the filename are executed in the user's shell with the user's privileges.

- Impact:
    - **Critical**: Successful command injection allows the attacker to execute arbitrary shell commands with the privileges of the user running PathPicker. This can lead to complete system compromise, including:
        - **Data Theft**: Accessing and exfiltrating sensitive files and information.
        - **Malware Installation**: Installing backdoors, ransomware, or other malicious software.
        - **System Modification**: Altering system configurations, creating new users, or deleting critical data.
        - **Denial of Service**: Disrupting system operations or making resources unavailable.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - **Partial Mitigation**: PathPicker attempts to mitigate command injection by enclosing filenames in single quotes within the `compose_file_command` function in `src/output.py`.
    ```python
    def compose_file_command(command: str, line_objs: List[LineMatch]) -> str:
        command = command.encode().decode("utf-8")
        paths = [f"'{line_obj.get_path()}'" for line_obj in line_objs] # Filenames are quoted here
        path_str = " ".join(paths)
        if "$F" in command:
            command = command.replace("$F", path_str)
        else:
            command = f"{command} {path_str}"
        return command
    ```
    - This mitigation is present in `src/output.py`, but it is demonstrably insufficient to prevent injection, particularly when filenames contain single quotes or other shell metacharacters designed for command injection.

- Missing Mitigations:
    - **Robust Filename Sanitization/Escaping**: PathPicker lacks proper sanitization or escaping of filenames before embedding them in shell commands. This is the most critical missing mitigation.  Robust sanitization should include:
        - Using a secure quoting mechanism like `shlex.quote` in Python to properly escape filenames. This ensures filenames are treated as literal strings, even if they contain shell-sensitive characters.
        - Alternatively, implementing a strict whitelist of allowed characters in filenames, though this might be overly restrictive and impact usability.
    - **Secure Command Execution**: PathPicker uses `output.append_friendly_command` to write commands to a file and then executes this file using `bash`. This approach is inherently vulnerable if the command string is not perfectly sanitized. Safer alternatives include:
        - Using `subprocess.Popen` with a list of arguments, which avoids shell interpretation of the command string and is inherently safer.
        - Avoiding shell execution altogether where possible and using Python libraries to perform file operations directly.
    - **Input Validation and User Warning**: While PathPicker performs some file existence checks, it does not validate the content of filenames for malicious shell commands. Implementing checks for potentially malicious characters in filenames and displaying a warning to the user before executing commands with such filenames would add a layer of defense.

- Preconditions:
    1. **Malicious Filename in Input**: The user must pipe command output to PathPicker that includes a malicious filename crafted by an attacker. The attacker needs to control or influence the input to PathPicker to inject these malicious filenames.
    2. **User Interaction**: The user must select a line containing the malicious filename in PathPicker's UI.
    3. **Command Execution Trigger**: The user must then trigger command execution, either by entering command mode and specifying a command or by using a default action (like pressing Enter to edit files) that results in command execution involving the selected filename.

- Source Code Analysis:
    1. **`src/output.py:compose_file_command`**: This function is the core of the vulnerability as it constructs the vulnerable shell command.
    ```python
    def compose_file_command(command: str, line_objs: List[LineMatch]) -> str:
        command = command.encode().decode("utf-8")
        paths = [f"'{line_obj.get_path()}'" for line_obj in line_objs]
        path_str = " ".join(paths)
        if "$F" in command:
            command = command.replace("$F", path_str)
        else:
            command = f"{command} {path_str}"
        return command
    ```
    - **Vulnerability Point**: The code attempts to quote filenames with single quotes using `f"'{line_obj.get_path()}'"`. This is insufficient because if `line_obj.get_path()` returns a filename like `test'file.txt`, the resulting quoted string becomes `'test'file.txt'`, which still allows for command injection. The single quote within the filename terminates the initial quote, allowing for injection of arbitrary shell commands after it.

    2. **`src/output.py:append_friendly_command`**: This function writes the composed command to the output script.
    ```python
    def append_friendly_command(command: str) -> None:
        header = 'echo "executing command:"\necho "' + command.replace('"', '\\"') + '"'
        append_to_file(header)
        append_to_file(command)
    ```
    - The `command` string, potentially containing injected commands, is directly passed to `append_to_file`.

    3. **`src/output.py:append_to_file`**: This function appends the command to the `.fpp.sh` script file.
    ```python
    def append_to_file(command: str) -> None:
        file = open(state_files.get_script_output_file_path(), "a")
        file.write(command + "\n")
        file.close()
        logger.output()
    ```
    - The command is written to the file without further sanitization.

    4. **`fpp` (Bash Script)**: The `fpp` bash script executes the generated `.fpp.sh` script using `bash`.
    ```bash
    if [ -n "$FPP_COMMAND_MODE" ]; then
      # interactive mode
      bash -i "$FPP_SCRIPT_PATH"
    else
      # non-interactive mode
      bash "$FPP_SCRIPT_PATH"
    fi
    ```
    - `bash "$FPP_SCRIPT_PATH"` executes the script, including the potentially malicious command, leading to command injection.

    **Vulnerability Flow Visualization:**

    ```
    [Command Output with Malicious Filename] --> PathPicker (Parsing) --> [User Selection: Malicious Filename] --> [Custom Command Input or Default Action] --> src/output.py:compose_file_command (Insufficient Quoting: "'" around filename) --> src/output.py:append_friendly_command --> .fpp.sh (Malicious Command) --> bash (Command Injection!)
    ```

- Security Test Case:
    1. **Setup Malicious Filename**: Create a file with a malicious filename designed for command injection:
       ```bash
       touch $'test\' -i whoami #.txt'  # Filename with single quote and command injection payload
       ```
       Alternatively, for simpler testing with `touch injected` command:
       ```bash
       touch "test'file.txt ; touch injected ;"
       ```

    2. **Generate Input for PathPicker**: Create command output that includes this malicious filename. Use `ls -l` for example:
       ```bash
       ls -l > input.txt
       echo "malicious line with test'file.txt ; touch injected ;" >> input.txt # Or $'test\' -i whoami #.txt'
       ```
       Or for `$'file\' ; touch injected ; \'file'` filename:
       ```bash
       touch $'file\' ; touch injected ; \'file'
       ls > input.txt
       ```

    3. **Run PathPicker with Malicious Input**: Pipe the input to PathPicker and optionally specify a command to execute (though command mode trigger is enough):
       ```bash
       cat input.txt | ./fpp -c "ls -l \$F" # Or just `cat input.txt | ./fpp` and trigger command mode in UI
       ```

    4. **Select Malicious Filename and Execute Command**: In PathPicker UI:
        - Navigate to the line containing the malicious filename.
        - Select the line (e.g., press `f`).
        - Press `c` to enter command mode.
        - Type a simple command like `ls` or `sh -c` and press Enter twice. Alternatively, just press Enter to trigger default action.

    5. **Verify Command Injection**: After PathPicker exits, check for the injected effect. For `touch injected` payload:
       ```bash
       ls -l injected # Check if 'injected' file is created
       ```
       For `whoami` payload in filename `$'test\' -i whoami #.txt'`: observe the output in the terminal where PathPicker was executed. If the output of `whoami` is printed, command injection is confirmed.

    6. **Cleanup**: Remove the created files and input file:
       ```bash
       rm -f injected input.txt "test'file.txt ; touch injected ;" $'test\' -i whoami #.txt' $'file\' ; touch injected ; \'file'
       ```

    **Expected Result (Vulnerable)**: If the vulnerability exists, the injected command (e.g., `touch injected` or `whoami`) will be executed. For `touch injected`, the file `injected` will be created. For `whoami`, the output of the `whoami` command will be visible in the terminal. This confirms successful command injection.

    **Expected Result (Mitigated)**: If properly mitigated, the injected command should NOT be executed. The `injected` file should NOT be created, and commands like `whoami` should not be executed unexpectedly. PathPicker should treat the filename as a literal string, preventing shell command interpretation.