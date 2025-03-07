### Vulnerability List

- Vulnerability Name: Command Injection via Filename with Single Quote

- Description:
    1. An attacker crafts a filename that includes a single quote, for example, `test'file.txt`.
    2. This malicious filename is embedded within the output of a command, which is then piped to PathPicker. For instance, the output of `find . -name "test'file.txt"` or a compromised script could be used.
    3. PathPicker parses this output and displays the filename `test'file.txt` in the selection UI.
    4. The user selects this filename and proceeds to execute a custom command, such as `ls -l $F` or `git add $F`.
    5. PathPicker's `compose_file_command` function encloses the selected filenames in single quotes. However, if a filename itself contains a single quote, this quoting is insufficient to prevent command injection. The generated command becomes vulnerable because the single quote in the filename prematurely terminates the intended single-quoted string, allowing for the injection of arbitrary shell commands after it.
    6. When the crafted command is executed by PathPicker through `output.append_friendly_command` which simply appends command to output file and then executes it using `bash`, the injected commands in the filename are executed in the user's shell.

- Impact:
    - **High/Critical**: Successful command injection allows the attacker to execute arbitrary shell commands with the privileges of the user running PathPicker. This can lead to complete system compromise, data theft, malware installation, or denial of service. The severity depends on the commands injected and the system's security posture.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - **Partial Mitigation**: PathPicker encloses the filenames in single quotes within the `compose_file_command` function in `src/output.py`.
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
    - This mitigation is present in `src/output.py`, but it's insufficient to prevent injection via filenames containing single quotes.

- Missing Mitigations:
    - **Robust Filename Sanitization**: PathPicker lacks proper sanitization or escaping of filenames, especially those containing single quotes or other shell metacharacters, before embedding them in shell commands.
    - **Input Validation**: While PathPicker performs some file existence checks, it does not validate the content of filenames for malicious shell commands.
    - **Secure Command Execution**: The project uses `output.append_friendly_command` which writes commands to a file and executes it using `bash`. This approach is inherently vulnerable if the command string is not perfectly sanitized. Using safer command execution methods, such as parameterized commands or avoiding shell execution altogether where possible, would be a better mitigation.

- Preconditions:
    1. The user must pipe command output containing a malicious filename to PathPicker.
    2. The malicious filename must contain a single quote or other shell metacharacters.
    3. The user must select the line containing the malicious filename and execute a custom command using PathPicker's command mode or a predefined key binding that triggers command execution.

- Source Code Analysis:
    1. **`src/output.py:compose_file_command`**: This function is responsible for constructing the shell command that will be executed.
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
    - The code iterates through selected `line_objs` and retrieves the file path using `line_obj.get_path()`.
    - It then encloses each path in single quotes using f-string formatting: `f"'{line_obj.get_path()}'"`.
    - These quoted paths are joined into `path_str` and appended to the user-provided `command`.
    - If the command contains `$F`, it's replaced with `path_str`. Otherwise, `path_str` is appended to the command.
    - **Vulnerability Point**: The single quoting is intended to protect against spaces and some special characters in filenames. However, it is insufficient for filenames that themselves contain single quotes. A filename like `test'file.txt` will be quoted as `'test'file.txt'`, which will be interpreted incorrectly by the shell.

    2. **`src/output.py:append_friendly_command`**: This function writes the composed command to a file and adds an echo statement for user feedback.
    ```python
    def append_friendly_command(command: str) -> None:
        header = 'echo "executing command:"\necho "' + command.replace('"', '\\"') + '"'
        append_to_file(header)
        append_to_file(command)
    ```
    - The `command` is passed directly to `append_to_file`.

    3. **`src/output.py:append_to_file`**: This function appends the given command to the output script file (`.fpp.sh`).
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
    - `bash "$FPP_SCRIPT_PATH"` executes the script, including the potentially malicious command.

    **Visualization:**

    ```
    [Command Output with Malicious Filename] --> PathPicker (Parsing) --> [User Selection: Malicious Filename] --> [Custom Command Input] --> src/output.py:compose_file_command (Insufficient Quoting: "'" around filename) --> src/output.py:append_friendly_command --> .fpp.sh (Malicious Command) --> bash (Command Injection!)
    ```

- Security Test Case:
    1. **Setup Malicious Filename**: Create a file with a single quote in its name:
       ```bash
       touch "test'file.txt"
       ```

    2. **Generate Input for PathPicker**: Create command output that includes this malicious filename. For example, use `ls`:
       ```bash
       ls -l > input.txt
       echo "malicious line with test'file.txt" >> input.txt
       ```

    3. **Run PathPicker with Malicious Input**: Pipe the generated input to PathPicker and specify a command to execute, e.g., `ls -l $F`:
       ```bash
       cat input.txt | ./fpp -c "ls -l \$F"
       ```
       Alternatively, to directly verify command injection, use a command like `touch injected` within the filename itself and a simple command like `ls -l $F`:
       ```bash
       rm -f injected
       MALICIOUS_FILE="test'file.txt ; touch injected ;"
       touch "$MALICIOUS_FILE"
       ls -l > input.txt
       echo "malicious line with $MALICIOUS_FILE" >> input.txt
       cat input.txt | ./fpp -c "ls -l \$F"
       ls -l injected # Check if 'injected' file is created
       rm -f "test'file.txt ; touch injected ;" injected input.txt
       ```
       **Expected Result (Vulnerable)**: If the vulnerability exists, a file named `injected` will be created in the current directory after executing the PathPicker command, even though the intended command was just `ls -l $F`. This indicates that the `touch injected` command embedded in the filename was executed due to command injection.

       **Expected Result (Mitigated)**: If properly mitigated, the `injected` file should NOT be created, and the `ls -l` command should execute without any side effects from the filename.

This vulnerability allows for command injection due to insufficient sanitization of filenames, specifically when filenames contain single quotes. The single quoting mechanism in `compose_file_command` is not robust enough to prevent exploitation when filenames themselves include single quotes, leading to arbitrary command execution.