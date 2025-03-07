### Vulnerability List

* Vulnerability Name: Command Injection via Filenames
* Description:
    1. An attacker crafts a malicious command output. This output contains filenames that include shell command injection payloads. For example, a filename could be crafted as `"file`; touch injected.txt` or `"file\$(touch injected.txt)"`.
    2. A user pipes this malicious command output to PathPicker (e.g., `echo 'malicious output with "file"; touch injected.txt' | fpp`).
    3. PathPicker parses the input and presents the crafted filenames in the selection UI.
    4. The user, unaware of the malicious nature of the filenames, selects one or more of these filenames using PathPicker's UI.
    5. The user then initiates the "execute command" feature by pressing `c` and entering a command, or by pressing Enter to edit files (which also relies on command execution in some editors).
    6. PathPicker constructs a shell command by appending the selected filenames to the user-provided command (or default editor command). Due to insufficient sanitization of filenames, the shell injection payload embedded in the filename is executed when the constructed command is run by the `fpp` script.
    7. As a result, arbitrary commands injected by the attacker (e.g., `touch injected.txt` in the example filename) are executed on the user's system with the user's privileges.
* Impact: Arbitrary command execution. An attacker can gain full control over the user's system by injecting and executing malicious commands. This can lead to data theft, malware installation, or other malicious activities.
* Vulnerability Rank: Critical
* Currently Implemented Mitigations:
    * None. The project does not implement any sanitization or escaping of filenames before passing them to the shell command in `output.py`.
* Missing Mitigations:
    * **Filename Sanitization/Escaping:** The most crucial missing mitigation is to sanitize or properly escape filenames before they are used in shell commands. This could involve:
        - Using shell quoting (e.g., `shlex.quote` in Python) to ensure filenames are treated as literal strings and not interpreted as shell commands.
        - Implementing a whitelist of allowed characters in filenames, although this might be too restrictive and break legitimate use cases.
    * **Warning to User:** Display a clear warning to the user before executing any command with selected files, especially if filenames contain unusual characters that might be indicative of shell injection attempts.
* Preconditions:
    1. The user must pipe a crafted command output to PathPicker.
    2. The crafted command output must contain filenames with shell injection payloads.
    3. The user must select one or more of these malicious filenames in PathPicker's UI.
    4. The user must then use PathPicker's "execute command" feature or press Enter to open files, triggering command construction and execution.
* Source Code Analysis:
    1. **`src/output.py`:** This file is responsible for generating the shell script that is executed by `fpp`.
    2. **`compose_file_command(command: str, line_objs: List[LineMatch])` function:** This function in `output.py` is the core of the vulnerability. It constructs the shell command by taking a user-provided command prefix and appending the selected filenames.
    ```python
    def compose_file_command(command: str, line_objs: List[LineMatch]) -> str:
        command = command.encode().decode("utf-8")
        paths = [f"'{line_obj.get_path()}'" for line_obj in line_objs] # Vulnerable line
        path_str = " ".join(paths)
        if "$F" in command:
            command = command.replace("$F", path_str)
        else:
            command = f"{command} {path_str}" # Vulnerable line
        return command
    ```
    - **Vulnerability:** In the line `paths = [f"'{line_obj.get_path()}'" for line_obj in line_objs]`, single quotes are used in an attempt to quote filenames. However, this is insufficient to prevent command injection because if a filename itself contains a single quote, it can break out of the quoting, allowing for command injection. For example, if `line_obj.get_path()` returns `"file'$(touch injected.txt)"`, the generated path string becomes `"'file'$(touch injected.txt)'"`. When this is inserted into the shell command, the single quotes around `file` are properly quoted, but the single quote *inside* `file'$(touch injected.txt)` terminates the initial quoting, and `$(touch injected.txt)` is then executed as a shell command.
    - The subsequent lines, particularly `command = f"{command} {path_str}"`, directly concatenate the potentially malicious `path_str` into the shell command without proper escaping for shell execution.
    3. **`exec_composed_command(command: str, line_objs: List[LineMatch])` function:** This function calls `compose_command` and then `append_friendly_command`, which ultimately writes the constructed command to the output file that is executed by the `fpp` bash script.
    4. **`fpp` bash script:** The `fpp` script executes the generated script file using `source`, which directly runs the commands within the current shell environment, making it vulnerable to command injection.

* Security Test Case:
    1. **Craft Malicious Input:** Create a text file named `malicious_input.txt` with the following content:
    ```text
    "evil_file_';touch injected_file.txt'"
    ```
    This filename contains a single quote to break out of quoting and the command `touch injected_file.txt` to be injected.
    2. **Pipe Input to PathPicker and Execute Command:** Run PathPicker with the crafted input and attempt to execute a command.
    ```bash
    cat malicious_input.txt | fpp
    ```
    3. **Select the Malicious Filename:** In the PathPicker UI, use the navigation keys (j/k or arrow keys) to highlight the line containing `"evil_file_';touch injected_file.txt'"` and press `f` to select it.
    4. **Execute a Command (or simply open files):** Press `c` to enter command mode, and type `ls -l`. Press Enter twice (once to confirm the command, and again to execute). Alternatively, simply press Enter to attempt to open the selected file in the editor.
    5. **Verify Command Injection:** After PathPicker exits, check if the file `injected_file.txt` has been created in the current directory.
    ```bash
    ls -l injected_file.txt
    ```
    If `injected_file.txt` exists, the command injection vulnerability is confirmed. The `touch injected_file.txt` command embedded in the filename was successfully executed.

This vulnerability allows for arbitrary command execution, posing a significant security risk. Mitigation through proper filename sanitization/escaping is critical.