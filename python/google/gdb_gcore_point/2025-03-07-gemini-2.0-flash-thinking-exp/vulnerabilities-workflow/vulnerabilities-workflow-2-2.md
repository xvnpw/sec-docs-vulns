- **Vulnerability Name:** Path Traversal in `gcore-point` command's `core name` argument
- **Description:**
    1. A user executes the `gcore-point` command in GDB to set a breakpoint that generates a core file when hit.
    2. The `gcore-point` command takes an optional second argument, `core name`, which is intended to be a descriptive name included in the generated core file's filename.
    3. An attacker can provide a malicious `core name` argument containing path traversal characters, such as `../`, to manipulate the output path of the `gcore` command.
    4. When the breakpoint is hit, the script executes the `gcore` command using the provided `core name` argument without proper sanitization.
    5. Due to the path traversal characters, the `gcore` command writes the core file to an unexpected directory relative to the current GDB working directory, potentially outside the intended directory.
    6. This can lead to arbitrary file creation or overwrite within the GDB working directory's hierarchy, depending on the permissions of the GDB process and the file path specified in the malicious `core name`.
- **Impact:**
    - Arbitrary file creation and potentially file overwrite within the directory structure where GDB is running.
    - An attacker could potentially overwrite existing files, including configuration files or scripts, if the GDB process has sufficient write permissions.
    - In some scenarios, an attacker might be able to create files in sensitive directories if the GDB process is running with elevated privileges or if the file system permissions are misconfigured.
- **Vulnerability Rank:** Medium
- **Currently Implemented Mitigations:**
    - None. The script does not perform any validation or sanitization of the `core name` argument. It directly incorporates the user-provided string into the core file path.
- **Missing Mitigations:**
    - **Input Validation and Sanitization:** The script should validate the `core name` argument to ensure it does not contain path traversal sequences (e.g., `../`, `..\\`).
    - **Path Sanitization:** Employ secure path manipulation techniques to prevent path traversal. For example, the script could:
        - Restrict the `core name` to alphanumeric characters and underscores.
        - Use a safe path joining function that normalizes the path and prevents traversal outside of an intended base directory.
- **Preconditions:**
    1. The user must be using the GNU Debugger (GDB).
    2. The user must source the `gcore_point.py` script into their GDB session, making the `gcore-point` command available.
    3. The user, intentionally or unintentionally, must execute the `gcore-point` command with a `core name` argument that includes path traversal characters.
- **Source Code Analysis:**
    1. In `gcore_point.py`, the `GcorePointCmd.invoke` function is responsible for handling the `gcore-point` command.
    2. It receives the command arguments as a string `arg` and splits them by spaces: `argv = arg.split(" ")`.
    3. The breakpoint specification `spec` is taken as the first argument `argv[0]`.
    4. The optional `core name` is taken as the second argument `argv[1]` if it exists.
    5. A `CoreDumpBP` object is created using `CoreDumpBP(spec, core_name=argv[1])` or `CoreDumpBP(spec)`.
    6. In `CoreDumpBP.__init__`, the `core_name` is stored in `self._core_name` without any sanitization.
    7. When the breakpoint is hit, the `CoreDumpBP.stop` method is executed.
    8. Inside `CoreDumpBP.stop`, the core filename is constructed using an f-string: `core_file_name = f"core.{core_name_prefix}{inferior.pid}.{self.hit_count}` where `core_name_prefix` is derived directly from `self._core_name`.
    9. The `core_file_name`, which can contain path traversal characters from the user-provided `core name`, is passed to `GCoreOnStop(core_file_name)`.
    10. Finally, in `GCoreOnStop.run_event`, the `gdb.execute(f"gcore {self._file_name}")` command is executed, passing the unsanitized `core_file_name` to the `gcore` GDB command.
    11. The `gcore` command then uses this potentially malicious filename to write the core dump, leading to the path traversal vulnerability.

    ```
    GcorePointCmd.invoke(arg, from_tty)
    │
    └── argv = arg.split(" ")
    │   spec = argv[0]
    │   core_name = argv[1] (if exists)
    │
    └── CoreDumpBP(spec, core_name)  # core_name is passed unsanitized
        │
        └── CoreDumpBP.__init__(spec, core_name)
            │
            └── self._core_name = core_name  # core_name stored unsanitized
            │
            └── CoreDumpBP.stop() # Breakpoint hit
                │
                └── core_name_prefix = f"{self._core_name}." if self._core_name is not None else ""
                │   core_file_name = f"core.{core_name_prefix}{inferior.pid}.{self.hit_count}" # core_name used unsanitized in filename
                │
                └── GCoreOnStop(core_file_name) # core_file_name passed unsanitized
                    │
                    └── GCoreOnStop.__init__(file_name=core_file_name)
                        │
                        └── self._file_name = file_name # file_name stored unsanitized
                        │
                        └── GCoreOnStop.run_event()
                            │
                            └── gdb.execute(f"gcore {self._file_name}") # gcore executed with unsanitized filename
    ```

- **Security Test Case:**
    1. Open a terminal and navigate to a temporary directory, for example, `/tmp`.
    2. Create a test C program (e.g., `test.c`) with the following content:
        ```c
        #include <stdio.h>

        int main() {
            int x = 5;
            printf("Value of x: %d\n", x); // Breakpoint here
            return 0;
        }
        ```
    3. Compile the program with debug symbols: `gcc -g -o test test.c`
    4. Start GDB: `gdb ./test`
    5. Source the `gcore_point.py` script: `(gdb) source /path/to/gcore_point.py` (replace `/path/to/gcore_point.py` with the actual path to the script).
    6. Set a `gcore-point` breakpoint with a path traversal payload in the `core name` argument to attempt to write a core file to `/tmp`: `(gdb) gcore-point test.c:5 ../evil_core`
    7. Run the program: `(gdb) run`
    8. Exit GDB: `(gdb) quit`
    9. Check if a core file named `core.evil_core.<pid>.0` (or similar, depending on PID and hit count) has been created in `/tmp`. You should find a file like `/tmp/core.evil_core.<pid>.0`.
    10. To further verify, try to traverse further up and potentially overwrite a known file (exercise caution when doing this in a real system). For example, if you have a writable file in your home directory (e.g., `/home/user/test_overwrite.txt`), you could try: `(gdb) gcore-point test.c:5 ../../../home/user/test_overwrite`. After running and exiting GDB, check if `/home/user/test_overwrite.txt` has been overwritten by a core file. (Note: Overwriting might fail due to permissions, but the attempt to write outside the intended directory confirms the vulnerability).