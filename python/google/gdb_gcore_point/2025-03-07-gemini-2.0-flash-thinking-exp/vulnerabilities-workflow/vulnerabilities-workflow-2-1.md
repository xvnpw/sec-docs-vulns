* **Vulnerability Name:** Local File Write via Path Traversal in Core Filename

* **Description:**
    1. A user executes the `gcore-point` command in GDB, providing a breakpoint specification (`spec`) and a malicious `core name` argument containing path traversal characters (e.g., `../`).
    2. The `gcore-point.py` script creates a breakpoint using the provided `spec`.
    3. When the breakpoint is hit during program execution, the `stop` method of the `CoreDumpBP` class is triggered.
    4. Inside the `stop` method, the script constructs a core file name using the unsanitized `core name` provided by the user. This allows path traversal characters in the `core name` to manipulate the output path of the core file.
    5. The script then executes the GDB `gcore` command with the crafted file name, attempting to write the core file to a potentially arbitrary location on the file system, as dictated by the path traversal characters in the `core name`.

* **Impact:**
    An attacker, or a user with malicious intent, could potentially overwrite or create files in locations writable by the user running GDB. This could lead to:
    - **Local File Overwrite:** Overwriting critical files if the user running GDB has sufficient permissions.
    - **Information Disclosure (Indirect):**  In some scenarios, overwriting certain configuration or data files could indirectly lead to information disclosure or altered program behavior.
    - **Potential for further exploitation:** In highly specific and unlikely scenarios, controlled file writes could be a primitive for more complex local exploits if combined with other vulnerabilities in the system or applications being debugged.
    It's important to note that the impact is limited to the privileges of the user running GDB.

* **Vulnerability Rank:** Medium

* **Currently Implemented Mitigations:**
    None. The script directly uses the user-provided `core name` without any sanitization or validation.

* **Missing Mitigations:**
    - **Input Sanitization:** The `core name` argument should be sanitized to remove or escape path traversal characters (e.g., `../`, `./`, absolute paths).
    - **Path Validation:** Validate the generated core file path to ensure it remains within an expected directory or prevent path traversal.
    - **Warning to User:** At a minimum, documentation should be added to warn users about the potential security implications of using unsanitized core names and recommend caution.

* **Preconditions:**
    1. The user must be using GDB and source the `gcore_point.py` script.
    2. The user must execute the `gcore-point` command and provide a malicious `core name` argument.
    3. The user running GDB must have write permissions to the directory targeted by the path traversal.

* **Source Code Analysis:**
    1. **`GcorePointCmd.invoke(self, arg, from_tty)`:**
       ```python
       def invoke(self, arg, from_tty):
           if arg == "":
               raise gdb.GdbError(f"The {self._name} command must be called with arguments.")

           argv = arg.split(" ")
           spec = argv[0]
           if len(argv) > 1:
               CoreDumpBP(spec, core_name=argv[1]) # core_name is taken directly from user input
           else:
               CoreDumpBP(spec)
           return None
       ```
       - The `invoke` function parses the arguments provided to the `gcore-point` command.
       - `argv[1]` is directly assigned to `core_name` without any sanitization.

    2. **`CoreDumpBP.__init__(self, spec, core_name=None)`:**
       ```python
       def __init__(self, spec, core_name=None):
           self._core_name = core_name # core_name is stored without sanitization
           super(CoreDumpBP, self).__init__(spec)
       ```
       - The `core_name` argument is stored in the `self._core_name` attribute without any sanitization.

    3. **`CoreDumpBP.stop(self)`:**
       ```python
       def stop(self):
           inferior = gdb.selected_inferior()
           core_name_prefix = f"{self._core_name}." if self._core_name is not None else ""
           core_file_name = f"core.{core_name_prefix}{inferior.pid}.{self.hit_count}" # core_file_name is constructed using unsanitized core_name

           GCoreOnStop(core_file_name) # core_file_name is passed to GCoreOnStop

           return True
       ```
       - The `stop` method constructs the `core_file_name` by directly concatenating `"core."`, `core_name_prefix` (which contains the unsanitized `self._core_name`), the process ID, and the hit count.
       - This constructed `core_file_name` is then passed to `GCoreOnStop`, which eventually executes the `gcore` command with this file name.

    4. **`GCoreOnStop.run_event(self)`:**
       ```python
       def run_event(self):
           gdb.execute(f"gcore {self._file_name}") # gcore is executed with the potentially malicious file_name
       ```
       - The `run_event` method executes the `gcore` command using `gdb.execute` with the `self._file_name`, which can be manipulated by path traversal in the `core name`.

* **Security Test Case:**
    1. Start GDB on a test program (e.g., the `test_program` provided in `README.md`).
    2. Source the `gcore_point.py` script in GDB: `(gdb) source gcore_point.py`
    3. Create a `gcore-point` with a path traversal payload in the `core name`. For example, to attempt writing to `/tmp/evil_core`:
       `(gdb) gcore-point main.c:8 ../../../tmp/evil_core`
    4. Run the program: `(gdb) run`
    5. After the program runs and the breakpoint is hit, exit GDB: `(gdb) quit`
    6. Check if the core file was created at the path specified by the path traversal. In this example, check if a file named `evil_core.<pid>.0` (or similar) exists in `/tmp/`.
    7. If the file exists in `/tmp`, the path traversal vulnerability is confirmed.