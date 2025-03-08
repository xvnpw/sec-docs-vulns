### Vulnerability List:

* Vulnerability Name: Path Traversal in Trace Output Directory
* Description:
    1. The Sherlock tool allows users to specify the output directory for captured Perfetto traces using the `--traces-directory` command-line argument.
    2. This argument is used in both `device-manager` and `trace-analysis` modes.
    3. The tool uses `os.path.join` to construct the full path to save trace files, combining the user-provided `--traces-directory` with device serial numbers and trace filenames.
    4. However, the `--traces-directory` input is not properly validated or sanitized to prevent path traversal attacks.
    5. An attacker can provide a malicious path like `/tmp/output/../../../sensitive_dir` as the `--traces-directory`.
    6. When Sherlock attempts to create directories and save trace files, it will resolve the path traversal sequences, leading to file operations outside the intended `/tmp/output` directory.
    7. For example, if the attacker provides `/tmp/output/../../../sensitive_dir` and the device serial is `emulator-5554`, the tool might attempt to create a directory and save files in `/sensitive_dir/emulator-5554/`, potentially overwriting or creating files in sensitive locations.
* Impact:
    * An attacker can write trace files to arbitrary locations on the file system where the Sherlock tool is executed.
    * This can lead to:
        * **Information Disclosure**: Overwriting existing files with trace data, potentially corrupting legitimate files.
        * **Data Corruption**: Creating new files in unexpected locations, which might interfere with system operations or other applications.
        * **Potential for Code Execution**: In a more severe scenario, if an attacker can predict file paths and permissions, they might be able to overwrite executable files or configuration files, potentially leading to arbitrary code execution when those overwritten files are used by the system or other users.
* Vulnerability Rank: High
* Currently Implemented Mitigations:
    * The tool uses `os.path.basename` when constructing the final trace filename before saving. This prevents path traversal through the filename itself. For example, if a malicious filename like `../../../evil.pftrace` is somehow generated, `os.path.basename` will reduce it to `evil.pftrace`, mitigating filename-based path traversal. However, this does not prevent path traversal in the directory path specified by `--traces-directory`.
    * Mitigation is present in `/code/src/sherlock/sherlock_device.py` in `collect_traces` function when saving the trace file:
    ```python
    self.adb_device.sync.pull(
        trace_filepath,
        f'{local_output_dirpath}{os.path.sep}{os.path.basename(trace_filepath)}',
    )
    ```
* Missing Mitigations:
    * Input validation and sanitization for the `--traces-directory` argument in `sherlock.py`.
    * Implement path canonicalization and validation to ensure that the resolved output directory is within an expected and safe base directory. For example, resolve the absolute path of the user-provided `--traces-directory` using `os.path.abspath()` and check if it is a subdirectory of a predefined safe base path.
* Preconditions:
    * The attacker needs to trick a user into running the Sherlock tool with a maliciously crafted `--traces-directory` argument. This could be achieved through social engineering or by providing a seemingly innocuous configuration file that suggests using a malicious output directory.
* Source Code Analysis:
    1. In `/code/src/sherlock.py`, the `argparse` module is used to parse command-line arguments, including `--traces-directory`.
    2. The value provided for `--traces-directory` is directly passed to the `_handle_device_manager` and `_handle_trace_analysis` functions without any sanitization.
    3. In `/code/src/sherlock_config.py`, the `SherlockConfig` dataclass stores the `local_output_dir` which is directly assigned from the parsed `--traces-directory` argument.
    4. In `/code/src/sherlock_device.py`, the `collect_traces` function constructs the local output directory path using `os.path.join(self.sherlock_config.local_output_dir, self.serial)`.
    5. `os.makedirs(local_output_dirpath, exist_ok=True)` is then used to create the directory structure.
    6. Finally, `self.adb_device.sync.pull` saves the trace file under the constructed path.
    7. **Vulnerability:** The lack of sanitization of `args.traces_directory` in `sherlock.py` and subsequent use in `os.path.join` within `sherlock_device.py` allows path traversal.

    ```python
    # /code/src/sherlock.py
    def _handle_device_manager(args: argparse.Namespace) -> None:
      dm = device_manager.DeviceManager(
          config=sherlock_config.SherlockConfig(
              local_output_dir=args.traces_directory, # <-- User provided path, no sanitization
              trace_config_file_path=args.perfetto_config_file,
          ),
          mode=args.operation,
      )
      ...

    # /code/src/sherlock_config.py
    @dataclasses.dataclass
    class SherlockConfig:
      local_output_dir: str # <-- Stored directly from user input
      trace_config_file_path: str
      ...

    # /code/src/sherlock_device.py
    def collect_traces(
        self, filename_filter=lambda x: True, delete_after_transfer=True
    ) -> None:
      local_output_dirpath = os.path.join(
          self.sherlock_config.local_output_dir, self.serial # <-- Vulnerable os.path.join
      )
      try:
        os.makedirs(local_output_dirpath, exist_ok=True) # <-- Directory creation under attacker controlled path
        ...
        self.adb_device.sync.pull(
            trace_filepath,
            f'{local_output_dirpath}{os.path.sep}{os.path.basename(trace_filepath)}', # <-- File saved under attacker controlled path
        )
        ...
    ```

* Security Test Case:
    1. **Setup:**
        * Install Sherlock tool as described in the `README.md`.
        * Create a directory `/tmp/sherlock_output` which will be the intended output directory.
        * Create a malicious output directory path string: `malicious_output_path="/tmp/sherlock_output/../../../tmp/malicious_traces"`. This path attempts to traverse out of the `/tmp/sherlock_output` directory and write into `/tmp/malicious_traces`.
        * Create a simple valid Perfetto configuration file, e.g., `test_config.pbtxt`:
        ```
        buffers: {
          size_kb: 8192
          fill_policy: RING_BUFFER
        }
        data_sources: {
          config {
            name: "linux.process_stats"
          }
        }
        ```
        * Convert `test_config.pbtxt` to binary format `test_config.bin` using `protoc` as described in `README.md`.
        * Connect an Android device via `adb`.
    2. **Execution:**
        * Run Sherlock in `device-manager` mode, providing the malicious output path and the test configuration file:
        ```bash
        python sherlock.py device-manager --perfetto-config-file test_config.bin --traces-directory "/tmp/sherlock_output/../../../tmp/malicious_traces" --operation TERMINATE_COLLECT
        ```
    3. **Verification:**
        * After the command completes, check if a directory named `malicious_traces` and a subdirectory with the device serial number have been created under `/tmp`.
        * Verify that the Perfetto trace file (`*.pftrace`) is located in `/tmp/malicious_traces/<device_serial>/` instead of the intended `/tmp/sherlock_output/<device_serial>/`.
        * If the trace file is found in `/tmp/malicious_traces`, the path traversal vulnerability is confirmed.