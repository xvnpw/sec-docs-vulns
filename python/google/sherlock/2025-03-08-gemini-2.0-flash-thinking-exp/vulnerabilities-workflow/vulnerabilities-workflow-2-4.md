### Vulnerability List

#### Vulnerability Name: Malicious Perfetto Config File Injection

* Description:
    1. The Sherlock tool requires a Perfetto configuration file as input, specified by the `--perfetto-config-file` argument in `device-manager` mode.
    2. This configuration file dictates what data Perfetto captures from the Android device.
    3. A malicious actor could socially engineer a user into using a crafted Perfetto configuration file.
    4. This malicious configuration file could be designed to capture sensitive user data such as location, contacts, browsing history, application usage, or any other data Perfetto is capable of recording.
    5. Once the user executes Sherlock with the malicious configuration file, the tool will instruct the Android device to start recording a Perfetto trace based on this configuration.
    6. The captured trace, containing the sensitive data, is then stored on the user's local machine in the directory specified by the `--traces-directory` argument.
    7. An attacker could then further socially engineer the user into sharing the collected trace file, or if the attacker gains access to the user's machine, they could directly exfiltrate the trace file containing the sensitive data.

* Impact:
    * Confidentiality breach: Sensitive user data from the Android device, as defined in the malicious Perfetto configuration file, can be captured and exposed to the attacker. This could include personal information, browsing history, location data, contacts, application usage patterns, and more, depending on the capabilities defined in the malicious configuration.
    * Privacy violation: Users' privacy is severely violated as their device activity and personal data are monitored and potentially exfiltrated without their informed consent or understanding of the full extent of data being collected.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    * None. The application directly uses the provided Perfetto configuration file without any validation or security checks. The README.md provides instructions on how to generate configuration files, but does not warn users about the security risks of using untrusted configuration files.

* Missing Mitigations:
    * Input validation: Implement validation of the Perfetto configuration file to ensure it adheres to a safe and expected schema, preventing the injection of malicious configurations. This could involve parsing the configuration file and checking for potentially dangerous data sources or tracing categories.
    * Security warnings: Display clear warnings to the user about the security risks of using Perfetto configuration files from untrusted sources. This warning should be presented when the `device-manager` mode is initiated and should emphasize the potential for sensitive data capture.
    * Documentation: Enhance the documentation to explicitly warn users about the risks associated with using untrusted Perfetto configuration files and provide guidelines on how to obtain and verify safe configuration files.

* Preconditions:
    * The user must download and install the Sherlock tool.
    * The user must have an Android device with Developer Mode enabled and Chrome configured as described in the README.
    * The attacker must successfully socially engineer the user into using a malicious Perfetto configuration file with the Sherlock tool. This could be achieved by distributing the malicious configuration file through various channels (e.g., email, websites, forums) and convincing the user to use it with Sherlock.

* Source Code Analysis:
    1. **`src/sherlock.py`**:
       - The `_handle_device_manager` function is responsible for handling the `device-manager` subcommand.
       - It creates a `DeviceManager` object, passing the `perfetto_config_file` argument value directly into the `SherlockConfig`.
       - ```python
         def _handle_device_manager(args: argparse.Namespace) -> None:
           dm = device_manager.DeviceManager(
               config=sherlock_config.SherlockConfig(
                   local_output_dir=args.traces_directory,
                   trace_config_file_path=args.perfetto_config_file, # [Vulnerable code] - Unvalidated config file path from user input
               ),
               mode=args.operation,
           )
           # ...
         ```
    2. **`src/sherlock/sherlock_config.py`**:
       - The `SherlockConfig` dataclass stores the `trace_config_file_path` directly without any validation.
       - ```python
         @dataclasses.dataclass
         class SherlockConfig:
             # ...
             trace_config_file_path: str # [Vulnerable code] - Unvalidated config file path
             # ...
         ```
    3. **`src/sherlock/device_manager.py`**:
       - The `DeviceManager` class initializes with the `SherlockConfig`.
    4. **`src/sherlock/sherlock_device.py`**:
       - In the `start_perfetto` function, the `trace_config_file_path` from `sherlock_config` is directly used to open and read the configuration file.
       - This file content is then passed as standard input to the `perfetto` command executed on the Android device via ADB shell.
       - ```python
         def start_perfetto(self) -> bool:
             # ...
             with open(self.sherlock_config.trace_config_file_path, 'rb') as f: # [Vulnerable code] - Opens and reads user-provided config file without validation
                 remote_trace_filepath = self._generate_perfetto_trace_filename()
                 adb_perfetto_command_line = self._build_perfetto_shell_cmd(
                     remote_trace_filepath
                 )
                 proc = _adb_direct(
                     adb_perfetto_command_line,
                     self.serial,
                     stdin=f, # [Vulnerable code] - Passes user-provided config file content to perfetto
                     stdout=subprocess.PIPE,
                 )
                 # ...
         ```
    - **Visualization**:
      ```mermaid
      graph LR
          A[sherlock.py: _handle_device_manager] --> B(sherlock_config.SherlockConfig);
          B --> C[device_manager.py: DeviceManager];
          C --> D[sherlock_device.py: ConnectedDevice];
          D --> E[sherlock_device.py: start_perfetto];
          E --> F{open(trace_config_file_path)};
          F --> G[subprocess.Popen(perfetto, stdin=f)];
          G --> H[Android Device: perfetto with malicious config];
      ```
      The diagram shows the flow of execution where the user-provided `perfetto_config_file_path` is directly used to read the configuration and execute the `perfetto` command on the Android device, highlighting the lack of validation.

* Security Test Case:
    1. **Preparation:**
        * Set up a test environment with the Sherlock tool installed and a connected Android device configured for Perfetto tracing as per the README.
        * Create a malicious Perfetto configuration file (e.g., `malicious_config.pbtx`) that is designed to capture sensitive data. For example, configure it to trace `logcat` events with verbose logging or capture system metrics like location data if possible with Perfetto config. A simple example is to capture `filesystem` category to potentially monitor file access. Example `malicious_config.pbtx`:
          ```textproto
          buffers: {
            size_kb: 8192
            fill_policy: RING_BUFFER
          }
          data_sources: {
            config {
              name: "linux.ftrace"
              ftrace_config {
                ftrace_events: "filesystem/inode_rename"
                ftrace_events: "filesystem/inode_unlink"
                ftrace_events: "filesystem/mkdir"
                ftrace_events: "filesystem/open"
                ftrace_events: "filesystem/read"
                ftrace_events: "filesystem/rmdir"
                ftrace_events: "filesystem/rename"
                ftrace_events: "filesystem/symlink"
                ftrace_events: "filesystem/unlink"
                atrace_categories: "filesystem"
              }
            }
          }
          ```
        * Convert this textproto to binary format `malicious_config.bin` using `protoc` as described in README.md.
    2. **Execution:**
        * Run Sherlock in `device-manager` mode, providing the malicious configuration file and specifying a traces directory:
          ```bash
          python sherlock.py device-manager --perfetto-config-file malicious_config.bin --traces-directory malicious_traces --operation TERMINATE_COLLECT
          ```
        * Allow Sherlock to capture the trace.
    3. **Verification:**
        * After the trace collection is complete, analyse the collected trace file (located in `malicious_traces/<device_serial>`).
        * Use `perfetto` UI or `traceconv` command line tool to inspect the trace file (`.pftrace`) content.
        * Check if the trace file contains the data that the malicious configuration was intended to capture (e.g., filesystem events from `malicious_config.pbtx`). If the configuration was designed to capture sensitive data (like location if possible through config, or logcat), verify if that sensitive data is present in the trace.
        * For the example `malicious_config.pbtx`, inspect the trace for filesystem events.
    4. **Expected Result:**
        * The trace file should contain data as configured in `malicious_config.bin`, demonstrating that the tool blindly accepts and uses the provided configuration file. This validates the vulnerability of Malicious Perfetto Config File Injection.