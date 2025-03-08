## Combined Vulnerability List

### Unvalidated Perfetto Configuration File leads to Potential Sensitive Data Exposure
*   **Description:**
    1.  An attacker crafts a malicious Perfetto configuration file. This file is designed to capture sensitive data from the Android device, such as detailed location history, contact information, or application-specific data, by specifying appropriate tracing categories and data sources.
    2.  The attacker tricks a user into using Sherlock in `device-manager` mode with the malicious configuration file. This could be achieved through social engineering, by sharing the malicious configuration file and instructing the user to use it with Sherlock.
    3.  The user executes Sherlock with the command: `python sherlock.py device-manager --perfetto-config-file <malicious_config_file> --traces-directory <traces_directory> --operation TERMINATE_COLLECT`.
    4.  Sherlock's `device-manager` mode, without validating the configuration file, passes the path to the `perfetto` command on the Android device.
    5.  The `perfetto` tool on the device uses the provided malicious configuration to start tracing.
    6.  As the device operates, `perfetto` captures trace data as specified in the malicious configuration, potentially including sensitive user information.
    7.  Sherlock collects the generated trace file from the device and stores it in the specified `--traces-directory` on the user's local machine.
    8.  The attacker, if they gain access to the trace file (e.g., if the user unknowingly shares it or if it's stored in a publicly accessible location), can then analyze it to extract the sensitive data captured due to the malicious configuration.

*   **Impact:**
    *   **Confidentiality Breach:** Sensitive user data from the Android device, such as personal information, location history, communication logs, or application data, can be captured in the Perfetto trace file.
    *   **Privacy Violation:** Exposure of personal and potentially private user data to unauthorized parties.
    *   **Reputational Damage:** If Sherlock is used in contexts where data privacy is critical, this vulnerability could severely damage the tool's reputation and user trust.

*   **Vulnerability Rank:** High

*   **Currently Implemented Mitigations:**
    *   None. The application currently lacks any input validation or sanitization for the Perfetto configuration file. It directly uses the user-provided file path to execute the `perfetto` command.

*   **Missing Mitigations:**
    *   **Configuration File Validation:** Implement validation of the Perfetto configuration file before passing it to the `perfetto` command. This validation should include:
        *   **Schema Validation:** Verify the configuration file against the expected Perfetto configuration schema to ensure it adheres to the correct format and structure.
        *   **Content Sanitization:** Analyze the configuration content to identify and remove or neutralize potentially malicious or overly broad tracing configurations that could lead to excessive data capture. This might involve limiting allowed tracing categories or data sources to a predefined safe list.
        *   **Size Limits:** Impose limits on the size of the configuration file to prevent excessively large or complex configurations that could be used for denial-of-service or other attacks.
    *   **Principle of Least Privilege for Tracing:**  Educate users about the importance of using minimal necessary tracing configurations and the potential privacy implications of overly verbose tracing. Provide example configurations that are safe and sufficient for common use cases.
    *   **Warning to User:**  Display a clear warning to the user when using `device-manager` mode, emphasizing the security risks associated with using untrusted Perfetto configuration files and advising them to only use configurations from trusted sources.

*   **Preconditions:**
    *   The attacker needs to create a malicious Perfetto configuration file.
    *   The attacker must trick a user into using Sherlock's `device-manager` mode with this malicious configuration file.
    *   The user must have an Android device connected and be able to run Sherlock in `device-manager` mode.

*   **Source Code Analysis:**
    1.  **`src/sherlock.py: _handle_device_manager(args: argparse.Namespace)`:**
        ```python
        def _handle_device_manager(args: argparse.Namespace) -> None:
          """Handle device monitoring based on command-line arguments.
          ...
          """
          dm = device_manager.DeviceManager(
              config=sherlock_config.SherlockConfig(
                  local_output_dir=args.traces_directory,
                  trace_config_file_path=args.perfetto_config_file, # [VULNERABILITY POINT 1]
              ),
              mode=args.operation,
          )
          ...
          dm.start_monitoring_devices()
          ...
        ```
        *   The `_handle_device_manager` function in `sherlock.py` takes the `--perfetto-config-file` argument directly from the command line arguments (`args.perfetto_config_file`) and passes it to the `SherlockConfig` object.
        *   **Vulnerability Point 1:** No validation or sanitization is performed on `args.perfetto_config_file` at this stage.

    2.  **`src/sherlock/sherlock_config.py: class SherlockConfig`:**
        ```python
        @dataclasses.dataclass
        class SherlockConfig:
          """Configuration for Sherlock.
          ...
          """
          local_output_dir: str
          trace_config_file_path: str # [VULNERABILITY POINT 2]
          ...
        ```
        *   The `SherlockConfig` class simply stores the `trace_config_file_path` without any processing or validation.
        *   **Vulnerability Point 2:** The `trace_config_file_path` attribute in `SherlockConfig` directly holds the user-provided path without validation.

    3.  **`src/sherlock/sherlock_device.py: class ConnectedDevice`, `start_perfetto()`:**
        ```python
        class ConnectedDevice:
          ...
          def start_perfetto(self) -> bool:
            """Start a perfetto tracing session on the device.
            ...
            """
            ...
            with open(self.sherlock_config.trace_config_file_path, 'rb') as f: # [VULNERABILITY POINT 3]
              remote_trace_filepath = self._generate_perfetto_trace_filename()
              adb_perfetto_command_line = self._build_perfetto_shell_cmd(
                  remote_trace_filepath
              )
              proc = _adb_direct(
                  adb_perfetto_command_line,
                  self.serial,
                  stdin=f, # [VULNERABILITY POINT 4] - Config file content as stdin
                  stdout=subprocess.PIPE,
              )
              ...
        ```
        *   In `ConnectedDevice.start_perfetto()`, the code opens the file specified by `self.sherlock_config.trace_config_file_path` directly in read-binary mode (`'rb'`).
        *   **Vulnerability Point 3:** The file path from `SherlockConfig` (which is directly from user input) is used to open the configuration file without any checks.
        *   **Vulnerability Point 4:** The content of this user-provided file is then directly passed as standard input (`stdin=f`) to the `perfetto` command executed on the Android device via `adb_direct`. This means the untrusted configuration file content directly controls the behavior of `perfetto` without any intermediate validation by Sherlock.

        **Visualization:**

        ```
        User Input (--perfetto-config-file) --> sherlock.py (_handle_device_manager) --> SherlockConfig (trace_config_file_path) --> sherlock_device.py (ConnectedDevice.start_perfetto) --> open(trace_config_file_path, 'rb') --> subprocess.Popen(..., stdin=config_file_content) --> adb shell perfetto ... -c - (config as stdin) --> Perfetto on Android Device (starts tracing based on config)
        ```

*   **Security Test Case:**
    1.  **Prepare a Malicious Perfetto Config File (e.g., `malicious_config.pbtxt`):**
        ```textproto
        buffers: {
          size_kb: 8192
          fill_policy: RING_BUFFER
        }
        data_sources: {
          config {
            name: "linux.raw_events"
            target_buffer: 0
            raw_event_config {
              event_names: "binder_transaction"
              event_names: "binder_command"
              event_names: "dms_binder_transaction"
              event_names: "dms_binder_command"
              event_names: "ion_buffer_create"
              event_names: "ion_buffer_destroy"
              event_names: "ion_buffer_map"
              event_names: "ion_buffer_unmap"
              event_names: "ion_alloc_call"
              event_names: "ion_free_call"
              event_names: "mali_kbase_mem_import"
              event_names: "mali_kbase_mem_export"
              event_names: "mali_kbase_mem_alloc"
              event_names: "mali_kbase_mem_free"
              event_names: "mali_kbase_api_call"
              event_names: "mali_userspace_mem_alloc"
              event_names: "mali_userspace_mem_free"
              event_names: "power_cpu_idle"
              event_names: "power_cpu_state"
              event_names: "power_cpu_frequency"
              event_names: "power_gpu_frequency"
              event_names: "power_memory_state"
              event_names: "res_desc_set_create"
              event_names: "res_desc_set_destroy"
              event_names: "res_render_pass_begin"
              event_names: "res_render_pass_end"
              event_names: "res_cmd_encoder_create"
              event_names: "res_cmd_encoder_destroy"
              event_names: "res_buffer_create"
              event_names: "res_buffer_destroy"
              event_names: "res_texture_create"
              event_names: "res_texture_destroy"
              event_names: "res_sampler_create"
              event_names: "res_sampler_destroy"
              event_names: "res_pipeline_create"
              event_names: "res_pipeline_destroy"
              event_names: "res_query_create"
              event_names: "res_query_destroy"
              event_names: "res_fence_create"
              event_names: "res_fence_destroy"
              event_names: "res_semaphore_create"
              event_names: "res_semaphore_destroy"
              event_names: "gpu_memory_total"
              event_names: "gpu_memory_used"
              event_names: "gpu_renderstage"
              event_names: "gpu_counter_query"
              event_names: "gpu_frame_completion"
              event_names: "gpu_queue_submit"
              event_names: "tracing_mark_write"
              event_names: "tracing_mark_write_instant"
              event_names: "tracing_mark_write_begin"
              event_names: "tracing_mark_write_end"
              event_names: "tracing_mark_object_new"
              event_names: "tracing_mark_object_delete"
              event_names: "tracing_mark_object_dump"
              event_names: "batt_current"
              event_names: "batt_voltage"
              event_names: "thermal_throttle_cpu"
              event_names: "thermal_throttle_gpu"
              event_names: "thermal_throttle_vpu"
              event_names: "thermal_throttle_modem"
              event_names: "thermal_throttle_ambient"
              event_names: "thermal_throttle_battery"
              event_names: "thermal_throttle_skin"
              event_names: " thermal_engine_clamp"
              event_names: "thermal_engine_override"
              event_names: "thermal_engine_sample"
              event_names: "thermal_device_temp"
              event_names: "cpufreq_interaction"
              event_names: "cpufreq_min_max"
              event_names: "cpuidle"
              event_names: "cdev_update"
              event_names: "clock_enable"
              event_names: "clock_disable"
              event_names: "clock_set_rate"
              event_names: "clock_get_rate"
              event_names: "sync_timeline_wait_begin"
              event_names: "sync_timeline_wait_end"
              event_names: "sync_pt_wait_begin"
              event_names: "sync_pt_wait_end"
              event_names: "sync_merge"
              event_names: "sync_fence_create"
              event_names: "sync_fence_destroy"
              event_names: "page_fault_count"
              event_names: "rss_anon_count"
              event_names: "rss_file_count"
              event_names: "rss_shmem_count"
              event_names: "vsize_count"
              event_names: "oom_kill"
              event_names: "memfd_create"
              event_names: "dmabuf_cache_hit"
              event_names: "dmabuf_cache_miss"
              event_names: "dmabuf_import"
              event_names: "dmabuf_export"
              event_names: "task_sched_wakeup"
              event_names: "task_sched_blocked"
              event_names: "task_sched_pi_blocked"
              event_names: "task_sched_migrate_task"
              event_names: "task_sched_process_execve"
              event_names: "task_sched_process_fork"
              event_names: "task_sched_process_exit"
              event_names: "task_sched_process_free"
              event_names: "task_sched_process_tick"
              event_names: "task_sched_switch"
              event_names: "task_sched_irq_off"
              event_names: "task_sched_irq_on"
              event_names: "task_sched_preempt_off"
              event_names: "task_sched_preempt_on"
              event_names: "task_sched_stat_run_delay"
              event_names: "task_sched_stat_seep_delay"
              event_names: "task_sched_stat_blocked_delay"
              event_names: "task_sched_stat_wait_delay"
              event_names: "task_sched_stat_sleep_delay"
              event_names: "task_sched_stat_iowait_delay"
              event_names: "task_sched_stat_voluntary_switch"
              event_names: "task_sched_stat_involuntary_switch"
              event_names: "task_sched_stat_page_reclaim_count"
              event_names: "task_sched_stat_page_fault_count"
              event_names: "task_sched_stat_context_switch_count"
              event_names: "task_sched_stat_bpf_output"
              event_names: "irq_handler_entry"
              event_names: "irq_handler_exit"
              event_names: "softirq_entry"
              event_names: "softirq_exit"
              event_names: "android_log_print"
              event_names: "ftrace_marker"
              event_names: "userspace_trace_mark"
              event_names: "print"
            }
          }
        }
        ```

    2.  **Convert the textproto config to binary format (malicious_config.bin):**
        ```bash
        ./protoc/bin/protoc --encode=perfetto.protos.TraceConfig -I. perfetto_config.proto < malicious_config.pbtxt > malicious_config.bin
        ```

    3.  **Run Sherlock in `device-manager` mode with the malicious config file:**
        ```bash
        python sherlock.py device-manager --perfetto-config-file malicious_config.bin --traces-directory ./traces --operation TERMINATE_COLLECT
        ```

    4.  **Analyze the captured trace file (`./traces/<serial>/<timestamp>-<random_suffix>.pftrace`):**
        *   Open the trace file in `perfetto UI` (ui.perfetto.dev) or using `trace_processor`.
        *   Examine the trace data to verify if the trace contains the events specified in the malicious configuration (e.g., `binder_transaction`, `task_sched_switch`, `android_log_print`, etc.).
        *   If the trace contains the events from the malicious config, it confirms that the unvalidated configuration file was successfully used by Perfetto to capture trace data.
        *   In a more targeted attack scenario, if the malicious config was designed to capture specific user data (and if such data is accessible via Perfetto categories), verify if that data is present in the trace.

    5.  **Expected Result:**
        *   The trace file should contain data corresponding to the events and categories defined in `malicious_config.bin`, demonstrating that Sherlock blindly uses the provided configuration file, leading to the capture of potentially excessive or sensitive data as dictated by the malicious configuration.

### SQL Injection in Perfetto Trace Analysis
*   **Description:**
    - An attacker crafts a malicious Perfetto trace file specifically designed to exploit a potential SQL injection vulnerability within the `perfetto.trace_processor.TraceProcessor` library. This library is used by Sherlock to parse and analyze trace data.
    - The attacker then tricks a user into analyzing this malicious trace file using Sherlock's `trace-analysis` mode. The user is unaware of the file's malicious nature and uses Sherlock to process it.
    - Sherlock, in its `trace-analysis` mode, utilizes the `perfetto.trace_processor.TraceProcessor` to parse the provided trace file.
    - During analysis, Sherlock executes SQL queries against the parsed trace data using `TraceProcessor` (e.g., in modules like `analysis_url.py` which uses `tp.query()`).
    - The malicious trace file is crafted such that when parsed and queried, it injects malicious SQL code into the queries executed by `TraceProcessor`.
    - This injected SQL code is then executed by `TraceProcessor`, potentially leading to arbitrary code execution on the user's machine running Sherlock.
*   **Impact:**
    - Arbitrary code execution on the user's machine.
    - Successful exploitation could allow an attacker to gain complete control over the system running Sherlock, potentially leading to data theft, malware installation, or further system compromise.
*   **Vulnerability Rank:** Critical
*   **Currently Implemented Mitigations:**
    - None. The current Sherlock project does not implement any specific mitigations against malicious trace files. It directly utilizes the `perfetto` library without any input validation, sanitization, or sandboxing.
*   **Missing Mitigations:**
    - Input validation and sanitization of the Perfetto trace file content before it is processed by `perfetto.trace_processor.TraceProcessor`. This should include checks to ensure the trace file conforms to expected formats and does not contain malicious payloads designed to exploit parsing vulnerabilities.
    - Sandboxing the trace analysis process. Running the `trace-analysis` in a restricted environment (e.g., using containers or virtual machines) can limit the impact of successful code execution, preventing attackers from gaining full system access.
    - Regular updates and monitoring of the `perfetto` library for known vulnerabilities. Keeping the `perfetto` dependency updated to the latest version is crucial to patch any security flaws discovered in the library itself.
    - Implementing a policy to only analyze traces from trusted sources. Warn users about the risks of analyzing trace files from untrusted or unknown sources.
*   **Preconditions:**
    - The user must have Sherlock installed and must execute the `trace-analysis` mode.
    - The user must be tricked into analyzing a malicious Perfetto trace file provided by an attacker. This could be achieved through social engineering or by hosting the malicious file on a seemingly legitimate platform.
    - The `perfetto.trace_processor.TraceProcessor` library must be vulnerable to SQL injection or other types of parsing vulnerabilities that can be exploited through a crafted trace file.
*   **Source Code Analysis:**
    - `src/sherlock/sherlock_analysis.py`: The `TraceAnalysis.run_analysis` method orchestrates the trace analysis process. It iterates through the list of trace files and analysis modules provided.
    - For each trace file and analysis module, it calls `analysis_module.run(trace_filepath)`. This is where the actual trace parsing and analysis take place.
    - `src/sherlock/analysis/analysis_url.py` (example analysis module): The `TraceAnalysisModuleUrl.run` method demonstrates how trace files are processed.
        ```python
        def run(self, trace_filepath: str) -> trace_analysis.TraceAnalysisModuleResult:
            logging.info(
                'Running %s module on trace %s', self.module_name, trace_filepath
            )
            self.trace_filepath = trace_filepath
            results = {}
            for url_id, url in _extract_url_information(
                TraceProcessor(trace=trace_filepath) # TraceProcessor is instantiated here
            ):
                results[url_id] = {'url': url}
            return trace_analysis.TraceAnalysisModuleResult(
                module_name=self.module_name,
                trace_filepath=trace_filepath,
                results=results,
            )
        ```
        - Inside `analysis_url.py`, `TraceProcessor(trace=trace_filepath)` is instantiated with the user-provided `trace_filepath`. This `TraceProcessor` instance is then used to execute SQL queries against the trace data using `tp.query()`.
        - The code directly passes the user-provided trace file to the `TraceProcessor` without any prior validation or sanitization. If `perfetto.trace_processor.TraceProcessor` has vulnerabilities in its parsing or query execution logic, a malicious trace file could exploit these vulnerabilities.
*   **Security Test Case:**
    - Step 1: Setup
        - Install Sherlock and its dependencies using `pip install -r requirements.txt`.
        - Create a directory to store the malicious trace file, e.g., `/tmp/malicious_traces/`.
        - Craft a malicious Perfetto trace file named `malicious.pftrace`. This file should be designed to exploit a hypothetical SQL injection vulnerability in the `perfetto.trace_processor.TraceProcessor` library when processing SQL queries.  *(Note: Creating a real malicious trace file requires deep understanding of `perfetto` internals and potential vulnerabilities, which might require dedicated security research. For testing purposes, you might need to simulate a vulnerable scenario or use a known vulnerable version of `perfetto` if one exists and is publicly documented.)*
        - Place the `malicious.pftrace` file inside the `/tmp/malicious_traces/` directory.
    - Step 2: Execution
        - Execute Sherlock in `trace-analysis` mode, specifying the directory containing the malicious trace file and using the `ANALYSIS_URL` module.
          ```bash
          python sherlock.py trace-analysis --traces-directory /tmp/malicious_traces --module ANALYSIS_URL
          ```
    - Step 3: Verification
        - Monitor the execution of Sherlock. Successful exploitation of a SQL injection vulnerability could manifest in several ways, such as:
          - Sherlock crashing or exhibiting unexpected behavior.
          - Error messages related to SQL parsing or execution.
          - If the vulnerability allows for more advanced exploitation, it might be possible to achieve arbitrary code execution. In a controlled test environment, you could attempt to make the exploit create a file on the file system, establish a network connection, or perform other observable actions that would indicate successful code execution.
        - Examine the output logs and any generated report files for anomalies or signs of successful exploitation.

### Path Traversal in Trace Output Directory
*   **Description:**
    1. The Sherlock tool allows users to specify the output directory for captured Perfetto traces using the `--traces-directory` command-line argument.
    2. This argument is used in both `device-manager` and `trace-analysis` modes.
    3. The tool uses `os.path.join` to construct the full path to save trace files, combining the user-provided `--traces-directory` with device serial numbers and trace filenames.
    4. However, the `--traces-directory` input is not properly validated or sanitized to prevent path traversal attacks.
    5. An attacker can provide a malicious path like `/tmp/output/../../../sensitive_dir` as the `--traces-directory`.
    6. When Sherlock attempts to create directories and save trace files, it will resolve the path traversal sequences, leading to file operations outside the intended `/tmp/output` directory.
    7. For example, if the attacker provides `/tmp/output/../../../sensitive_dir` and the device serial is `emulator-5554`, the tool might attempt to create a directory and save files in `/sensitive_dir/emulator-5554/`, potentially overwriting or creating files in sensitive locations.
*   **Impact:**
    * An attacker can write trace files to arbitrary locations on the file system where the Sherlock tool is executed.
    * This can lead to:
        * **Information Disclosure**: Overwriting existing files with trace data, potentially corrupting legitimate files.
        * **Data Corruption**: Creating new files in unexpected locations, which might interfere with system operations or other applications.
        * **Potential for Code Execution**: In a more severe scenario, if an attacker can predict file paths and permissions, they might be able to overwrite executable files or configuration files, potentially leading to arbitrary code execution when those overwritten files are used by the system or other users.
*   **Vulnerability Rank:** High
*   **Currently Implemented Mitigations:**
    * The tool uses `os.path.basename` when constructing the final trace filename before saving. This prevents path traversal through the filename itself. For example, if a malicious filename like `../../../evil.pftrace` is somehow generated, `os.path.basename` will reduce it to `evil.pftrace`, mitigating filename-based path traversal. However, this does not prevent path traversal in the directory path specified by `--traces-directory`.
    * Mitigation is present in `/code/src/sherlock/sherlock_device.py` in `collect_traces` function when saving the trace file:
    ```python
    self.adb_device.sync.pull(
        trace_filepath,
        f'{local_output_dirpath}{os.path.sep}{os.path.basename(trace_filepath)}',
    )
    ```
*   **Missing Mitigations:**
    * Input validation and sanitization for the `--traces-directory` argument in `sherlock.py`.
    * Implement path canonicalization and validation to ensure that the resolved output directory is within an expected and safe base directory. For example, resolve the absolute path of the user-provided `--traces-directory` using `os.path.abspath()` and check if it is a subdirectory of a predefined safe base path.
*   **Preconditions:**
    * The attacker needs to trick a user into running the Sherlock tool with a maliciously crafted `--traces-directory` argument. This could be achieved through social engineering or by providing a seemingly innocuous configuration file that suggests using a malicious output directory.
*   **Source Code Analysis:**
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

*   **Security Test Case:**
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