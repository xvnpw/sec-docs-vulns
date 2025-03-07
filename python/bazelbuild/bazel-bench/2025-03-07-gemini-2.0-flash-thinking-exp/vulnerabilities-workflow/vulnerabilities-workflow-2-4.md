### Vulnerability 1: Command Injection via Bazel Command Arguments

- **Description:**
    1. The `bazel-bench` application parses Bazel commands and arguments from command-line flags and configuration files.
    2. Specifically, the `BenchmarkConfig._parse_unit` function in `/code/utils/benchmark_config.py` uses `shlex.split()` to parse the `command` string from user-provided input.
    3. This parsed command, along with its arguments, is then passed to the `Bazel.command` function in `/code/utils/bazel.py`.
    4. The `Bazel.command` function executes this command using `subprocess.check_call()` without any sanitization of the arguments.
    5. An attacker can inject arbitrary shell commands by crafting malicious Bazel arguments, either through command-line flags after the `--` separator or within the `command` field of the `config.yaml` file.
    6. When the `benchmark.py` script executes the Bazel command, the injected shell commands will also be executed, leading to command injection.

- **Impact:**
    - Arbitrary command execution on the server or machine running the `bazel-bench` script.
    - An attacker could potentially gain full control of the system, steal sensitive data, or cause denial of service.
    - This vulnerability is critical as it allows for remote code execution if the benchmark tool is exposed or if an attacker can influence the configuration or command-line arguments.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - None. The use of `shlex.split()` is for command parsing, not for security sanitization.
    - While `subprocess.check_call()` is used with `shell=False` (by default implicitly), this only prevents shell injection through the command string itself, not through the arguments if they are attacker-controlled.

- **Missing Mitigations:**
    - Input sanitization and validation of all user-provided Bazel command arguments, both from command-line flags and configuration files.
    - Consider using parameterized commands or a safer method to construct and execute commands with user-provided arguments, ensuring no shell metacharacters can be interpreted maliciously.
    - Implement least privilege principles for the user account running the benchmark tool to limit the impact of successful command injection.

- **Preconditions:**
    - The attacker must be able to provide command-line arguments to the `benchmark.py` script when it is executed. This is typically the case for users running the benchmark locally or in CI environments where parameters can be controlled.
    - Alternatively, if the benchmark is configured to use a configuration file (`config.yaml`), the attacker must be able to modify the content of this configuration file.

- **Source Code Analysis:**
    1. **`/code/utils/benchmark_config.py`:**
        ```python
        # File: /code/utils/benchmark_config.py
        class BenchmarkConfig(object):
            # ...
            @classmethod
            def _parse_unit(cls, unit):
                # ...
                full_command_tokens = shlex.split(unit['command']) # [VULNERABLE CODE] Command string is parsed using shlex.split
                # ...
                parsed_unit['startup_options'] = startup_options
                parsed_unit['command'] = command
                parsed_unit['options'] = options
                parsed_unit['targets'] = targets
                return parsed_unit
        ```
        - The `_parse_unit` method in `BenchmarkConfig` class uses `shlex.split()` to parse the `command` string from the configuration. This is the initial parsing point where user input is processed.

    2. **`/code/benchmark.py`:**
        ```python
        # File: /code/benchmark.py
        def _run_benchmark(bazel_bin_path,
                           project_path,
                           runs,
                           command,
                           options,
                           targets,
                           startup_options,
                           prefetch_ext_deps,
                           bazel_bench_uid,
                           unit_num,
                           data_directory=None,
                           collect_profile=False,
                           bazel_identifier=None,
                           project_commit=None):
            # ...
            results = _single_run(
                bazel_bin_path=unit['bazel_bin_path'],
                project_path=project_clone_repo.working_dir,
                runs=unit['runs'],
                command=unit['command'],
                options=unit['options'],
                targets=unit['targets'],
                startup_options=unit['startup_options'],
                prefetch_ext_deps=FLAGS.prefetch_ext_deps,
                bazel_bench_uid=bazel_bench_uid,
                unit_num=i,
                collect_profile=unit['collect_profile'],
                data_directory=data_directory,
                bazel_identifier=bazel_identifier,
                project_commit=project_commit)

        def _single_run(bazel_bin_path,
                        command,
                        options,
                        targets,
                        startup_options):
            # ...
            bazel = Bazel(bazel_bin_path, startup_options)
            # ...
            measurements = bazel.command(command, args=options + targets) # Calls Bazel.command with parsed command and args
            # ...

        ```
        - `_run_benchmark` and `_single_run` orchestrate the benchmark execution and eventually call `Bazel.command`. The `command`, `options`, and `targets` are passed directly from the parsed configuration.

    3. **`/code/utils/bazel.py`:**
        ```python
        # File: /code/utils/bazel.py
        class Bazel(object):
            # ...
            def command(self, command, args=None):
                # ...
                subprocess.check_call( # [VULNERABLE CODE] Command is executed using subprocess.check_call without sanitization
                    [self._bazel_binary_path] + self._startup_options + [command] + args, # Arguments are directly used in subprocess.check_call
                    stdout=dev_null,
                    stderr=tmp_stdout.file)
                # ...
        ```
        - The `Bazel.command` method in `utils/bazel.py` executes the Bazel command using `subprocess.check_call()`. Critically, it directly uses the `args` list (which originates from the parsed user input) without any sanitization, making it vulnerable to command injection.

- **Security Test Case:**
    1. Create a file named `evil_config.yaml` with the following content:
        ```yaml
        units:
          - command: 'build -- ; touch /tmp/pwned ; -- //:all'
        ```
        This configuration attempts to inject a `touch /tmp/pwned` command after the `build` command and before the targets, using `;` as a command separator, which is commonly effective in shell command injection.
    2. Run the `bazel-bench` script using the created configuration file. Navigate to the root directory of the `bazel-bench` project in a terminal and execute the following command:
        ```shell
        bazel run :benchmark -- --benchmark_config=evil_config.yaml
        ```
    3. After the benchmark script finishes execution, check if the file `/tmp/pwned` exists on the system. Execute the following command in the terminal:
        ```shell
        ls /tmp/pwned
        ```
    4. **Expected Result:** If the file `/tmp/pwned` exists, it confirms that the command injection was successful. The injected command `touch /tmp/pwned` was executed by the system when the benchmark script ran the Bazel command, proving the vulnerability. If the file exists, the test case is successful and the vulnerability is validated.