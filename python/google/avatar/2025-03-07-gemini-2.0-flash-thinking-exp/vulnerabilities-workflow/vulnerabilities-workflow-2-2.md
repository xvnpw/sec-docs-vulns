- Vulnerability Name: YAML Deserialization leading to Arbitrary Code Execution
- Description:
    1. The Avatar application parses configuration files in YAML format using the `mobly` library.
    2. The `mobly` library's configuration parsing functionality, specifically `config_parser.load_test_config_file`, may use the unsafe `yaml.load` function from PyYAML library without specifying `SafeLoader`.
    3. An attacker can craft a malicious `config.yml` file containing a YAML payload that exploits the deserialization vulnerability in `yaml.load`.
    4. When the Avatar application loads this malicious `config.yml` file using the `-c` or `--config` command-line arguments, the `mobly` library will parse it.
    5. Due to the unsafe `yaml.load` usage, the malicious YAML payload will be deserialized, leading to arbitrary code execution on the system running the Avatar application.
- Impact:
    - Arbitrary code execution on the machine running the Avatar tool.
    - Full compromise of the affected system, including data confidentiality, integrity, and availability.
    - Potential for lateral movement to other systems accessible from the compromised machine.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None. The code relies on `mobly` library for configuration parsing, and there are no explicit mitigations implemented in the Avatar project to prevent YAML deserialization vulnerabilities.
- Missing Mitigations:
    - Usage of `yaml.safe_load` instead of `yaml.load` in `mobly`'s `config_parser.load_test_config_file` or wherever YAML is parsed to prevent arbitrary code execution during deserialization.
    - Input validation and sanitization of the configuration file content before parsing to detect and reject potentially malicious payloads.
- Preconditions:
    - The attacker needs to be able to provide a malicious `config.yml` file to the Avatar application. This could be achieved if the attacker can influence the command-line arguments used to run the Avatar tool, or if the application is configured to load configuration files from an attacker-controlled location.
- Source Code Analysis:
    1. **`avatar/runner.py`**: This file uses `mobly` library's `config_parser.load_test_config_file` function to load configuration files:
    ```python
    from mobly import config_parser

    class SuiteRunner:
        # ...
        def add_config_file(self, path: pathlib.Path) -> None:
            self.test_run_configs += config_parser.load_test_config_file(str(path))  # type: ignore
        # ...
    ```
    2. **`avatar/__init__.py`**: This file defines the `main` function which uses `SuiteRunner` to load configuration files based on command-line arguments:
    ```python
    import argparse
    import pathlib
    from avatar.runner import SuiteRunner

    def main(args: Optional[argparse.Namespace] = None) -> None:
        # ...
        runner = SuiteRunner()
        # ...
        argv = args or args_parser().parse_args()
        if argv.config:
            runner.add_config_file(pathlib.Path(argv.config))
        # ...
        runner.run()
    ```
    3. **`mobly/config_parser.py` (External - not in PROJECT FILES)**: Assuming `mobly` library uses PyYAML to parse YAML files and if `config_parser.load_test_config_file` internally uses `yaml.load` without `SafeLoader`, it will be vulnerable to YAML deserialization attacks.

- Security Test Case:
    1. **Prerequisites:**
        - Attacker machine with Python and `pip` installed.
        - Access to the Avatar project code.
        - Ability to execute the `avatar` command with custom arguments.
    2. **Craft Malicious `config.yml`:**
        - Create a file named `malicious_config.yml` with the following content. This payload will execute the `touch /tmp/pwned` command on the system.
        ```yaml
        test_beds:
          - name: malicious_testbed
            controllers:
              BumbleDevice:
                - transport: 'tcp-client:127.0.0.1:6402'
        !!python/object/apply:os.system ["touch /tmp/pwned"]
        ```
    3. **Run Avatar with Malicious Configuration:**
        - Execute the Avatar tool with the malicious configuration file using the `-c` option:
        ```bash
        python avatar cases/host_test.py -c malicious_config.yml --verbose
        ```
    4. **Verify Code Execution:**
        - Check if the file `/tmp/pwned` has been created on the system running the Avatar tool.
        - If the file `/tmp/pwned` exists, it confirms that the YAML deserialization vulnerability was successfully exploited, and arbitrary code execution was achieved.