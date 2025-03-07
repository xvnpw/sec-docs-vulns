- vulnerability name: Code Injection via Gin Configuration File
- description: |
    The ML-fairness-gym library utilizes the Gin configuration library, which allows for dependency injection and configurable parameters defined in `.gin` or `.gcl` files. The `runner.py` script uses the `--gin_config_path` command-line argument to load a configuration file specified by the user.

    An attacker could exploit this by providing a malicious Gin configuration file through the `--gin_config_path` argument. Gin configuration files, while primarily for configuration, can execute arbitrary Python code through `gin.configurable` and bindings.

    Steps to trigger vulnerability:
    1. An attacker crafts a malicious Gin configuration file (e.g., `malicious_config.gin`) that includes code to be executed. This could involve using `gin.configurable` to decorate a malicious function or using bindings to execute code during configuration.
    2. The attacker tricks a user into running the `runner.py` script with the `--gin_config_path` argument pointing to the malicious configuration file:
       ```bash
       python -m runner --gin_config_path=malicious_config.gin --output_path=/tmp/output.json
       ```
    3. When `runner.py` parses and loads the malicious configuration file using Gin, the injected code within the configuration file gets executed.

- impact: |
    Successful exploitation of this vulnerability can lead to arbitrary code execution on the machine running the `runner.py` script. This could allow an attacker to:
    - Gain complete control over the user's system.
    - Steal sensitive data, including credentials and personal files.
    - Install malware or ransomware.
    - Pivot to other systems on the network.

- vulnerability rank: Critical
- currently implemented mitigations:
    - No specific mitigations are implemented within the project to prevent loading of arbitrary Gin configuration files. The project relies on users to provide trusted configuration files.
- missing mitigations:
    - Input validation: Implement validation to check the content of the Gin configuration file before loading it, ensuring it conforms to expected structure and doesn't contain potentially harmful code. This is challenging to implement robustly for Gin configuration files due to their flexibility.
    - Sandboxing or isolation: Run the `runner.py` script in a sandboxed or isolated environment with restricted permissions to limit the impact of potential code execution vulnerabilities.
    - Documentation and warnings: Clearly document the security risks associated with loading external Gin configuration files and warn users against using untrusted configuration files. While documentation exists, stronger warnings about code execution risks should be added.
- preconditions:
    - The user must execute the `runner.py` script.
    - The attacker must be able to provide or convince the user to use a malicious Gin configuration file path as the `--gin_config_path` argument.
- source code analysis: |
    1. **File: `/code/runner.py`**:
       - This script is the entry point for running experiments using the configurable runner.
       - It uses `gin.parse_config_file(FLAGS.gin_config_path)` to load the configuration file specified by the `--gin_config_path` command-line flag.
       - ```python
         gin.parse_config_file(FLAGS.gin_config_path)
         runner = runner_lib.Runner()
         results = runner.run()
         ```
       - The `gin.parse_config_file` function is the point where the external configuration file is parsed and executed by the Gin library.

    2. **File: `/code/runner_lib.py`**:
       - This file defines the `Runner` class, which uses the Gin library for configuration.
       - The `@gin.configurable` decorator is used throughout the codebase, enabling Gin to inject and configure objects based on the loaded configuration files.
       - This mechanism, while powerful for configuration, allows for arbitrary code execution if the configuration source is untrusted.

    3. **File: `/code/docs/using_runner.md`**:
       - This document explains how to use the configurable runner and mentions Gin configuration files.
       - Example configurations demonstrate how to register and configure classes using Gin, highlighting the dependency injection mechanism that can be exploited.

    In summary, the `runner.py` script directly loads and executes Gin configuration files specified by the user through the command line. The Gin library's design allows for arbitrary code execution through configuration files, making the `--gin_config_path` argument a potential injection point.

- security test case: |
    1. Create a malicious Gin configuration file named `malicious_config.gin` with the following content:
       ```gin
       import os
       import gin

       @gin.configurable
       def malicious_function():
           os.system('touch /tmp/pwned') # Example malicious command
           return 1

       Runner.env_class = @test_util.DummyEnv
       Runner.agent_class = @test_util.DummyAgent
       Runner.metric_classes = {'num_steps': @test_util.DummyMetric}
       Runner.num_steps = 10
       Runner.seed = 4321
       Runner.report_fn = @malicious_function
       ```
       This malicious configuration file defines a `malicious_function` which executes the `touch /tmp/pwned` command and registers it as `report_fn` for the `Runner`.

    2. Run the `runner.py` script, providing the path to the malicious configuration file:
       ```bash
       python -m runner --gin_config_path=malicious_config.gin --output_path=/tmp/output.json
       ```

    3. After running the command, check if the file `/tmp/pwned` exists. If the file exists, it confirms that the code injected through the malicious Gin configuration file was executed.

    This test case demonstrates that arbitrary code execution is possible by providing a crafted Gin configuration file to the `runner.py` script.