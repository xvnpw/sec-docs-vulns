- Vulnerability Name: Arbitrary Code Execution via Malicious Gin Configuration Files
- Description:
    - An attacker can craft a malicious Gin configuration file (e.g., `experiments/config/example.gcl`, `experiments/config/college_admission_config.gin`) that, when loaded by the `runner.py` script, executes arbitrary Python code.
    - Gin configuration files allow for defining object bindings and executing function calls. A malicious configuration can leverage these features to inject and execute code by:
        1. Defining a configurable Python function within a configuration file using `gin.configurable`.
        2. Crafting a Gin configuration file that imports and binds this configurable function.
        3. Within the configuration file, binding this function to be executed, potentially with attacker-controlled arguments.
        4. Executing `runner.py` with the malicious Gin configuration file using `--gin_config_path`.
- Impact:
    - Critical: Successful exploitation allows for arbitrary code execution on the user's machine with the privileges of the user running the `runner.py` script. This can lead to complete system compromise, data exfiltration, installation of malware, or denial of service.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None: The project does not implement any specific mitigations against loading and executing malicious Gin configuration files. The documentation mentions Gin usage but lacks security warnings.
- Missing Mitigations:
    - Input validation and sanitization: Implement strict validation of Gin configuration files to ensure they only contain expected configurations and not malicious code or function calls. Consider using a restricted Gin configuration parsing mode if available.
    - Sandboxing or isolation: Execute the configuration loading and simulation execution in a sandboxed environment or container with limited privileges to contain the impact of potential code execution vulnerabilities.
    - Security warnings in documentation: Add prominent security warnings in the documentation, especially in sections related to configuration and running experiments, advising users to only use trusted configuration files and be cautious about running configurations from untrusted sources.
- Preconditions:
    - The user must download and execute the `runner.py` script.
    - The attacker must be able to provide or convince the user to use a maliciously crafted Gin configuration file, either by social engineering, supply chain attack, or by compromising a location where configuration files are stored or downloaded from.
- Source Code Analysis:
    - File: `/code/runner.py`
        - This script is the entry point for running experiments and loads Gin configuration files using `gin.parse_config_file(FLAGS.gin_config_path)`.
    - File: `/code/runner_lib.py`
        - The `Runner` class uses Gin configuration to instantiate and configure environment, agent, and metrics.
        - The `@gin.configurable` decorator throughout the codebase makes various classes and functions configurable via Gin, increasing the attack surface.
    - File: `/code/docs/using_runner.md`
        - This document explains how to use the configurable runner and Gin configuration files, highlighting the use of `@gin.configurable` and configuration files (`.gin`, `.gcl`).
    - Visualization:
        ```mermaid
        graph LR
        A[runner.py] --> B(gin.parse_config_file);
        B --> C[Malicious Config File];
        C --> D(Arbitrary Code Execution);
        ```
- Security Test Case:
    1. Create a malicious Gin configuration file named `malicious_config.gin` with the following content:
        ```gin
        import os
        import fairness_gym.runner_lib

        Runner.report_fn = @malicious_report

        gin.configurable(os.system, name='system')

        @gin.configurable
        def malicious_report(env, agent, metric_results):
          system('touch /tmp/pwned')
          return {'metrics': metric_results}
        ```
    2. Save this file in the `/code/experiments/config/` directory.
    3. Run the `runner.py` script with the malicious configuration file:
        ```bash
        python -m runner --gin_config_path=experiments/config/malicious_config.gin --output_path=/tmp/output.json
        ```
    4. Check if the file `/tmp/pwned` was created. If the file exists, it confirms arbitrary code execution.
    5. Examine the `/tmp/output.json` file to ensure the runner completed execution as expected despite the malicious configuration, indicating the code execution happened within the normal program flow.

- Vulnerability Name: Insecure Deserialization in History Serialization/Deserialization
- Description:
    - The `FairnessEnv` class uses `simplejson` library with `GymEncoder` for serializing and deserializing the environment history using `serialize_history()` and potentially during metric computations via `_simulate` and `_extract_history`.
    - While `GymEncoder` attempts to handle `np.random.RandomState` and other Gym objects, there is a risk of insecure deserialization if a malicious actor can craft a history object that, when deserialized, leads to arbitrary code execution.
    - Specifically, the `GymEncoder` handles 'callable' types by storing their name and enums with `__enum__` key. If these are not handled securely during deserialization (although not explicitly shown in provided code snippet), they could be a potential attack vector. Furthermore, custom `Params` and `State` objects have `asdict()` method called and `to_json()` which might have insecure deserialization issues if attributes are not handled carefully.
- Impact:
    - High: If exploited, this vulnerability could allow an attacker to achieve arbitrary code execution by providing a crafted serialized history object to be loaded by the ML-fairness-gym library. This could occur if history files are stored and re-loaded, or during complex metric calculations that involve serialization and deserialization of environment states.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - Limited Type Handling in `GymEncoder`: The `GymEncoder` attempts to handle specific types like `RandomState`, `enum.Enum`, `callable`, `np.ndarray`, `nx.Graph`, `Params`, and `State`. However, this might not be sufficient to prevent all insecure deserialization attacks.
- Missing Mitigations:
    - Secure Deserialization Practices: Implement secure deserialization practices. Avoid using `eval` or similar unsafe methods during deserialization. If possible, rely on safer alternatives for handling custom objects or restrict deserialization to only allow pre-defined safe types.
    - Input Validation for History Objects: Implement robust input validation for history objects before deserialization to ensure they conform to expected schemas and do not contain malicious data.
    - Consider using safer serialization formats: Investigate using safer serialization formats that are less prone to code execution vulnerabilities compared to JSON when dealing with complex Python objects.
- Preconditions:
    - An attacker needs to be able to supply a maliciously crafted serialized history, potentially through:
        - Compromising a stored history file.
        - Intercepting and modifying history data during transmission, if history is transmitted across networks.
        - Tricking a user or developer into loading a malicious history for debugging or analysis.
- Source Code Analysis:
    - File: `/code/core.py`
        - `GymEncoder` class is used for JSON serialization and deserialization.
        - `to_json()` function uses `GymEncoder`.
        - `serialize_history()` method in `FairnessEnv` uses `to_json()` to serialize history.
        - Metric class's `_simulate` and `_extract_history` might involve deserialization when working with environment history although not explicitly shown in the provided code.
    - Visualization:
        ```mermaid
        graph LR
        A[FairnessEnv.serialize_history()] --> B(core.to_json);
        B --> C(GymEncoder);
        C --> D[JSON Serialization of History];
        E[Metric._extract_history() or _simulate()] --> F[JSON Deserialization of History];
        F --> C;
        C --> G(Potential Insecure Deserialization);
        ```
- Security Test Case:
    1. Craft a malicious JSON payload that, when deserialized by `GymEncoder`, attempts to execute arbitrary code (e.g., using a callable object or manipulated state). This requires deeper code analysis of `GymEncoder` and potentially `simplejson` to identify specific vulnerabilities. A simplified example might involve trying to serialize and deserialize a callable and check if it can be invoked upon deserialization, although `GymEncoder` attempts to serialize callable names rather than the callable itself.
    2. Modify a test or example script to load this malicious JSON payload as environment history or state.
    3. Run the modified script and observe if arbitrary code execution occurs (e.g., by checking for creation of a file or network activity).
    4. If code execution is successful, it confirms the insecure deserialization vulnerability.