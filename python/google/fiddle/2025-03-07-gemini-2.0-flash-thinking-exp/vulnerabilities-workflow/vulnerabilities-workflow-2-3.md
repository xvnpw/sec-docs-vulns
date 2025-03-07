- Vulnerability Name: YAML Deserialization leading to Arbitrary Code Execution
- Description:
    1. An attacker crafts a malicious YAML file.
    2. This YAML file leverages the `!fdl.Config` tag, intended for Fiddle's internal use, to embed Python object instantiation instructions within the YAML data.
    3. A Fiddle-based application, if configured to load YAML configurations without proper sanitization, parses this malicious YAML file using a YAML loader that is configured to instantiate Python objects from tags.
    4. The YAML loader, upon encountering the `!fdl.Config` tag with attacker-controlled parameters, dynamically instantiates Python objects as specified in the YAML.
    5. If the attacker carefully crafts the YAML to instantiate malicious Python objects or manipulate existing ones in a harmful way, it can lead to arbitrary code execution within the application's context.
- Impact: Arbitrary code execution. An attacker can potentially gain full control over the application or the system where the application is running, leading to data breaches, system compromise, and other malicious activities.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None. The code examples and documentation highlight the usage of YAML for configuration, but there are no explicit warnings against loading untrusted YAML or sanitization guidelines within the provided files.
- Missing Mitigations:
    - Input sanitization: Implement strict input validation and sanitization for all configuration data, especially YAML and JSON, to prevent the injection of malicious payloads.
    - Secure YAML loading:  Avoid using YAML loaders that automatically execute code from tags (like `yaml.unsafe_load` or `yaml.Loader` with default constructors). If YAML loading is necessary, use `yaml.safe_load` or a custom loader that explicitly disables tag processing or only allows safe tags and constructs.
    - Principle of least privilege: Ensure that the application runs with the minimal necessary privileges to limit the impact of potential code execution vulnerabilities.
    - Sandboxing/Isolation: Isolate the configuration loading and parsing process from the core application logic using sandboxing or process isolation techniques to restrict the damage caused by successful exploits.
- Preconditions:
    1. The application using Fiddle must be designed to load configuration data from external sources, such as YAML files, potentially influenced by an attacker.
    2. The application must use a YAML loading library (like PyYAML) without explicitly disabling unsafe features like tag processing or using `yaml.unsafe_load`.
- Source Code Analysis:
    1. File: `/code/fiddle/_src/experimental/testdata/yaml_serialization_diamond.yaml`
    2. This file is a test data file, and its content demonstrates the usage of `!fdl.Config` tag in YAML.
    3. The content `!fdl.Config __fn_or_cls__: module: __main__ name: Foo ...` shows that `!fdl.Config` tag can be used to specify a function or class (`__fn_or_cls__`) and its parameters (`a`, `b`, `c`).
    4. If a YAML loader processes this tag without security measures, it will attempt to resolve and instantiate the specified class `Foo` from module `__main__` and configure it with the provided parameters.
    5. An attacker can replace `__main__` and `Foo` with malicious code to achieve arbitrary code execution.
    6. The `docs/flags_code_lab.md` file mentions "config_file" and reading "JSON-serialized configuration from a file", suggesting file-based configuration loading is a supported feature, increasing the likelihood of this attack vector if YAML loading is similarly supported or introduced.
    7. The files lack explicit code that prevents YAML deserialization or sanitizes YAML input to prevent tag exploitation.

- Security Test Case:
    1. Vulnerability Test Name: YAML Deserialization Arbitrary Code Execution Test
    2. Preconditions:
        - A Fiddle-based application that loads configurations from YAML files.
        - The application is publicly accessible or the attacker can influence the configuration files loaded by the application.
    3. Test Steps:
        - Step 1: Create a malicious YAML file (e.g., `malicious_config.yaml`) with the following content:

```yaml
!fdl.Config
__fn_or_cls__: !fdl.Partial
  __fn_or_cls__:
    module: os
    name: system
  command: "touch /tmp/pwned"
```

        - Step 2: Configure the Fiddle-based application to load the `malicious_config.yaml` file. This step depends on how the application is designed to load configurations (e.g., via a command-line argument, environment variable, or hardcoded path). Assume for this test case that the application has a flag `--config_file` that accepts a path to a YAML configuration file.
        - Step 3: Run the application with the crafted malicious YAML file:

```bash
python3 <your_fiddle_app>.py --config_file=malicious_config.yaml
```

        - Step 4: Check for Impact: After running the application, verify if the command specified in the malicious YAML file was executed. In this case, check if the file `/tmp/pwned` was created:

```bash
ls /tmp/pwned
```

        - If the file `/tmp/pwned` exists, the vulnerability is confirmed.
    4. Expected Result: The file `/tmp/pwned` is created, indicating successful arbitrary code execution due to YAML deserialization vulnerability.