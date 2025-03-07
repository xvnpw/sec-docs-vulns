- vulnerability name: Arbitrary code execution via untrusted Fiddle configuration
- description:
    - An attacker crafts a malicious YAML configuration file or string.
    - This malicious configuration contains a `!fdl.Config` or `!fdl.Partial` tag with the `__fn_or_cls__` key pointing to a malicious Python function.
    - The attacker provides this configuration file or string to an application that uses Fiddle to load and process configurations, for example, via command-line flags using `DEFINE_fiddle_config` or `create_buildable_from_flags`.
    - When the application parses the configuration using Fiddle's YAML loading or flag parsing mechanisms, Fiddle attempts to resolve the function specified by `__fn_or_cls__`.
    - Due to `yaml.unsafe_load` and `exec` being used in Fiddle's flag parsing and YAML loading functionalities, if the attacker-controlled configuration is processed, the malicious Python code within `__fn_or_cls__` gets executed. This can lead to arbitrary code execution within the application's context.
- impact:
    - Critical: Successful exploitation of this vulnerability allows for arbitrary code execution. An attacker could gain complete control over the application, potentially leading to data breaches, system compromise, or other malicious activities.
- vulnerability rank: critical
- currently implemented mitigations: None
- missing mitigations:
    - Input validation: Implement strict validation of the configuration source to ensure it originates from a trusted source.
    - Secure YAML loading: Replace `yaml.unsafe_load` with `yaml.safe_load` to prevent arbitrary code execution during YAML parsing. However, `yaml.safe_load` might not support all Fiddle's YAML features, so a more robust solution might involve a custom YAML loader that specifically handles Fiddle tags securely.
    - Sandboxing or isolation: If dynamic configuration loading from untrusted sources is a core requirement, consider sandboxing or isolating the Fiddle configuration processing to limit the impact of potential code execution vulnerabilities.
    - Code review: Thoroughly review the code paths involved in configuration loading, especially the flag parsing and YAML loading functionalities, to identify and eliminate any other potential code injection points.
- preconditions:
    - The application must use Fiddle's flag parsing (`DEFINE_fiddle_config`, `create_buildable_from_flags`) or YAML loading capabilities to load configurations.
    - The application must load configuration from an untrusted source (e.g., command-line arguments, user-provided files, network sources).
- source code analysis:
    - File: `/code/docs/flags_code_lab.md`
        - This file documents the usage of Fiddle flags, highlighting the potential risk if configuration is loaded from untrusted sources. It mentions both "New API" (`DEFINE_fiddle_config`) and "Legacy API" (`create_buildable_from_flags`) as potential attack vectors.
    - File: `/code/fiddle/_src/absl_flags/utils.py`
        - The `ZlibJSONSerializer.deserialize` method is used to deserialize configurations from strings or files provided via flags. This method uses `serialization.load_json` to load JSON, which in turn uses `yaml.unsafe_load`.
        - The `resolve_function_reference` function is used to dynamically resolve function names from strings provided in flags. While not directly executing code, this function is crucial in allowing users to specify arbitrary functions to be used in Fiddle configurations, which becomes a security risk when combined with untrusted configuration sources.
    - File: `/code/fiddle/_src/experimental/serialization.py`
        - The `load_json` function uses `yaml.unsafe_load` to deserialize YAML into Python objects. This function is called by `ZlibJSONSerializer.deserialize`, making it a key part of the attack vector.
    - File: `/code/fiddle/_src/experimental/testdata/yaml_serialization_diamond.yaml`
        - This file demonstrates YAML serialization and deserialization with Fiddle, including `!fdl.Config` tags, which are processed by `yaml.unsafe_load`, making the system vulnerable to code injection if this YAML processing is exposed to untrusted input.
- security test case:
    1. Create a malicious YAML file named `evil_config.yaml` with the following content:
    ```yaml
    !fdl.Config
    __fn_or_cls__:
      module: os
      name: system
    command: "touch /tmp/pwned"
    ```
    2. Create a Python application `test_fiddle_app.py` that uses `DEFINE_fiddle_config` to load configuration and build it:
    ```python
    import fiddle as fdl
    from fiddle import absl_flags
    from absl import app
    import os

    _CONFIG = fdl_flags.DEFINE_fiddle_config(
        name="config", help_string="Fiddle configuration."
    )

    def main(_):
      cfg = _CONFIG.value
      fdl.build(cfg)

    if __name__ == '__main__':
      app.run(main)
    ```
    3. Run the application, providing the malicious YAML file via command-line flag:
    ```sh
    python3 test_fiddle_app.py --config=config_file:evil_config.yaml
    ```
    4. After running the application, check if the file `/tmp/pwned` exists. If it does, it confirms successful arbitrary code execution.