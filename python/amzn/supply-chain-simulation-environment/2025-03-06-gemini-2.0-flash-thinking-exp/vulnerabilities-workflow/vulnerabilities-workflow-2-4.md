- Vulnerability name: Profile Path Traversal and Arbitrary Code Execution
- Description:
  1. The `miniscot` command-line application uses a `profile` parameter to load simulation configurations from JSON files.
  2. The `load_profile` function in `src/scse/profiles/profile.py` attempts to load a profile based on the provided `profile_configuration` string. It first tries to find a JSON file in the profile directory by appending `.json`. If not found, it directly uses the `profile_configuration` string as a file path.
  3. This behavior allows for path traversal, where an attacker can specify a file path outside the intended profile directory.
  4. Furthermore, the loaded profile JSON file dictates which modules and metrics are instantiated, specifying their full class names.
  5. The `instantiate_class` function in `src/scse/profiles/profile.py` uses `importlib.import_module` and `getattr` to dynamically import modules and instantiate classes based on these class names from the profile.
  6. By crafting a malicious profile JSON file and using path traversal to load it, an attacker can inject arbitrary module and class names.
  7. When `instantiate_class` processes these malicious names, it can import and instantiate arbitrary Python classes, leading to arbitrary code execution on the system running `miniscot`.
- Impact: Arbitrary code execution. An attacker can execute arbitrary Python code on the system running `miniscot` by providing a malicious profile. This can lead to complete system compromise, including data theft, malware installation, and denial of service.
- Vulnerability rank: Critical
- Currently implemented mitigations: None. The application directly loads and processes the profile path and class names from the profile without any validation or sanitization.
- Missing mitigations:
  - Implement input validation for the `profile` parameter to ensure it points to a valid profile file within the expected directory or a predefined set of allowed profiles.
  - Validate class names specified in the profile JSON to ensure they belong to expected modules and classes within the project's codebase. A whitelist of allowed modules and classes could be used.
  - Consider sandboxing or using a more secure mechanism for module and class instantiation to limit the impact of loading potentially malicious code.
- Preconditions:
  - The attacker must have the ability to execute the `miniscot` command-line application.
  - The attacker needs to be able to provide or control the `profile` parameter when running `miniscot`.
- Source code analysis:
  1. **`src/scse/main/cli.py`**: The `MiniSCOTDebuggerApp` uses `argparse` to parse command-line arguments, including the `-profile` argument, which is passed to the `do_start` command and subsequently to the `_start` method. The `_start` method then passes this `profile` argument directly to the `miniSCOT.SupplyChainEnvironment` constructor.
  2. **`src/scse/controller/miniscot.py`**: The `SupplyChainEnvironment` constructor takes the `profile` argument and passes it to the `load_profile` function from `src/scse/profiles/profile.py`. The loaded profile configuration is then used to instantiate modules and metrics using the `instantiate_class` function.
  3. **`src/scse/profiles/profile.py`**:
     - **`load_profile` function**: This function is vulnerable to path traversal. If the initial attempt to load the profile from the default directory fails (`FileNotFoundError`), the function proceeds to directly use the provided `profile_configuration` string as a file path without any validation. This allows an attacker to specify a path to a file outside the intended profile directory.
     ```python
     def load_profile(profile_configuration):
         module_path = dirname(__file__)
         try:
             fpath = join(module_path, profile_configuration + '.json')
             # ... (attempt to open from default dir) ...
         except FileNotFoundError:
             fpath = profile_configuration # Path Traversal vulnerability
             # ... (attempt to open directly from provided path) ...
         return profile
     ```
     - **`instantiate_class` function**: This function is vulnerable to arbitrary code execution. It takes a `full_class_name` from the loaded profile, splits it into `module_name` and `class_name`, and uses `importlib.import_module(module_name)` to import the module and `getattr(module, class_name)` to get the class. If an attacker can control the `full_class_name` in the profile, they can specify any module and class to be imported and instantiated, leading to arbitrary code execution.
     ```python
     def instantiate_class(full_class_name, **parameters):
         last_dot = full_class_name.rindex('.')
         module_name = full_class_name[:last_dot]
         class_name = full_class_name[last_dot + 1:]
         module = importlib.import_module(module_name) # Arbitrary Code Execution vulnerability
         agent_class = getattr(module, class_name)
         # ...
         return agent_instance
     ```
- Security test case:
  1. Create a malicious Python file named `malicious_module.py` at `/tmp/malicious_module.py` with the following content:
     ```python
     # /tmp/malicious_module.py
     import os
     class MaliciousClass:
         def __init__(self, config):
             os.system('touch /tmp/pwned') # Executes a malicious command
         def get_name(self):
             return 'malicious'
     ```
  2. Create a malicious profile JSON file named `malicious_profile.json` at `/tmp/malicious_profile.json` with the following content:
     ```json
     {
         "modules": [
             "/tmp/malicious_module.MaliciousClass"
         ],
         "metrics": [
             "scse.metrics.demo_newsvendor_cash_accounting.CashAccounting"
         ]
     }
     ```
  3. Run the `miniscot` command-line application, providing the path to the malicious profile using the `--profile` argument:
     ```bash
     miniscot --profile /tmp/malicious_profile.json
     ```
  4. After running the command, check if the file `/tmp/pwned` has been created.
  5. If the file `/tmp/pwned` exists, this confirms that the code from `/tmp/malicious_module.py` was executed, demonstrating arbitrary code execution due to the profile path traversal and dynamic module loading vulnerability.