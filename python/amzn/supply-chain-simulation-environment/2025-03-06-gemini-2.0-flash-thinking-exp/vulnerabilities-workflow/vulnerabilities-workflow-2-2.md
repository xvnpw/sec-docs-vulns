### Vulnerability List

- Vulnerability Name: Path Traversal in Profile Loading
- Description:
    1. The `miniscot` application uses profiles (JSON files) to configure the simulation environment.
    2. The `load_profile` function in `/code/src/scse/profiles/profile.py` is responsible for loading these profile files.
    3. This function takes a `profile_configuration` string as input, which is derived from the `-profile` command-line argument.
    4. Inside `load_profile`, the code first attempts to open a file by joining the profile name with the `.json` extension to the profile directory. If this file is not found (`FileNotFoundError`), it directly attempts to open the `profile_configuration` string as a file path without any sanitization or path validation.
    5. An attacker can provide a crafted `profile_configuration` string containing path traversal characters (e.g., `../`, `..\\`) to access files outside the intended profile directory.
    6. For example, if an attacker provides `../README.md` as the profile name, the application will attempt to open `/code/src/scse/profiles/../README.md`, effectively reading the `README.md` file located in the `/code/src/` directory, bypassing the intended profile directory.
- Impact:
    - An attacker can read arbitrary files on the server's file system that the `miniscot` application has permissions to access. This could include sensitive configuration files, source code, or data files, potentially leading to information disclosure.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations:
    - None. The code directly attempts to open the provided path without validation.
- Missing Mitigations:
    - Input validation and sanitization of the `profile_configuration` string.
    - Implement path validation to ensure that the profile path stays within the intended profile directory. For example, using `os.path.abspath` and checking if the resolved path is still within the allowed profile directory.
- Preconditions:
    - The attacker must be able to execute the `miniscot` command-line application and provide command-line arguments, specifically the `-profile` argument.
- Source Code Analysis:
    ```python
    File: /code/src/scse/profiles/profile.py

    def load_profile(profile_configuration):
        module_path = dirname(__file__)

        try:
            fpath = join(module_path, profile_configuration + '.json') # Line 1
            logger.debug("Open profile file = {}.".format(fpath))

            with open(fpath) as f:
                profile = json.load(f)

        except FileNotFoundError:
            fpath = profile_configuration # Line 2 - Path Traversal Vulnerability
            logger.debug("Open profile file = {}.".format(fpath))

            with open(fpath) as f:
                profile = json.load(f)

        return profile
    ```
    - **Line 1**: The code first attempts to load the profile from the expected location by joining the `profile_configuration` with `.json` and the module path. This is the intended secure path.
    - **Line 2**: If the file is not found in the expected location (e.g., if the user provides a profile name without the `.json` extension, or a completely different path), the code falls back to directly using the `profile_configuration` as the file path without any validation. This is where the path traversal vulnerability exists. An attacker can provide a path like `../README.md` as `profile_configuration`, and the `open(fpath)` will attempt to open the file at that path relative to the current working directory of the script, potentially accessing files outside the intended `profiles` directory.

- Security Test Case:
    1.  Set up the miniSCOT environment as described in the `README.md` (clone, install).
    2.  Navigate to the `/code/src/scse/profiles/` directory.
    3.  Create a dummy profile file named `test_profile.json` with any valid JSON content (e.g., `{"metrics": [], "modules": []}`).
    4.  From the command line, execute the `miniscot` application with a path traversal payload as the profile name:
        ```bash
        miniscot -profile '../README.md'
        ```
    5.  Observe the output. If the vulnerability is present, the application will attempt to parse the `README.md` file as a JSON profile, which will likely result in a `json.decoder.JSONDecodeError` because `README.md` is not a valid JSON file. However, this error confirms that the application tried to open and parse the `README.md` file due to path traversal.
    6.  To further confirm, modify the `load_profile` function temporarily to print the `fpath` just before `with open(fpath) as f:`. Rerun the test and observe that `fpath` is resolved to a path outside the profiles directory, such as `/path/to/miniscot/code/src/README.md`.

---
- Vulnerability Name: Arbitrary Code Execution via Profile Configuration
- Description:
    1. The `miniscot` application uses profiles to define which modules and metrics to load for the simulation.
    2. The `instantiate_class` function in `/code/src/scse/profiles/profile.py` is used to instantiate classes (modules and metrics) based on class names specified in the profile.
    3. This function takes a `full_class_name` string from the profile and uses `importlib.import_module` to import the module and `getattr` to get the class.
    4. If an attacker can control the content of the profile file (e.g., through path traversal vulnerability or by providing a malicious profile file), they can specify arbitrary `full_class_name` values.
    5. By crafting a malicious profile with a `full_class_name` pointing to a malicious Python module and class, an attacker can achieve arbitrary code execution when the `instantiate_class` function is called.
    6. For example, an attacker could create a profile that specifies a malicious module and class to be instantiated as a metric or module. When miniSCOT loads this profile and calls `instantiate_class`, it will import and instantiate the attacker-controlled class, leading to code execution within the miniSCOT application's context.
- Impact:
    - Complete compromise of the miniSCOT application and potentially the server it is running on.
    - An attacker can execute arbitrary commands, install malware, steal sensitive data, or disrupt the simulation environment.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None. The code directly imports and instantiates classes based on string names from the profile without validation or sanitization.
- Missing Mitigations:
    - Strict validation of `full_class_name` from the profile to ensure it belongs to a safe and expected set of modules and classes.
    - Implement a whitelist of allowed modules and classes that can be instantiated via profiles.
    - Consider using a safer mechanism for module and class instantiation that does not rely on string-based class names from user-controlled input.
- Preconditions:
    - The attacker must be able to provide a malicious profile file to the `miniscot` application. This can be achieved through exploiting the path traversal vulnerability (Vulnerability: Path Traversal in Profile Loading) or by directly replacing or modifying profile files if the attacker has write access to the file system.
- Source Code Analysis:
    ```python
    File: /code/src/scse/profiles/profile.py

    def instantiate_class(full_class_name, **parameters):
        last_dot = full_class_name.rindex('.')
        module_name = full_class_name[:last_dot]
        #logger.debug("module_name is {}".format(module_name))
        class_name = full_class_name[last_dot + 1:]

        module = importlib.import_module(module_name) # Line 1 - Module Import
        agent_class = getattr(module, class_name)     # Line 2 - Class Attribute Access
        agent_instance = agent_class(parameters)

        return agent_instance
    ```
    - **Line 1**: `importlib.import_module(module_name)` dynamically imports a Python module based on the `module_name` string, which is extracted from the `full_class_name` from the profile. If an attacker controls `full_class_name`, they can control which module is imported.
    - **Line 2**: `getattr(module, class_name)` retrieves a class attribute (class itself) from the imported module using the `class_name` string, also derived from the profile. Again, attacker control over `class_name` allows them to choose which class is accessed.
    - By controlling both `module_name` and `class_name` through a malicious profile, an attacker can import arbitrary modules and instantiate arbitrary classes available in the Python environment, leading to arbitrary code execution when the instance is created in `agent_instance = agent_class(parameters)`.

- Security Test Case:
    1.  Set up the miniSCOT environment.
    2.  Create a malicious Python module file named `malicious_module.py` in the `/code/src/scse/profiles/` directory (or any directory where Python can import from).
    3.  Inside `malicious_module.py`, define a class `MaliciousClass` with an `__init__` method that executes arbitrary code, for example:
        ```python
        # /code/src/scse/profiles/malicious_module.py
        import os

        class MaliciousClass:
            def __init__(self, config):
                os.system('touch /tmp/pwned') # Arbitrary command execution - creates file /tmp/pwned
                print("Malicious code executed!")
        ```
    4.  Create a malicious profile file, e.g., `malicious_profile.json`, in the `/code/src/scse/profiles/` directory, that uses the malicious module and class as a metric:
        ```json
        {
          "metrics": ["scse.profiles.malicious_module.MaliciousClass"],
          "modules": []
        }
        ```
    5.  Run the `miniscot` application using the malicious profile:
        ```bash
        miniscot -profile profiles/malicious_profile.json
        ```
    6.  Check if the arbitrary command was executed. In this example, check if the file `/tmp/pwned` was created:
        ```bash
        ls /tmp/pwned
        ```
        If the file exists, it confirms that the code within the `MaliciousClass.__init__` method was executed, demonstrating arbitrary code execution vulnerability.
    7.  Observe the output. You should see "Malicious code executed!" printed to the console, further confirming code execution.