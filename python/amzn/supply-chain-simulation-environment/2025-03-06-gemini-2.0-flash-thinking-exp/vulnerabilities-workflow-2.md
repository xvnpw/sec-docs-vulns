## Combined Vulnerability List

### Arbitrary Code Execution via Profile Configuration

* Description:
    1. The `miniscot` application utilizes profiles (JSON files) to configure simulation modules and services. These profiles dictate which modules and metrics are loaded for the simulation.
    2. The application loads profiles based on user-supplied input via the `-profile` command-line argument.
    3. The `load_profile` function in `src/scse/profiles/profile.py` is responsible for loading profile files. It first attempts to load a profile by joining the provided profile name with `.json` and the profile directory path. If this fails, it directly uses the provided profile path without validation or sanitization. This behavior enables path traversal vulnerabilities.
    4. The `load_profile` function reads and parses the profile file (JSON).
    5. The profile file specifies modules and metrics to be loaded and instantiated. The `instantiate_class` function in `src/scse/profiles/profile.py` is used for this purpose.
    6. The `instantiate_class` function dynamically imports and instantiates Python classes based on the `full_class_name` specified in the profile. It uses `importlib.import_module` to import the module and `getattr` to get the class.
    7. A malicious user can craft a profile file that specifies a malicious Python module and class with code designed to execute system commands.
    8. By providing the path to this malicious profile via the `-profile` argument to the `miniscot` application, or exploiting the path traversal vulnerability to load a malicious profile, the attacker can force the application to load and execute the malicious module, leading to arbitrary code execution on the server.

* Impact: Arbitrary code execution on the server running `miniscot`. This is a critical vulnerability that allows an attacker to gain complete control of the miniSCOT application and potentially the entire server. The attacker can execute arbitrary commands, install malware, steal sensitive data, or disrupt the simulation environment, leading to complete system compromise, data theft, malware installation, and denial of service.

* Vulnerability Rank: Critical

* Currently implemented mitigations: None. The application currently loads modules and profiles without any validation of the module paths, profile paths or class names.

* Missing mitigations:
    - Input validation and sanitization of the `profile` parameter to ensure it only accepts valid profile names or paths from a restricted set of allowed locations and formats, preventing path traversal and unexpected file access.
    - Restrict profile loading to a predefined, secure directory and prevent loading from arbitrary file paths provided by users.
    - Implement a safelist of allowed modules and classes that can be instantiated via profiles. Any module or class not on the safelist should be rejected.
    - Sandboxing or isolation for loaded modules to restrict their access to system resources, limiting the impact of malicious code.
    - Least privilege principles for the `miniscot` application process to minimize the damage from potential exploits.
    - Code review of the module loading and instantiation mechanisms to identify and address any other potential vulnerabilities.

* Preconditions:
    - The attacker needs to be able to execute the `miniscot` command-line application.
    - The attacker must be able to provide a crafted profile file path as an argument to the `miniscot` application using the `-profile` flag, or be able to exploit the path traversal vulnerability to load a malicious profile from an arbitrary location.

* Source code analysis:
    1. **`src/scse/main/cli.py`**: The `do_start` function in `MiniSCOTDebuggerApp` class uses `argparse` to handle command-line arguments, including `-profile`. The value provided for `-profile` is stored in `args.profile` and passed to the `_start` method.
    2. **`src/scse/main/cli.py`**: The `_start` function calls `self._env = miniSCOT.SupplyChainEnvironment(**run_parameters)`, passing the `profile` value within the `run_parameters` dictionary to the `SupplyChainEnvironment` constructor.
    3. **`src/scse/controller/miniscot.py`**: In the `SupplyChainEnvironment.__init__` method, the `profile` value from `run_parameters` is directly passed to the `load_profile` function: `profile_config = load_profile(profile)`.
    4. **`src/scse/profiles/profile.py`**: The `load_profile` function first attempts to load the profile from the expected location by joining the `profile_configuration` with `.json` and the module path. If this fails with a `FileNotFoundError`, it falls back to directly using the `profile_configuration` as the file path without any validation or sanitization.
    ```python
    def load_profile(profile_configuration):
        module_path = dirname(__file__)
        try:
            fpath = join(module_path, profile_configuration + '.json')
            logger.debug("Open profile file = {}.".format(fpath))
            with open(fpath) as f:
                profile = json.load(f)
        except FileNotFoundError:
            fpath = profile_configuration # Path Traversal Vulnerability
            logger.debug("Open profile file = {}.".format(fpath))
            with open(fpath) as f:
                profile = json.load(f)
        return profile
    ```
    5. **`src/scse/profiles/profile.py`**: After loading the profile configuration as a JSON object, the `instantiate_class` function is used to instantiate modules and metrics listed in the profile. The `full_class_name` for each module and metric is taken directly from the profile.
    ```python
    def instantiate_class(full_class_name, **parameters):
        last_dot = full_class_name.rindex('.')
        module_name = full_class_name[:last_dot]
        class_name = full_class_name[last_dot + 1:]
        module = importlib.import_module(module_name) # Arbitrary Code Execution Vulnerability
        agent_class = getattr(module, class_name)
        agent_instance = agent_class(parameters)
        return agent_instance
    ```
    6. **`src/scse/profiles/profile.py`**: The `instantiate_class` function uses `importlib.import_module(module_name)` to dynamically import the Python module specified in `module_name` (extracted from `full_class_name`) and then uses `getattr(module, class_name)` to get and return an instance of the class. If a malicious user can control the `full_class_name` in the profile, they can cause arbitrary Python code to be imported and executed when `miniscot` is run.

* Security test case:
    1. Create a file named `malicious_module.py` in the `/tmp/` directory with the following content:
    ```python
    # /tmp/malicious_module.py
    import os
    import scse.api.module

    class MaliciousModule(scse.api.module.Module):
        def __init__(self, config):
            os.system("touch /tmp/miniscot_pwned") # Creates a file in /tmp as a proof of concept
            print("Malicious code executed!")

        def get_name(self):
            return 'malicious_module'
    ```
    2. Create a file named `malicious_profile.json` in the `/tmp/` directory with the following content:
    ```json
    {
      "modules": [
        "/tmp/malicious_module.MaliciousModule"
      ],
      "metrics": []
    }
    ```
    3. Run the `miniscot` application from your terminal, providing the malicious profile file as an argument:
    ```bash
    miniscot -profile /tmp/malicious_profile.json
    ```
    4. After executing the command, check if a file named `miniscot_pwned` has been created in the `/tmp` directory.
    ```bash
    ls /tmp/miniscot_pwned
    ```
    5. If the file `/tmp/miniscot_pwned` exists and you see "Malicious code executed!" in the console output, it confirms that the code from `malicious_module.py` was executed by `miniscot` as a result of loading the `malicious_profile.json`, demonstrating the arbitrary code execution vulnerability.