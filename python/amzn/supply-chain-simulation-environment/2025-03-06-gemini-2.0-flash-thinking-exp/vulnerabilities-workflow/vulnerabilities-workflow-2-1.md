### Vulnerability List:

* Vulnerability Name: Profile-based Code Injection
* Description:
    1. The `miniscot` application uses profiles to configure simulation modules and services.
    2. The application loads profiles based on user-supplied input via the `-profile` command-line argument.
    3. The `load_profile` function in `src/scse/profiles/profile.py` reads and parses the profile file (JSON).
    4. The profile file specifies modules to be loaded and instantiated using `instantiate_class` function in `src/scse/profiles/profile.py`.
    5. The `instantiate_class` function dynamically imports and instantiates Python classes based on the `full_class_name` specified in the profile.
    6. A malicious user can craft a profile file that specifies a malicious Python module with code designed to execute system commands.
    7. By providing the path to this malicious profile via the `-profile` argument to the `miniscot` application, the attacker can force the application to load and execute the malicious module, leading to arbitrary code execution on the server.
* Impact: Arbitrary code execution on the server running `miniscot`. This could allow an attacker to gain full control of the system, steal sensitive data, or disrupt operations.
* Vulnerability Rank: Critical
* Currently implemented mitigations: None
* Missing mitigations:
    - Input validation for profile names to ensure they are within expected boundaries and formats, preventing path traversal and unexpected file access.
    - Sandboxing or isolation for loaded modules to restrict their access to system resources, limiting the impact of malicious code.
    - Least privilege principles for the `miniscot` application process to minimize the damage from potential exploits.
* Preconditions:
    - The attacker needs to be able to execute the `miniscot` command-line application.
    - The attacker must be able to provide a crafted profile file path as an argument to the `miniscot` application using the `-profile` flag.
* Source code analysis:
    1. **`src/scse/main/cli.py`**: The `do_start` function uses `argparse` to handle command-line arguments, including `-profile`. The value provided for `-profile` is stored in `args.profile`.
    2. **`src/scse/main/cli.py`**: The `do_start` function then calls `self._start` passing the parsed arguments.
    3. **`src/scse/main/cli.py`**: The `_start` function in turn calls `self._env = miniSCOT.SupplyChainEnvironment(**run_parameters)`, passing the `profile` value within the `run_parameters` dictionary.
    4. **`src/scse/controller/miniscot.py`**: In the `SupplyChainEnvironment.__init__` method, the `profile` value from `run_parameters` is directly passed to the `load_profile` function: `profile_config = load_profile(profile)`.
    5. **`src/scse/profiles/profile.py`**: The `load_profile` function attempts to load the profile from two locations. First, it tries to open a file named `<profile_configuration>.json` within the same directory as `profile.py` itself (`module_path`). If this fails with a `FileNotFoundError`, it then attempts to open the `profile_configuration` path directly without any validation or sanitization. This is the point where a path traversal vulnerability can occur if `profile_configuration` is a malicious path.
    6. **`src/scse/profiles/profile.py`**: After loading the profile configuration as a JSON object, the `instantiate_class` function is used to instantiate modules listed in the 'modules' section of the profile. The `full_class_name` for each module is taken directly from the profile.
    7. **`src/scse/profiles/profile.py`**: The `instantiate_class` function uses `importlib.import_module(module_name)` to dynamically import the Python module specified in `module_name` (extracted from `full_class_name`) and then uses `getattr(module, class_name)` to get and return an instance of the class. If a malicious user can control the `full_class_name` in the profile, they can cause arbitrary Python code to be imported and executed when `miniscot` is run.

* Security test case:
    1. Create a file named `malicious_module.py` in the same directory where you intend to run `miniscot` from, with the following content:
    ```python
    import os
    import scse.api.module

    class MaliciousModule(scse.api.module.Module):
        def __init__(self, config):
            os.system("touch /tmp/miniscot_pwned") # Creates a file in /tmp as a proof of concept

        def get_name(self):
            return 'malicious_module'
    ```
    2. Create a file named `malicious_profile.json` in the same directory as `malicious_module.py` with the following content:
    ```json
    {
      "modules": [
        "malicious_module.MaliciousModule"
      ],
      "metrics": []
    }
    ```
    3. Run the `miniscot` application from your terminal, providing the malicious profile file as an argument:
    ```bash
    miniscot -profile ./malicious_profile.json
    ```
    4. After executing the command, check if a file named `miniscot_pwned` has been created in the `/tmp` directory.
    ```bash
    ls /tmp/miniscot_pwned
    ```
    5. If the file `/tmp/miniscot_pwned` exists, it confirms that the code from `malicious_module.py` was executed by `miniscot` as a result of loading the `malicious_profile.json`, demonstrating the profile-based code injection vulnerability.