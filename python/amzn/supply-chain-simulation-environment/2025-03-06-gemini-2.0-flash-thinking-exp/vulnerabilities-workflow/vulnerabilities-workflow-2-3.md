### Vulnerability List

- Vulnerability Name: Unsafe Module Loading via Profile Configuration
- Description: The miniSCOT application dynamically loads Python modules and classes based on configuration specified in profile JSON files. The `instantiate_class` function in `src/scse/profiles/profile.py` uses `importlib.import_module` and `getattr` to load modules and classes from their fully qualified names provided in the profile. The `load_profile` function in `src/scse/profiles/profile.py` allows loading profile configurations from arbitrary file paths if a provided profile name does not correspond to a file in the default profile directory. This functionality, combined with the dynamic module loading, creates a vulnerability where a malicious user who can control the profile file path can achieve arbitrary code execution by crafting a malicious profile that points to and loads a malicious Python module.
- Impact: Arbitrary code execution on the machine running the miniSCOT simulation. An attacker could potentially gain full control of the system, steal sensitive data, or use the system for further malicious activities.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations: None. The application currently loads modules and profiles without any validation of the module paths or class names.
- Missing Mitigations:
    - **Input validation and sanitization:** Sanitize the `profile` parameter to ensure it only accepts valid profile names or paths from a restricted set of allowed locations.
    - **Restrict profile loading:** Modify `load_profile` function to only load profiles from a predefined, secure directory and prevent loading from arbitrary file paths provided by users.
    - **Safelist of allowed modules and classes:** Implement a safelist of allowed modules and classes that can be loaded via profiles. Any module or class not on the safelist should be rejected.
    - **Code review:** Conduct a thorough code review of the module loading and instantiation mechanisms to identify and address any other potential vulnerabilities.
- Preconditions:
    - The attacker must be able to control the `profile` parameter passed to the miniSCOT application. This can be achieved if the application is exposed in an environment where users can provide command-line arguments (e.g., via a web interface or API that improperly handles user inputs or if the attacker has access to the command line interface).
- Source Code Analysis:
    - **`src/scse/profiles/profile.py` - `instantiate_class` function:**
      ```python
      def instantiate_class(full_class_name, **parameters):
          last_dot = full_class_name.rindex('.')
          module_name = full_class_name[:last_dot]
          class_name = full_class_name[last_dot + 1:]

          module = importlib.import_module(module_name) # [VULNERABLE LINE] - Dynamic module import
          agent_class = getattr(module, class_name)      # [VULNERABLE LINE] - Dynamic class attribute access
          agent_instance = agent_class(parameters)

          return agent_instance
      ```
      This function dynamically imports a module and retrieves a class based on the `full_class_name` string. There is no validation on `full_class_name`, allowing an attacker to potentially specify any module and class available to the Python interpreter.
    - **`src/scse/profiles/profile.py` - `load_profile` function:**
      ```python
      def load_profile(profile_configuration):
          module_path = dirname(__file__)

          try:
              fpath = join(module_path, profile_configuration + '.json')
              logger.debug("Open profile file = {}.".format(fpath))

              with open(fpath) as f:
                  profile = json.load(f)

          except FileNotFoundError: # [VULNERABLE SECTION] - Arbitrary file path loading
              fpath = profile_configuration
              logger.debug("Open profile file = {}.".format(fpath))

              with open(fpath) as f:
                  profile = json.load(f)

          return profile
      ```
      If the profile file is not found in the default `profiles` directory, the code falls back to treating the `profile_configuration` string as a direct file path and attempts to open and load it. This allows an attacker to specify an arbitrary file path for profile loading.
    - **`src/scse/controller/miniscot.py` - Profile loading and module instantiation:**
      ```python
      profile_config = load_profile(profile) # Loads profile based on user input 'profile'
      self._metrics = [instantiate_class(class_name, ...) for class_name in profile_config['metrics']] # Instantiates metrics from profile
      self._modules = [instantiate_class(class_name, ...) for class_name in profile_config['modules']] # Instantiates modules from profile
      ```
      The `SupplyChainEnvironment` class uses the `load_profile` function to load the profile configuration based on the `profile` parameter provided during initialization. It then uses `instantiate_class` to create instances of metrics and modules defined in the profile.
- Security Test Case:
    1. Create a malicious Python module file named `malicious_metric.py` and place it in the `/code/src/scse/profiles/` directory (or any location the Python interpreter can access).
       ```python
       # /code/src/scse/profiles/malicious_metric.py
       import os

       class MaliciousMetric:
           def __init__(self, run_parameters):
               print("MaliciousMetric Initialized - Code Execution Successful!")
               os.system("touch /tmp/miniscot_pwned") # Creates a file as a proof of concept

           def reset(self, context, state):
               pass

           def compute_reward(self, state, action):
               return 0
       ```
    2. Create a malicious profile JSON file named `malicious_profile.json` and place it in the `/code/src/scse/profiles/` directory. This profile will instruct miniSCOT to load the malicious metric.
       ```json
       {
           "metrics": [
               "scse.profiles.malicious_metric.MaliciousMetric"
           ],
           "modules": []
       }
       ```
    3. Execute the miniSCOT command-line interface (CLI) and provide the path to the malicious profile using the `-profile` argument:
       ```bash
       miniscot -profile scse/profiles/malicious_profile.json
       ```
    4. After running the command, check for the existence of the file `/tmp/miniscot_pwned`.
    5. **Expected Result:** If the vulnerability exists, the file `/tmp/miniscot_pwned` will be created, and the message "MaliciousMetric Initialized - Code Execution Successful!" will be printed in the console output, indicating that the malicious code from `malicious_metric.py` was executed. This confirms arbitrary code execution by controlling the profile configuration.