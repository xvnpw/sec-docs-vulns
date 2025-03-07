- ### Vulnerability 1

    * Vulnerability Name: Arbitrary Code Execution via Malicious Feature Map in Event Generator
    * Description:
        1. An attacker crafts a malicious data file or configuration that, when processed by LTVision, leads to the instantiation of an `EventGenerator` (or its subclasses) with a crafted `features_map`.
        2. This `features_map` contains dictionary entries where the values are malicious Python functions.
        3. When a user calls the `generate_events` method of the `EventGenerator` with a Pandas DataFrame, the `apply(self.features_map)` method in `event_generator.py` will execute these malicious functions for each row of the DataFrame.
        4. This results in arbitrary Python code execution within the LTVision environment.
    * Impact: Arbitrary code execution on the machine running LTVision. This could lead to complete system compromise, data exfiltration, or other malicious activities.
    * Vulnerability Rank: Critical
    * Currently Implemented Mitigations: None. The code directly uses the provided `features_map` without any validation or sanitization of the functions within it.
    * Missing Mitigations: Input validation and sanitization for the `features_map`. Ensure that the values in the dictionary are safe and cannot be used for code execution. Ideally, the `features_map` should not contain arbitrary functions but rather be restricted to safe data transformations or lookups. Restrict the types of functions allowed in `features_map` to only safe, predefined operations.
    * Preconditions:
        1. The user must load and use a malicious data file or configuration that influences the `features_map` used in the `EventGenerator`. This assumes a mechanism exists in LTVision to load or configure the `features_map` from an external source, or that a higher-level function uses user-controlled data to create this map. While the provided code shows `features_map` being hardcoded in scenarios, a more complex application might allow users to configure or extend these maps, or load them from external files, which would introduce this vulnerability.
    * Source Code Analysis:
        1. In `/code/src/event_generator.py`, the `EventGenerator` class is defined with a `features_map` attribute, which is a dictionary of feature names to functions.
        2. The `generate_events` method in `EventGenerator` (and its subclasses like `BinomialEventGenerator`, `LognormalEventGenerator`, `ParetoEventGenerator`) calls `data.apply(self.features_map, axis=1)`.
        3. Pandas `apply` method executes the functions passed as values in `features_map` on each row of the DataFrame.
        4. If `features_map` contains malicious functions, `apply` will execute them, leading to arbitrary code execution.
        5. No input validation or sanitization is performed on `features_map` before using it in `apply`. The constructor of `EventGenerator` takes the `features_map` directly as input without any checks on the nature of the functions within it.
    * Security Test Case:
        1. Create a Python file named `malicious_features.py` with the following content:
        ```python
        import subprocess

        def malicious_function(x):
            subprocess.run(["touch", "/tmp/ltvision_pwned"]) # Creates a file in /tmp to indicate successful code execution
            return 0
        ```
        2. Create a Python script or Jupyter Notebook (e.g., `exploit_notebook.ipynb`) with the following content:
        ```python
        import pandas as pd
        from src.event_generator import BinomialEventGenerator
        from malicious_features import malicious_function # Assuming malicious_features.py is in the same directory

        malicious_map = {
            'country': malicious_function,
            'device': lambda x: 0.5 if x == 'ios' else 0,
            'download_method': lambda x: 0 if x == 'wifi' else -1
        }

        data = pd.DataFrame({'country': ['US', 'CA'], 'device': ['ios', 'android'], 'download_method': ['wifi', 'mobile_data']})
        generator = BinomialEventGenerator(features_map=malicious_map, baseline=-3)
        events = generator.generate_events(data)
        print(events)

        import os
        if os.path.exists("/tmp/ltvision_pwned"):
            print("\\nVulnerability confirmed: /tmp/ltvision_pwned file created.")
        else:
            print("\\nVulnerability test failed: /tmp/ltvision_pwned file not found.")
        ```
        3. Place `malicious_features.py` and `exploit_notebook.ipynb` in the same directory as the `src` directory of the LTVision project, or adjust import paths accordingly.
        4. Run the `exploit_notebook.ipynb` using Jupyter Notebook with the LTVision environment activated.
        5. After execution, check if a file named `ltvision_pwned` exists in the `/tmp/` directory. If the file exists, it confirms arbitrary code execution, as the `malicious_function` was executed by the `EventGenerator`. The notebook should also print "Vulnerability confirmed: /tmp/ltvision_pwned file created." if successful.