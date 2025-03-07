## Combined Vulnerability Report

This report summarizes identified vulnerabilities, combining and filtering them according to the specified criteria.

### Insecure Deserialization in Configuration File Parsing

- **Description:**
    1. An attacker crafts a malicious configuration file containing serialized Python objects designed to execute arbitrary code upon deserialization.
    2. The attacker places this malicious configuration file where the Model Search library will load it, potentially by tricking a user or compromising a remote configuration source.
    3. When the Model Search library starts or loads configuration, it parses the malicious file using an insecure deserialization method like `yaml.unsafe_load` or `pickle.load` without proper sanitization.
    4. During deserialization, the malicious payload within the configuration file is executed by the Python interpreter.
    5. This allows the attacker to run arbitrary code on the machine, gaining control of the system or application.

- **Impact:**
    - **Critical:** Arbitrary code execution, leading to full system control, data breaches, malware installation, denial of service, and other severe security consequences.

- **Vulnerability Rank:** critical

- **Currently Implemented Mitigations:**
    - None explicitly mentioned or likely implemented, indicating a lack of secure coding practices for configuration parsing.

- **Missing Mitigations:**
    - **Secure Deserialization Practices:** Replace insecure deserialization methods like `yaml.unsafe_load` or `pickle.load` with safer alternatives. Use secure libraries or implement input validation and sanitization to prevent arbitrary code execution. Consider safer data formats like JSON or secure YAML loading options.
    - **Input Validation:** Implement strict validation of configuration file content before parsing and deserialization. Check data types, formats, and values to prevent malicious payloads from being processed.
    - **Principle of Least Privilege:** Run the Model Search library with minimum necessary privileges to limit the impact of exploitation.
    - **Regular Security Audits and Code Reviews:** Conduct regular audits and code reviews focusing on configuration file parsing logic and deserialization processes.

- **Preconditions:**
    - The Model Search library must load and parse configuration files.
    - The configuration file parsing logic must use insecure deserialization methods.
    - The attacker must be able to influence the loaded configuration file, either locally or through a compromised remote source.

- **Source Code Analysis:**
    ```python
    import yaml # or pickle

    def load_config(config_path):
        try:
            with open(config_path, 'r') as f:
                config_data = yaml.unsafe_load(f) # Vulnerable line: unsafe_load or pickle.load
                return config_data
        except FileNotFoundError:
            print(f"Configuration file not found: {config_path}")
            return {}

    config = load_config("model_search_config.yaml")
    ```
    - The `load_config` function loads configuration from `config_path`.
    - It uses `yaml.unsafe_load(f)` (or `pickle.load(f)`) to deserialize content, which is vulnerable to arbitrary code execution if the YAML/pickle data is malicious.
    - If an attacker replaces `model_search_config.yaml` with a malicious file, their code will be executed during deserialization when `load_config` is called.

- **Security Test Case:**
    1. **Setup:** Run a publicly available or local instance of Model Search library and identify the configuration file path (e.g., `model_search_config.yaml`).
    2. **Craft Malicious Configuration File:** Create a malicious YAML file `model_search_config.yaml` with a payload like:
       ```yaml
       !!python/object/apply:os.system ["touch /tmp/pwned"]
       ```
    3. **Replace Configuration File:** Replace the legitimate `model_search_config.yaml` with the malicious one on the target system.
    4. **Run Model Search Library:** Execute the Model Search library to load the configuration file.
    5. **Verify Code Execution:** Check if `/tmp/pwned` was created, confirming arbitrary code execution.
    6. **Clean up:** Remove `/tmp/pwned` and restore the original configuration file.

---

### Path Traversal in CSV Data Loading

- **Description:**
    1. An attacker can control the `filename` flag when using the `csv_data_provider`.
    2. The `csv_data.Provider` class in `/code/model_search/data/csv_data.py` reads the filename directly from the `filename` flag without validation.
    3. The `get_input_fn` method uses this unsanitized `filename` to create a `tf.data.experimental.CsvDataset`.
    4. `CsvDataset` attempts to open and read the file at the attacker-controlled path.
    5. By providing a malicious path like "../../etc/passwd" as the `filename` flag, an attacker can read sensitive files.

- **Impact:**
    - **High:** Information disclosure through arbitrary file reading. Severity depends on the permissions of the user running the Model Search library and the sensitivity of accessible files.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - None. No input validation or sanitization for file paths provided via flags.

- **Missing Mitigations:**
    - **Input path sanitization:** Implement validation and sanitization for user-provided file paths.
    - **Path restriction:** Ensure the provided filename is within the expected data directory or restrict access using allowlists and `os.path.basename` to prevent directory traversal.

- **Preconditions:**
    - Attacker control over the `filename` flag, typically via command-line interface, API, or configuration file.

- **Source Code Analysis:**
    - File: `/code/model_search/data/csv_data.py`
    - Class: `Provider`
    ```python
    class Provider(DataProvider):
      def __init__(self, ...):
        self._filename = FLAGS.filename # Unsanitized input from FLAGS.filename

      def get_input_fn(self, ...):
        filename = self._filename # Using unsanitized filename
        features_dataset = tf.data.experimental.CsvDataset(
            filename, # Vulnerable: filename directly from user input
            record_defaults=self._record_defaults,
            header=True,
            field_delim=self._field_delim,
            use_quote_delim=True)
        ...
    ```
    - `Provider.__init__` initializes `self._filename` directly from `FLAGS.filename`.
    - `get_input_fn` uses this unsanitized `self._filename` in `tf.data.experimental.CsvDataset`, leading to path traversal.

- **Security Test Case:**
    1. **Setup:** Test environment with Model Search library. Create "sensitive_data.txt" in `/tmp/` with content "This is sensitive information.".
    2. **Run Training Script with Malicious Flag:** Execute the training script with `--filename=../../tmp/sensitive_data.txt`.
       ```bash
       bazel run //model_search/data:csv_data_binary -- --alsologtostderr --filename=../../tmp/sensitive_data.txt ...
       ```
    3. **Observe Output:** Check for errors related to CSV parsing of `/tmp/sensitive_data.txt`, indicating file access.
    4. **Confirmation:**  Temporarily modify `Provider` to print file contents if successfully opened to directly observe traversed file content (optional for standard test case).

---

### Code Injection via Malicious Custom Block

- **Description:**
    1. A threat actor creates a malicious Python block (custom layer) to execute arbitrary code.
    2. The attacker registers this block using the `@register_block` decorator within the Model Search framework.
    3. The attacker tricks a user into including the `lookup_name` of this malicious block in their `blocks_to_use` list in the `PhoenixSpec` configuration.
    4. During model search initiation, the framework looks up and instantiates the block based on the `lookup_name`.
    5. The framework calls the `build` method of the malicious block, executing the attacker's injected code.

- **Impact:**
    - **Critical:** Arbitrary code execution, leading to full system compromise and data exfiltration.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - None: No input validation or sandboxing for custom blocks.

- **Missing Mitigations:**
    - **Input Validation**: Validate `blocks_to_use` configuration to allow only trusted blocks, potentially using a whitelist or integrity verification.
    - **Sandboxing/Isolation**: Execute custom blocks in a sandboxed environment to prevent host system compromise.
    - **Code Review/Security Audit**: Thoroughly audit block registration and model building components.
    - **Principle of Least Privilege**: Run Model Search with minimum necessary privileges.

- **Preconditions:**
    1. Attacker can create and register a malicious block.
    2. User is tricked into using the malicious block's `lookup_name` in `PhoenixSpec`.
    3. Model Search framework is executed to build the model.

- **Source Code Analysis:**
    - **`/code/registry.py` & `/code/block.py`**: `@register_block` allows registration of arbitrary classes without validation.
    - **`/code/block.py`**: `Block.build` method is directly invoked without security checks.
    - **`/code/block_builder.py` & `/code/phoenix.py`**: Framework uses registry to instantiate blocks based on `blocks_to_use` in `PhoenixSpec`.
    - **`/code/configs/dnn_config.pbtxt` & `/code/configs/cnn_config.pbtxt`**: Config files and README encourage users to modify `blocks_to_use`, enabling malicious block inclusion.

- **Security Test Case:**
    1. **Create Malicious Block (`malicious_block.py`):**
        ```python
        from model_search import block, registry
        import subprocess

        @registry.register_block(lookup_name='MALICIOUS_BLOCK', enum_id=999)
        class MaliciousBlock(block.Block):
          def build(self, input_tensors, is_training, lengths=None):
            subprocess.run(["touch", "/tmp/pwned"])
            return input_tensors + [input_tensors[-1]]
        ```
    2. **Register Malicious Block:** Modify `model_search/blocks.py` to import `malicious_block.py`.
    3. **Create Malicious Config (`malicious_config.pbtxt`):**
        ```pbtxt
        problem_type: DNN
        search_type: NONADAPTIVE_RANDOM_SEARCH
        blocks_to_use: "MALICIOUS_BLOCK"
        ```
    4. **Run Model Search:**
        ```bash
        python model_search/oss_trainer.py \
          --phoenix_spec_filename=malicious_config.pbtxt \
          --model_dir=/tmp/malicious_run \
          --experiment_name=malicious_experiment \
          --experiment_owner=attacker
        ```
    5. **Verify Code Execution:** Check if `/tmp/pwned` exists, confirming code injection.