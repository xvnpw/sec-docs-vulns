### Vulnerability List:

* Unsafe Deserialization/Command Injection via YAML Configuration File Loading

#### Vulnerability Name:
Unsafe Deserialization/Command Injection via YAML Configuration File Loading

#### Description:
1. The `PluginService` class loads configuration files using `yaml.safe_load()` in the `load_config` function.
2. The path to the configuration file is read from the environment variable `SERVICE_CONFIG_FILE`.
3. If an attacker can control the `SERVICE_CONFIG_FILE` environment variable, they can point it to a malicious YAML file.
4. While `yaml.safe_load` is used, if the application or a plugin uses the loaded configuration data unsafely (e.g., in command construction), it can lead to command injection or other vulnerabilities.
5. Plugin developers can add custom configuration parameters, and if these parameters are not handled securely in their plugin logic, vulnerabilities can arise.

#### Impact:
- High to Critical
- Potential command injection or other vulnerabilities depending on how plugin uses configuration data.

#### Vulnerability Rank:
High

#### Currently Implemented Mitigations:
- The project uses `yaml.safe_load()`, which is intended to prevent arbitrary code execution during deserialization compared to `yaml.load()`.

#### Missing Mitigations:
- Input validation and sanitization of configuration parameters loaded from YAML files are missing.
- Enforce a strict schema for configuration files and validate all loaded parameters against this schema.
- Plugins should be developed with secure coding practices, ensuring configuration parameters are handled safely and not used directly in commands or unsafe operations without sanitization.

#### Preconditions:
- An attacker needs to control the `SERVICE_CONFIG_FILE` environment variable (e.g., through container misconfiguration).
- A plugin must be implemented that unsafely processes configuration parameters loaded from the YAML file, leading to an exploitable vulnerability like command injection.

#### Source Code Analysis:
- File: `/code/decisionai_plugin/common/plugin_service.py`
    ```python
    def load_config(path):
        try:
            with open(path, 'r') as config_file:
                config_yaml = yaml.safe_load(config_file) # Vulnerable line: Using safe_load but potential unsafe usage of config values later
                Config = namedtuple('Config', sorted(config_yaml))
                config = Config(**config_yaml)
            return config
        except Exception:
            return None

    class PluginService():
        def __init__(self, trainable=True):
            config_file = environ.get('SERVICE_CONFIG_FILE') # Reads SERVICE_CONFIG_FILE from environment
            config = load_config(config_file) # Loads config file using yaml.safe_load
            if config is None:
                log.error("No configuration '%s', or the configuration is not in JSON format. " % (config_file))
                exit()
            self.config = config # Configuration is stored in self.config and accessible to plugin logic
            # ... rest of init ...
    ```

    **Visualization:**
    ```
    Environment Variable (SERVICE_CONFIG_FILE) --> load_config() --> yaml.safe_load() --> Configuration Object (self.config) --> Plugin Logic (potential unsafe usage)
    ```
    - The code loads the configuration file path from an environment variable and uses `yaml.safe_load`.
    - The vulnerability arises from potential insecure usage of the loaded configuration data within plugin implementations.

#### Security Test Case:
1. **Setup:** Deploy a sample plugin in a controlled environment where environment variables can be manipulated.
2. **Create Malicious Config:** Create `malicious_config.yaml` with a payload to exploit a hypothetical plugin vulnerability (e.g., `command: "rm -rf /tmp/*"` if plugin uses config in `os.system()`).
3. **Modify Deployment:** Set `SERVICE_CONFIG_FILE` environment variable to point to `malicious_config.yaml`.
4. **Trigger Plugin Action:** Trigger an action that loads and uses the configuration (e.g., inference request).
5. **Observe Impact:** Monitor system for execution of malicious payload (e.g., check if files in `/tmp` are deleted in test environment).
6. **Expected Result:** Malicious payload execution if plugin unsafely uses config data, demonstrating the vulnerability.


* Insufficient Input Validation on Plugin Parameters

#### Vulnerability Name:
Insufficient Input Validation on Plugin Parameters

#### Description:
1. An attacker uploads and installs a malicious plugin to the platform.
2. The attacker crafts a malicious API request (train, inference, verify) to the plugin's endpoint.
3. This request includes crafted parameters to exploit input handling vulnerabilities.
4. If the plugin service lacks input validation and sanitization, malicious payloads can be injected.
5. Depending on plugin parameter processing, this can lead to command injection, arbitrary code execution, or sensitive data access.
6. For example, unsanitized parameters in system commands or database queries can lead to exploits.

#### Impact:
- Remote code execution on the system.
- Unauthorized access to sensitive data.
- Compromise of the Decision AI service and infrastructure.

#### Vulnerability Rank:
High

#### Currently Implemented Mitigations:
- No explicit input validation in the plugin framework itself.
- Sample plugins have limited checks like permission checks in `do_verify`, but not general input validation.
- Relies on plugin developers to implement input validation, which is not enforced.

#### Missing Mitigations:
- **Framework-level input validation**: Implement input validation in `PluginService` or API endpoint handling in `plugin_model_api.py`.
    - Input type validation.
    - Input format validation (regex, date/time).
    - Input range validation (numerical parameters).
    - Sanitization of string inputs (escaping).
- **Secure deserialization practices**: Use safe deserialization methods (though not directly observed as missing, good practice).
- **Principle of least privilege for plugins**: Run plugins with minimum necessary privileges, consider sandboxing/containerization.

#### Preconditions:
- Attacker can upload and install a malicious plugin.
- Target plugin service processes user parameters insecurely, without validation.

#### Source Code Analysis:
- File: `/code/decisionai_plugin/common/plugin_model_api.py`
    ```python
    class PluginModelTrainAPI(Resource):
        # ...
        def post(self):
            return self.__plugin_service.train(request)
    class PluginModelInferenceAPI(Resource):
        # ...
        def post(self, model_id):
            return self.__plugin_service.inference(request, model_id)
    class PluginModelParameterAPI(Resource):
        # ...
        def post(self):
            return self.__plugin_service.verify(request)
    ```
    - APIs pass `request.data` directly to `PluginService` methods.
    - Framework lacks input validation on `request.data`.

- File: `/code/decisionai_plugin/common/plugin_service.py`
    ```python
    def train(self, request):
        request_body = json.loads(request.data)
        # ...
        result, message = self.do_verify(request_body, Context(...))
        # ... calls do_train with request_body['instance']['params'] ...
    def inference(self, request, model_id):
        request_body = json.loads(request.data)
        # ...
        result, message = self.do_verify(request_body, Context(...))
        # ... calls do_inference with request_body['instance']['params'] ...
    def verify(self, request):
        request_body = json.loads(request.data)
        # ... calls do_verify with request_body ...
    ```
    - `train`, `inference`, `verify` parse `request.data` with `json.loads` and pass `request_body` to plugin methods.
    - Lack of framework validation means plugin vulnerabilities are possible if plugin implementations (`do_verify`, `do_train`, `do_inference`) lack input validation.

#### Security Test Case:
1. **Precondition**: Assume malicious plugin installation is possible.
2. **Setup**: Install a sample plugin on a test instance.
3. **Craft Malicious Request**: Create a malicious JSON request for `/models/train` or `/models/<model_id>/inference` with payloads in `instance.params` or `seriesSets` (e.g., path injection `"; rm -rf / #"`).
4. **Send Malicious Request**: Send crafted POST request using `curl` or Postman.
5. **Observe System Behavior**: Monitor for file system changes (command injection), error logs, crashes.
6. **Analyze Results**: Unexpected behavior confirms vulnerability. RCE is critical, unauthorized access is high, service crash is medium-high.


* Zip Slip vulnerability in model download

#### Vulnerability Name:
Zip Slip vulnerability in model download

#### Description:
1. A Zip Slip vulnerability exists in the `download_model` function during plugin model download.
2. When a plugin model is downloaded, a zip archive is extracted using `zipfile.ZipFile.extractall()`.
3. Malicious zip files with filenames containing path traversal sequences (e.g., `../../../evil.so`) can write files outside `model_dir`.
4. `extractall()` extracts files based on filenames within the zip, without sanitization.
5. This allows arbitrary file write on the server, potentially leading to RCE by overwriting system files or placing executables in accessible locations.

#### Impact:
- Arbitrary File Write
- Remote Code Execution

#### Vulnerability Rank:
Critical

#### Currently Implemented Mitigations:
- None. `zipfile.ZipFile.extractall()` is used directly without filename sanitization or validation.

#### Missing Mitigations:
- Sanitize filenames within zip archives during extraction to prevent path traversal.
- Validate and sanitize each filename before extraction, ensuring no path traversal sequences.
- Use `os.path.basename()` and `os.path.join()` to securely construct destination paths within `model_dir`.

#### Preconditions:
- Attacker can upload a plugin model in zip format.
- Access to the plugin management interface (authenticated or unauthenticated depending on misconfiguration).

#### Source Code Analysis:
- File: `/code/decisionai_plugin/common/util/model.py`
- Function: `download_model`
    ```python
    def download_model(plugin_name, model_version, model_dir):
        # ...
        zip_file = os.path.join(tmp_dir, plugin_name + '_' + model_version + '.zip')
        # ... download zip_file from Azure Blob Storage ...
        zf = zipfile.ZipFile(zip_file)
        zf.extractall(path=model_dir) # Vulnerable line: extractall without sanitization
        # ...
    ```
    1. `download_model` downloads and extracts plugin models.
    2. Zip file downloaded to `zip_file`.
    3. `zipfile.ZipFile(zip_file)` opens the zip archive.
    4. `zf.extractall(path=model_dir)` extracts all files to `model_dir` without sanitization.
    5. `extractall()` is vulnerable to Zip Slip with filenames like `../../../evil.sh`.

    **Visualization:**
    ```
    [Attacker] --- Malicious Zip File (../../../evil.sh) ---> [DecisionAI Platform]
    [DecisionAI Platform] --- download_model() --> zipfile.ZipFile.extractall(model_dir) --- Arbitrary File Write (/tmp/evil.sh) --> [File System]
    ```

#### Security Test Case:
1. **Precondition**: Setup test environment or access test instance for plugin upload.
2. **Step 1: Create Malicious Zip**: Create `malicious_plugin.zip`.
    - Inside zip, create `evil.sh` with content `echo "PWNED" > /tmp/pwned.txt`.
    - Add `evil.sh` with path traversal filename: `zip malicious_plugin.zip ../../../tmp/evil.sh evil.sh`
3. **Step 2: Upload Malicious Zip**: Upload `malicious_plugin.zip` as plugin model via plugin management interface.
4. **Step 3: Trigger Model Download**: Trigger model download/extraction (plugin install or inference task).
5. **Step 4: Verify Exploitation**: Log into server and check if `/tmp/pwned.txt` exists with "PWNED" content.
6. **Step 5: Analyze Results**: Existence of `/tmp/pwned.txt` confirms Zip Slip, demonstrating arbitrary file write. Modify `evil.sh` for more impactful actions to verify RCE.