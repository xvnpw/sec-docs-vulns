- Vulnerability Name: Arbitrary Code Execution via Custom Backend/Exporter Class Loading
- Description:
    - The slo-generator tool allows users to extend its functionality by providing custom backend and exporter classes.
    - These custom classes are specified in the SLO and shared configuration files using a `class` path (e.g., `samples.custom.custom_backend.CustomBackend`).
    - The slo-generator dynamically imports and instantiates these classes using the `import_dynamic` function in `slo_generator/utils.py`.
    - An attacker can exploit this by crafting a malicious configuration file where the `class` path in the `backends` or `exporters` sections points to a Python file containing arbitrary malicious code.
    - When the slo-generator processes this configuration file, it will load and instantiate the attacker-controlled class, leading to arbitrary code execution on the system running the tool.
    - Step-by-step trigger:
        1. Attacker creates a malicious Python file with arbitrary code.
        2. Attacker crafts a malicious SLO or shared configuration file.
        3. In the configuration file, within the `backends` or `exporters` section, the `class` parameter is set to the path of the malicious Python file and class.
        4. The slo-generator tool processes this configuration file using the `compute` or `api` command.
        5. The `import_dynamic` function in `slo_generator/utils.py` imports and instantiates the malicious class.
        6. The malicious code within the custom class is executed on the system.
- Impact:
    - Critical. Successful exploitation allows for arbitrary code execution on the system running the slo-generator.
    - An attacker can gain complete control over the system, potentially leading to:
        - Data breaches and exfiltration of sensitive information (e.g., API keys, credentials, SLO reports, system data).
        - System compromise, including modification or deletion of files.
        - Denial of service by crashing the system or consuming resources.
        - Further lateral movement within the network if the compromised system has network access.
- Vulnerability Rank: critical
- Currently Implemented Mitigations:
    - None. The current implementation lacks any input validation or sanitization for the `class` path, and no restrictions are in place to prevent loading arbitrary Python code.
- Missing Mitigations:
    - Input validation and sanitization: Implement strict validation for the `class` path to ensure it only points to allowed and trusted classes within the slo-generator codebase or a predefined safe plugin directory. Sanitize user-provided input to prevent path traversal or injection attacks.
    - Restrict custom class loading: Remove or restrict the ability to load custom classes dynamically. If custom extensions are necessary, implement a secure plugin mechanism with sandboxing, code signing, or a whitelist of allowed classes and modules.
    - Principle of least privilege: Ensure the slo-generator tool runs with the minimal necessary privileges to limit the impact of arbitrary code execution. Use dedicated service accounts with restricted permissions.
    - Security Audits and Code Reviews: Conduct regular security audits and code reviews, specifically focusing on dynamic code loading and YAML/JSON parsing to identify and eliminate potential vulnerabilities.
- Preconditions:
    - Attacker's ability to supply a malicious configuration file to the slo-generator. This could be achieved through:
        - Modifying existing configuration files if the attacker has write access to the file system where configurations are stored.
        - Providing a malicious configuration file through the API if the API endpoint is exposed and accessible to the attacker.
        - Tricking an administrator into using a malicious configuration file, for example, by social engineering or supply chain attacks.
    - The slo-generator application must be running in an environment where arbitrary code execution is not prevented by system-level security measures (e.g., containers without sufficient security restrictions).
- Source Code Analysis:
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
- Security Test Case:
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