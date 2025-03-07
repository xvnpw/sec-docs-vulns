- Vulnerability Name: Insecure YAML Parsing in AutoML Job Configuration
- Description:
    - An attacker crafts a malicious YAML configuration file for an AutoML job.
    - This YAML file contains a payload that exploits insecure YAML parsing, potentially using YAML tags to execute arbitrary Python code or system commands during deserialization.
    - The attacker submits this crafted YAML file through the AutoML CLI or REST API to create an AutoML job.
    - The AutoML CLI or REST API, due to insecure YAML parsing practices, processes the malicious YAML file without proper sanitization or safe loading.
    - During the YAML parsing process, the malicious payload embedded in the YAML configuration is executed on the server or compute environment handling the AutoML job.
    - This execution can lead to arbitrary command execution, allowing the attacker to run commands on the AutoML infrastructure.
- Impact:
    - Arbitrary command execution on the AutoML compute environment.
    - Potential for unauthorized access to sensitive data and resources within the Azure environment.
    - Possible compromise of the model training process and the integrity of trained models.
    - Risk of lateral movement to other Azure services or resources accessible from the compromised environment.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - Based on the provided project files, there are no specific mitigations implemented within these files to address insecure YAML parsing. The files are primarily focused on component definitions, test pipelines, and example configurations, not the core CLI/API parsing logic.
- Missing Mitigations:
    - **Secure YAML Loading:** Implement secure YAML parsing practices in the AutoML CLI and REST API. Specifically, use safe YAML loading functions (e.g., `yaml.safe_load` in Python's `PyYAML` library or similar in other languages) that prevent the execution of arbitrary code during deserialization of YAML files.
    - **Input Validation and Sanitization:** Implement strict schema validation for all YAML configuration files to ensure they conform to expected structures and data types. Sanitize all input parameters from YAML files to prevent injection attacks.
    - **Principle of Least Privilege:** Ensure that the AutoML jobs and related processes run with the minimum necessary privileges. This limits the potential impact if arbitrary command execution is achieved.
- Preconditions:
    - The attacker must have the ability to interact with the AutoML CLI or REST API to submit YAML configuration files for AutoML job creation.
    - The AutoML CLI or REST API must be vulnerable to insecure YAML parsing, allowing for code or command injection through malicious YAML payloads.
- Source Code Analysis:
    - Unfortunately, the provided project files do not include the source code for the AutoML CLI or REST API where YAML parsing would be implemented. Therefore, a detailed source code analysis to pinpoint the exact location of the vulnerability within these files is not possible.
    - To perform a source code analysis, access to the codebase of the AutoML CLI or REST API is required to examine how YAML configuration files are parsed and processed. This analysis should focus on identifying the YAML parsing library used and whether safe loading practices are employed.
- Security Test Case:
    1. Set up an Azure Machine Learning workspace and environment where the AutoML CLI or REST API can be used to create AutoML jobs.
    2. Create a malicious YAML configuration file (e.g., `malicious_automl_config.yaml`) with a payload designed to exploit insecure YAML parsing. For example, include a YAML tag that attempts to execute a system command:

    ```yaml
    $schema: https://azuremlsdk2.blob.core.windows.net/development/autoMLJob.schema.json
    type: automl_job
    name: malicious-yaml-job
    experiment_name: malicious_yaml_exploit
    compute:
      target: azureml:cpu-cluster
    general:
        task: regression
        primary_metric: normalized_root_mean_squared_error
    data:
        target_column_name: ERP
        training:
            dataset: azureml:machineData_train_dataset:1
    command_payload: !!python/object/apply:os.system ["touch /tmp/yaml_pwned"]
    ```

    3. Use the AutoML CLI to create an AutoML job using this malicious YAML file:
       ```bash
       az ml job create --file malicious_automl_config.yaml --workspace-name <your-workspace-name> --resource-group <your-resource-group> --subscription <your-subscription-id>
       ```
       Alternatively, use the REST API to submit the job with the malicious YAML configuration.
    4. After submitting the job and allowing it to run (or attempt to run), access the compute environment where the AutoML job was executed (if possible and permitted) or check the job logs for any indication of command execution.
    5. Verify if the command injected via YAML was executed. In the example above, check if the file `/tmp/yaml_pwned` was created in the expected compute environment. Successful creation of this file (or similar evidence of command execution) confirms the insecure YAML parsing vulnerability.
    6. If the command is executed, this demonstrates that an attacker can achieve arbitrary command execution through maliciously crafted YAML configuration files submitted to the AutoML service.