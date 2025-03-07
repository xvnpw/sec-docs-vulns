* Vulnerability Name: Arbitrary Code Execution via Run Config Python File
* Description:
    - An attacker compromises the GitHub repository.
    - The attacker modifies the GitHub workflow file (e.g., `.github/workflows/main.yml`) to change the value of the `runconfig_python_file` input for the `Azure/aml-run` action. This input specifies the Python file that defines the Azure ML run configuration.
    - The attacker creates a malicious Python file and sets the `runconfig_python_file` input to point to this file. This malicious file can contain arbitrary Python code.
    - When the GitHub workflow runs, the `Azure/aml-run` action executes.
    - The action loads the malicious Python file specified by the attacker-controlled `runconfig_python_file` input using `importlib.util.spec_from_file_location` and `importlib.util.module_from_spec`.
    - The action then executes a function (default `main`) within the malicious Python file using `getattr` and function call.
    - The malicious Python code is executed within the Azure Machine Learning environment, potentially granting the attacker unauthorized access to data, resources, or the ability to perform other malicious actions within the Azure ML workspace.
* Impact:
    - Full control over the Azure Machine Learning environment.
    - Data exfiltration or manipulation.
    - Resource compromise within Azure ML.
    - Lateral movement within the Azure environment if credentials are mismanaged.
* Vulnerability Rank: Critical
* Currently Implemented Mitigations: None
* Missing Mitigations:
    - Input validation for `runconfig_python_file` to restrict the path to a predefined set of allowed files or locations.
    - Code review and static analysis to detect potentially malicious code in the run config Python file (though this is difficult in general).
    - Principle of least privilege for the service principal used by the GitHub Action to limit the impact of a successful exploit.
    - Documentation to warn users about the risks of modifying the workflow and `runconfig_python_file`.
* Preconditions:
    - Attacker has write access to the GitHub repository (e.g., compromised repository maintainer account or successful pull request merge of malicious changes).
* Source Code Analysis:
    - In `/code/main.py`:
        - Lines 118-134: This section of the code is responsible for loading the run configuration.
        - Lines 129-134: If no run configuration is loaded from YAML files, the code proceeds to load it from a Python file using the `load_runconfig_python` function. The path to this Python file is determined by the `runconfig_python_file` parameter, which is directly taken from user input (`parameters.get("runconfig_python_file", "code/train/run_config.py")`).
    - In `/code/utils.py`:
        - Lines 131-171: The `load_runconfig_python` function is defined here.
        - Lines 140-148: The function uses `importlib.util.spec_from_file_location` to load the Python file specified by the `runconfig_python_file` parameter.
        - Line 149: `run_config_spec.loader.exec_module(run_config_module)` executes the loaded Python module.
        - Line 150: `run_config_function = getattr(run_config_module, runconfig_python_function_name, None)` retrieves the specified function name (default "main") from the loaded module.
        - Line 162: `run_config = run_config_function(workspace)` finally executes the function, passing the Azure ML workspace object as an argument.
        - **Vulnerability:** There is no validation or sanitization of the `runconfig_python_file` input before it is used in `importlib.util.spec_from_file_location`. This allows an attacker to specify any Python file path within the repository, leading to arbitrary code execution when the action runs.
* Security Test Case:
    1. Fork the repository to your own GitHub account.
    2. Navigate to the workflow files (e.g., `.github/workflows/integration_test.yml`) in your forked repository. Edit the workflow file.
    3. In the workflow file, locate the `Azure/aml-run` action step. Modify the `with` section of this step to include or modify the `runconfig_python_file` input to point to a malicious Python file. For example:
        ```yaml
        - uses: Azure/aml-run@v1
          id: aml_run
          with:
            azure_credentials: ${{ secrets.AZURE_CREDENTIALS }}
            runconfig_python_file: malicious_run_config.py # Point to malicious file
        ```
    4. In the root of your forked repository, create a new Python file named `malicious_run_config.py` with the following malicious code. This code is a proof of concept and can be replaced with more harmful actions:
        ```python
        import os
        from azureml.core import Workspace

        def main(workspace: Workspace):
            print("Malicious code execution started")
            try:
                # Example malicious action: List compute targets (can be replaced with data exfiltration, etc.)
                compute_targets = Workspace.get(
                    name=workspace.name,
                    subscription_id=workspace.subscription_id,
                    resource_group=workspace.resource_group
                ).compute_targets
                print("Compute targets:", list(compute_targets.keys()))
            except Exception as e:
                print(f"Error accessing compute targets: {e}")
            print("Malicious code execution finished")

            # Return a dummy valid run config to prevent action failure
            from azureml.core import ScriptRunConfig, Environment, ComputeTarget
            compute_target = ComputeTarget(workspace=workspace, name="aml-intTest") # Replace with existing compute target if needed
            environment = Environment(name="dummy-env") # Dummy environment
            script_config = ScriptRunConfig(source_directory=".", script="dummy_script.py", compute_target=compute_target, environment=environment)
            return script_config
        ```
    5. Also, create a dummy script file named `dummy_script.py` in the repository root. This file can be empty, as it's only needed to satisfy the `ScriptRunConfig` object returned by the malicious script.
    6. Commit and push both `malicious_run_config.py` and the modified workflow file to your forked repository.
    7. Observe the GitHub Actions run for your fork. Check the logs for the `Azure/aml-run` action step.
    8. If the vulnerability is successfully exploited, you will see the output "Malicious code execution started", followed by the attempt to list compute targets (or any other malicious actions you included in `malicious_run_config.py`), and finally "Malicious code execution finished" in the action logs. This demonstrates that arbitrary Python code provided by the attacker was executed within the Azure ML environment.