- Vulnerability Name: Python Code Injection via `runconfig_python_file`
- Description:
    1. An attacker can control the `runconfig_python_file` input parameter of the GitHub Action by modifying the workflow file.
    2. The attacker sets the `runconfig_python_file` input to point to a malicious Python file hosted within the repository or accessible from it.
    3. When the GitHub Action executes, the `load_runconfig_python` function in `/code/code/utils.py` is called.
    4. This function uses `importlib.util.spec_from_file_location` to load the Python file specified by the attacker-controlled `runconfig_python_file` input.
    5. `importlib.util.module_from_spec` and `run_config_spec.loader.exec_module` are then used to execute the code within the malicious Python file.
    6. The malicious Python code is executed within the Azure Machine Learning environment with the permissions of the Azure credentials provided to the action.
- Impact:
    - Arbitrary Python code execution within the Azure Machine Learning environment.
    - Potential unauthorized access to Azure Machine Learning workspace and associated Azure cloud resources.
    - Data exfiltration from the Azure Machine Learning environment.
    - Modification or deletion of resources within the Azure Machine Learning environment.
    - Compromise of machine learning models and training processes.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None. The action currently lacks any input validation or sanitization for the `runconfig_python_file` input. It directly loads and executes the Python file specified by the user.
- Missing Mitigations:
    - Input validation: Implement strict validation of the `runconfig_python_file` input to ensure it points to a safe and expected file path.
    - Path restriction: Restrict the allowed paths for `runconfig_python_file` to a specific directory within the repository, preventing the inclusion of arbitrary or external files.
    - Code review: Conduct a thorough code review of the `load_runconfig_python` function and the entire action to identify and address any other potential injection points or vulnerabilities.
    - Principle of least privilege: Consider if the action requires full contributor role, and if it can be narrowed down to a more restrictive set of permissions to limit the blast radius of potential compromise.
- Preconditions:
    - Attacker needs to be able to modify the GitHub workflow file in the repository. This could be achieved through:
        - Direct write access to the repository (e.g., if the attacker is a collaborator).
        - Submitting a pull request that modifies the workflow file and getting it merged by a repository maintainer.
- Source Code Analysis:
    - File: `/code/action.yml`
        ```yaml
        inputs:
          runconfig_python_file:
            description: "Path to the python script in your repository  in which you define your run and return an Estimator, Pipeline, AutoMLConfig or ScriptRunConfig object."
            required: false
            default: "code/train/run_config.py"
        ```
        - The `runconfig_python_file` input is defined, allowing users to specify a Python file path.

    - File: `/code/code/main.py`
        ```python
        run_config = load_runconfig_python(
            workspace=ws,
            runconfig_python_file=parameters.get("runconfig_python_file", "code/train/run_config.py"),
            runconfig_python_function_name=parameters.get("runconfig_python_function_name", "main")
        )
        ```
        - The `main` function in `/code/code/main.py` calls `load_runconfig_python` from `utils.py`, passing the user-provided `runconfig_python_file` parameter.

    - File: `/code/code/utils.py`
        ```python
        import importlib
        ...
        def load_runconfig_python(workspace, runconfig_python_file, runconfig_python_function_name):
            ...
            try:
                run_config_spec = importlib.util.spec_from_file_location(
                    name="runmodule",
                    location=runconfig_python_file
                )
                run_config_module = importlib.util.module_from_spec(spec=run_config_spec)
                run_config_spec.loader.exec_module(run_config_module)
                run_config_function = getattr(run_config_module, runconfig_python_function_name, None)
            except ...
            ...
            try:
                run_config = run_config_function(workspace)
            except ...
            return run_config
        ```
        - The `load_runconfig_python` function in `/code/code/utils.py` directly uses `importlib.util.spec_from_file_location` with the user-provided `runconfig_python_file` to load and execute the Python code without any validation or sanitization of the file path.

- Security Test Case:
    1. Create a new file named `malicious_run_config.py` in the root of the repository with the following content:
        ```python
        import os
        from azureml.core import Workspace
        def main(workspace: Workspace):
            print("::warning::Malicious code executed!")
            # Example malicious action: Print workspace details (can be extended to exfiltrate data or more)
            print(f"::warning::Workspace name: {workspace.name}")
            print(f"::warning::Subscription ID: {workspace.subscription_id}")
            print(f"::warning::Resource Group: {workspace.resource_group}")
            # Exit to prevent actual training run
            exit(1)
        ```
    2. Modify the workflow file (e.g., `.github/workflows/your_workflow.yml`) to override the `runconfig_python_file` input for the `aml-run` action:
        ```yaml
        ...
        - uses: Azure/aml-run@v1
          id: aml_run
          with:
            azure_credentials: ${{ secrets.AZURE_CREDENTIALS }}
            runconfig_python_file: malicious_run_config.py # Point to the malicious python file
        ...
        ```
    3. Commit and push the changes to the repository to trigger the workflow.
    4. Observe the GitHub Action logs. You will see the "::warning::Malicious code executed!" message, followed by workspace details printed as warnings, indicating that the malicious Python code from `malicious_run_config.py` was successfully executed within the Azure ML environment. The workflow will also exit with code 1 due to the `exit(1)` call in the malicious script, preventing the intended training run.

This test case demonstrates that an attacker can inject and execute arbitrary Python code by controlling the `runconfig_python_file` input, confirming the Python Code Injection vulnerability.