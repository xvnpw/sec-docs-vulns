- Vulnerability 1: Malicious Model Registration via Parameter File Input

  - Vulnerability Name: Malicious Model Registration via Parameter File Input
  - Description:
    1. An attacker can modify the `parameters_file` input to the GitHub Action. This file, by default `registermodel.json`, is expected to be located in the `.cloud/.azure` directory of the repository, but the action allows specifying a different file path through the `parameters_file` input.
    2. Within this `parameters_file`, the `model_file_name` parameter specifies the path to the model file that will be registered in Azure Machine Learning.
    3. The action directly uses the `model_file_name` from the `parameters_file` to locate and register the model, without sufficient validation or sanitization of the provided path.
    4. If an attacker can control the content of the `parameters_file`, they can manipulate the `model_file_name` to point to a malicious file within the repository or potentially accessible from the GitHub Actions environment.
    5. When the action executes, it will register the model from the attacker-specified path, effectively allowing the registration of a malicious model into the Azure Machine Learning workspace.
  - Impact:
    - Successful exploitation allows an attacker to register a malicious model in the Azure Machine Learning workspace.
    - This constitutes a supply chain vulnerability, as the malicious model can then be deployed and used in downstream ML workflows within the organization.
    - The impact of using a malicious model can range from subtle data poisoning and model performance degradation to more severe consequences such as unauthorized access, data exfiltration, or system compromise, depending on the nature of the malicious model and its intended use.
  - Vulnerability Rank: High
  - Currently Implemented Mitigations:
    - None. The action reads the `parameters_file` and uses the `model_file_name` directly to construct the model path without any validation against allowed paths or content of the file.
  - Missing Mitigations:
    - **Input Validation and Sanitization:** Implement robust validation for the `parameters_file` input and its contents, specifically the `model_file_name`. This should include:
        - Schema validation (already partially implemented via `validate_json` but needs to be more restrictive on path inputs).
        - Sanitization of the `model_file_name` to prevent path traversal attacks.
        - Restriction of allowed paths for `model_file_name` to a predefined safe location within the repository or within the outputs of a trusted Azure ML run.
    - **Path Restriction:** Enforce that `model_file_name` must point to a file within a designated safe directory in the repository or a verified output location from a trusted Azure ML run. Disallow absolute paths or paths outside of the allowed directories.
    - **Model Integrity Checks:** Consider implementing basic integrity checks on the model file itself, such as verifying file type or, if feasible, applying more advanced checks like signature verification or scanning for known malicious patterns.
  - Preconditions:
    - The attacker needs to be able to modify the `parameters_file` that is used by the GitHub Action. This can be achieved through:
        - Submitting a Pull Request to the repository containing a modified `parameters_file`. If the repository accepts contributions without rigorous review, this could be a viable attack vector.
        - Compromising a developer account with write access to the repository, allowing direct modification of the `parameters_file`.
    - The GitHub workflow must be configured to use the `aml-registermodel` action and utilize the user-provided `parameters_file` input.
  - Source Code Analysis:
    1. **Parameter File Loading:** In `code/main.py`, the action loads the `parameters_file` specified by the `INPUT_PARAMETERS_FILE` environment variable, defaulting to `registermodel.json`:
       ```python
       parameters_file = os.environ.get("INPUT_PARAMETERS_FILE", default="registermodel.json")
       parameters_file_path = os.path.join(".cloud", ".azure", parameters_file)
       try:
           with open(parameters_file_path) as f:
               parameters = json.load(f)
       except FileNotFoundError:
           ...
       ```
    2. **Model File Name Extraction:** The `model_file_name` is extracted from the loaded `parameters` dictionary without specific path validation:
       ```python
       model_file_name = parameters.get("model_file_name", "model.pkl")
       ```
    3. **Local Model Path Construction (if no run_id/experiment_name):** If registering a local model (i.e., `run_id` and `experiment_name` are not provided), the code searches for the `model_file_name` within the `GITHUB_WORKSPACE`:
       ```python
       if not experiment_name or not run_id:
           ...
           directory = config_file_path = os.environ.get("GITHUB_WORKSPACE", default=None)
           model_paths = []
           for root, dirs, files in os.walk(directory):
               for filename in files:
                   if filename == model_file_name:
                       path = os.path.join(root, filename)
                       model_paths.append(path)
           model_path = model_paths[0]
           ...
           model = Model.register(..., model_path=model_path, ...)
       ```
       While `os.path.join` and `os.walk` are used, relying on filename matching within a workspace still leaves room for malicious file placement and potential path manipulation if `model_file_name` is not strictly validated.
    4. **AML Run Model Path Extraction (if run_id/experiment_name provided):** If registering a model from an AML run, the code retrieves the model path from the run's file names based on `model_file_name`:
       ```python
       else:
           ...
           model_path = [file_name for file_name in best_run.get_file_names() if model_file_name in os.path.split(file_name)[-1]][0]
           ...
           model = best_run.register_model(..., model_path=model_path, ...)
       ```
       This approach depends on the assumption that `best_run.get_file_names()` returns only safe and expected paths. However, if the AML run itself was compromised or if there are vulnerabilities in how file names are handled within AML Run, this could still be exploited.
    5. **Model Registration:** In both local and AML run scenarios, the `model_path` derived from the user-controlled `model_file_name` is directly passed to the `Model.register` or `best_run.register_model` functions.

  - Security Test Case:
    1. **Fork the Repository:** Create a fork of the `Azure/aml-registermodel` repository to your own GitHub account.
    2. **Create Malicious Model File:** In your forked repository, create a file named `malicious_model.pkl` at the root level. This file can be a simple text file for testing purposes, or a more realistic malicious model file (e.g., a Python pickle file containing potentially harmful code).
    3. **Modify Parameters File:** Edit the `.cloud/.azure/registermodel.json` file in your forked repository. Change the content to the following:
       ```json
       {
           "model_file_name": "malicious_model.pkl",
           "model_name": "malicious-model-test"
       }
       ```
    4. **Create Pull Request (Optional but Recommended):** Create a Pull Request from your forked repository to the original `Azure/aml-registermodel` repository (if you have permissions or want to demonstrate the vulnerability to maintainers). Alternatively, you can directly test within your fork if you have configured Azure credentials there.
    5. **Trigger Workflow:** Ensure a workflow in your fork (or the original repo if you created a PR and it triggers workflows from PRs) is set up to use the `aml-registermodel` action. This workflow should use the modified `parameters_file`. You might need to manually trigger the workflow or push a commit to your fork to initiate it.
    6. **Observe Action Output:** Monitor the GitHub Action run logs. If the action completes successfully, it indicates that it has attempted to register a model.
    7. **Verify Model Registration in Azure ML:** Go to your Azure Machine Learning workspace (the one configured in your workflow's Azure credentials). Check the "Models" section. You should find a model named "malicious-model-test" (or whatever you set as `model_name` in the `parameters_file`).
    8. **Inspect Model Details (Optional):** Click on the registered model and inspect its details, particularly the "Path" or "Source" information, if available. It should indicate that the model was registered from the `malicious_model.pkl` file you created.
    9. **Attempt Model Deployment/Usage (Optional and at your own risk):** If you want to further demonstrate the impact, you could attempt to deploy this "malicious" model or use it in a pipeline. This step should be performed with caution in a non-production or test environment to understand the potential consequences of using a maliciously registered model.