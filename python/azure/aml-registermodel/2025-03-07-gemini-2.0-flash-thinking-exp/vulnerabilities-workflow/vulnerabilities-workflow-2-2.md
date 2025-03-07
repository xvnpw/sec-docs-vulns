#### 1. Path Traversal in `parameters_file` leading to Arbitrary File Registration

* Description:
    1. The GitHub Action reads model registration parameters from a JSON file specified by the `parameters_file` input, defaulting to `registermodel.json` located in the `.cloud/.azure` directory.
    2. Within this parameters file, the `model_file_name` parameter specifies the path to the model file to be registered.
    3. If the `experiment_name` and `run_id` inputs are not provided, the action registers a model from the local GitHub repository.
    4. The action constructs the `model_path` based on the `model_file_name` parameter. If `model_file_name` contains path separators (e.g., `/`, `\`), it's directly used as the `model_path`.
    5. An attacker who can modify the `parameters_file` in the repository can set the `model_file_name` to include path traversal sequences like `../` to point to files outside the intended workspace directory.
    6. When the action executes, it will attempt to register the file specified by the manipulated `model_path` as a machine learning model in Azure Machine Learning.
    7. This allows an attacker to register arbitrary files from the repository as models, potentially including sensitive information, backdoors, or malicious code disguised as a model.

* Impact:
    - **High**: An attacker can register arbitrary files from the repository as machine learning models in Azure Machine Learning. This could lead to the exposure of sensitive data if an attacker registers a file containing secrets or confidential information. It could also enable the registration of a backdoor or malicious code as a model, which could be later deployed and executed in an Azure Machine Learning environment, leading to further compromise.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - None. The code does not perform any validation or sanitization of the `model_file_name` to prevent path traversal.

* Missing Mitigations:
    - Input validation for `model_file_name` in `main.py` to prevent path traversal. This could include:
        - Validating that the `model_file_name` does not contain path traversal sequences like `../` or `..\\`.
        - Ensuring that the resolved `model_path` is within the expected workspace directory.

* Preconditions:
    - The attacker needs to have write access to the GitHub repository to modify the `parameters_file` (e.g., `registermodel.json`) or the ability to control the `parameters_file` input to the GitHub Action workflow.

* Source Code Analysis:
    - File: `/code/code/main.py`
    - Lines 140-152 handle the case where the model is registered from the local GitHub workspace.
    - Line 144: `model_file_name = parameters.get("model_file_name", "model.pkl")` retrieves the `model_file_name` from the `parameters_file`.
    - Line 145: `if len(splitall(model_file_name)) > 1:` checks if the `model_file_name` contains path separators.
    - Line 146: `model_path = model_file_name` directly assigns the attacker-controlled `model_file_name` as `model_path` if it contains path separators, without any validation.
    - Lines 147-152: If `model_file_name` does not contain path separators, the code attempts to find the file within the workspace, which is a safer approach, but this logic is bypassed if the attacker includes path separators in `model_file_name`.
    ```python
    # Defining model path
    print("::debug::Defining model path")
    model_file_name = parameters.get("model_file_name", "model.pkl")
    if len(splitall(model_file_name)) > 1: # Check for path separators
        model_path = model_file_name # Vulnerable line: Directly uses attacker-controlled path
    else:
        directory = config_file_path = os.environ.get("GITHUB_WORKSPACE", default=None)
        model_paths = []
        for root, dirs, files in os.walk(directory):
            for filename in files:
                if filename == model_file_name:
                    path = os.path.join(root, filename)
                    model_paths.append(path)
            model_path = model_paths[0]
    ```

* Security Test Case:
    1. Create a file named `sensitive_data.txt` in the root of the repository with some sensitive content (e.g., "This is sensitive information.").
    2. Create a new branch in the repository (e.g., `malicious-model-registration`).
    3. Modify the `.cloud/.azure/registermodel.json` file in the new branch to include the following content:
    ```json
    {
      "model_file_name": "../../../sensitive_data.txt",
      "model_name": "malicious-model"
    }
    ```
    4. Create a new workflow or modify an existing workflow in `.github/workflows/` to trigger the `aml-registermodel` action on pushes to the `malicious-model-registration` branch. Ensure that `experiment_name` and `run_id` inputs are not set to trigger local model registration.
    ```yaml
    name: Malicious Model Registration Test
    on:
      push:
        branches:
          - malicious-model-registration

    jobs:
      register_malicious_model:
        runs-on: ubuntu-latest
        steps:
          - name: Checkout repository
            uses: actions/checkout@v3

          - name: Azure Login
            uses: azure/login@v1
            with:
              creds: ${{ secrets.AZURE_CREDENTIALS }}

          - name: Register Malicious Model
            uses: Azure/aml-registermodel@v1
            with:
              azure_credentials: ${{ secrets.AZURE_CREDENTIALS }}
              parameters_file: ".cloud/.azure/registermodel.json"
    ```
    5. Commit and push the changes to the `malicious-model-registration` branch.
    6. After the workflow run completes successfully, go to the Azure Machine Learning workspace and check the registered models.
    7. Verify that a model named `malicious-model` is registered.
    8. Download the `malicious-model` and inspect its content. It should contain the content of the `sensitive_data.txt` file, proving that an arbitrary file from outside the intended model directory was successfully registered due to path traversal.