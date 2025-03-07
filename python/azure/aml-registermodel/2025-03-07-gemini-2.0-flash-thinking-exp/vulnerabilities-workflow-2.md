## Combined Vulnerability List

### 1. Malicious Model Registration via Parameters File Modification

* **Vulnerability Name:** Malicious Model Registration via Parameters File Modification
* **Description:**
    1. An attacker forks the repository.
    2. The attacker creates a new branch in their forked repository.
    3. The attacker modifies the `parameters_file` (default: `registermodel.json`) within the forked repository. This modification can include:
        * Changing the `model_file_name` to point to a malicious model file hosted externally or within the attacker's forked repository.
        * Altering model registration parameters such as `model_name`, `model_description`, `model_tags`, or `model_properties` to inject malicious information or misrepresent the model.
    4. The attacker submits a pull request to the original repository, proposing to merge their malicious changes, including the modified `parameters_file`.
    5. If the repository maintainers merge this pull request without proper review and validation of the `parameters_file`, the GitHub Action workflow will execute using the attacker-supplied parameters.
    6. Consequently, a malicious model, or a model with attacker-defined metadata, will be registered in the Azure Machine Learning model registry.
* **Impact:**
    * **Malicious Model Registration:** Registering a malicious model can have severe consequences. If this model is subsequently deployed and used in production systems, it can lead to:
        * **Data Poisoning:** The malicious model might be designed to subtly corrupt data in downstream processes.
        * **Model Poisoning/Backdoor:** The model could contain backdoors or vulnerabilities allowing unauthorized access or control over systems using the model.
        * **Incorrect Predictions/Decisions:** The model may be designed to produce biased or incorrect predictions, leading to flawed decision-making in applications relying on it.
    * **Altered Model Metadata:** Even if the model itself isn't malicious, altering registration parameters can:
        * **Mislead Users:** Incorrect descriptions or tags can mislead users about the model's purpose, origin, or performance.
        * **Cause Confusion/Management Issues:** Incorrect naming or properties can complicate model management and versioning within the Azure ML registry.
* **Vulnerability Rank:** High
* **Currently Implemented Mitigations:**
    * **Input Validation:** The `validate_json` function in `/code/code/utils.py` and schemas defined in `/code/code/schemas.py` are used to validate the structure and data types of the `parameters_file`. This is implemented in the `main` function of `/code/code/main.py` before using the parameters.
    * **Schema Enforcement:** The `parameters_schema` in `/code/code/schemas.py` defines the expected structure and data types for the `parameters_file`, limiting the types of inputs the action will accept.
* **Missing Mitigations:**
    * **Pull Request Review Process:** There is no enforced pull request review process documented or implemented within the provided files. Code changes, including modifications to the `parameters_file`, could be merged without human inspection.
    * **Workflow Access Controls:** The project lacks explicit workflow access controls to restrict who can approve and merge pull requests. If repository collaborators or maintainers are compromised, they could merge malicious pull requests.
    * **Content Validation of `model_file_name`:** While the `parameters_schema` validates the `model_file_name` as a string, it does not validate the *content* or *source* of the model file itself. The action trusts that the specified `model_file_name` points to a legitimate and safe model.
* **Preconditions:**
    * The attacker must be able to fork the repository and create a pull request. This is generally possible for public GitHub repositories.
    * The repository must lack proper pull request review processes and workflow access controls, allowing pull requests to be merged without thorough inspection of changes, especially to configuration files like `parameters_file`.
* **Source Code Analysis:**
    1. **`action.yml`**: Defines `parameters_file` as an input.
        ```yaml
        inputs:
          parameters_file:
            description: "JSON file including the parameters for registering the model."
            required: true
            default: "registermodel.json"
        ```
    2. **`main.py`**: Loads and validates `parameters_file`.
        ```python
        parameters_file = os.environ.get("INPUT_PARAMETERS_FILE", default="registermodel.json")
        parameters_file_path = os.path.join(".cloud", ".azure", parameters_file)
        try:
            with open(parameters_file_path) as f:
                parameters = json.load(f)
        except FileNotFoundError:
            print(f"::debug::Could not find parameter file in {parameters_file_path}. Please provide a parameter file in your repository if you do not want to use default settings (e.g. .cloud/.azure/registermodel.json).")
            parameters = {}

        # Checking provided parameters
        print("::debug::Checking provided parameters")
        validate_json(
            data=parameters,
            schema=parameters_schema,
            input_name="PARAMETERS_FILE"
        )
        ```
    3. **`validate_json` function in `utils.py`**: Performs schema validation.
        ```python
        def validate_json(data, schema, input_name):
            validator = jsonschema.Draft7Validator(schema)
            errors = list(validator.iter_errors(data))
            if len(errors) > 0:
                for error in errors:
                    print(f"::error::JSON validation error: {error}")
                raise AMLConfigurationException(f"JSON validation error for '{input_name}'. Provided object does not match schema. Please check the output for more details.")
            else:
                print(f"::debug::JSON validation passed for '{input_name}'. Provided object does match schema.")
        ```
    4. **Model Registration in `main.py`**: Uses parameters from the loaded file.
        ```python
        if local_model:
            try:
                model = Model.register(
                    workspace=ws,
                    model_path=model_path, # Path from parameters_file
                    model_name=parameters.get("model_name", default_model_name)[:32], # Name from parameters_file
                    tags=parameters.get("model_tags", None), # Tags from parameters_file
                    properties=parameters.get("model_properties", None), # Properties from parameters_file
                    description=parameters.get("model_description", None), # Description from parameters_file
                    # ... other parameters ...
                )
            except ...
        ```

* **Security Test Case:**
    1. **Fork the repository:** Create a fork of the `Azure/aml-registermodel` repository on your GitHub account.
    2. **Create a malicious `parameters_file`:** In your forked repository, create or modify the `registermodel.json` file (or whatever file is specified by `parameters_file` input in `action.yml`) within the `.cloud/.azure` directory.  Modify this file to include malicious configurations. For example:
        ```json
        {
          "model_name": "malicious-model",
          "model_file_name": "malicious_model.pkl",
          "model_description": "This is a malicious model registered by an attacker.",
          "model_tags": {
            "malicious": "true",
            "attacker": "your_github_username"
          }
        }
        ```
        You would also need to create a dummy file named `malicious_model.pkl` (it doesn't need to be a real model for this test, an empty file will suffice to demonstrate the registration process). Place this file in the root of your forked repository to simulate a locally hosted "malicious model".
    3. **Create a branch:** Create a new branch in your forked repository, for example, `malicious-pr`.
    4. **Commit and push changes:** Commit the modified `parameters_file` and the dummy `malicious_model.pkl` to your `malicious-pr` branch and push it to your forked repository.
    5. **Create a Pull Request:** Create a pull request from your `malicious-pr` branch in your forked repository to the `master` branch of the original `Azure/aml-registermodel` repository.
    6. **Observe the Workflow Execution (if merged):** If a repository maintainer were to mistakenly merge this pull request without proper review, the GitHub Action workflow would automatically trigger.
    7. **Verify Malicious Model Registration in Azure ML:** After the workflow completes (assuming successful merge and execution), check the Azure Machine Learning workspace (configured in the workflow) and verify if a model named `malicious-model` with the description "This is a malicious model registered by an attacker." and tags `malicious: true`, `attacker: your_github_username` has been successfully registered. If the model is registered with these details, it confirms the vulnerability.

### 2. Path Traversal in `parameters_file` leading to Arbitrary File Registration

* **Vulnerability Name:** Path Traversal in `parameters_file` leading to Arbitrary File Registration
* **Description:**
    1. The GitHub Action reads model registration parameters from a JSON file specified by the `parameters_file` input, defaulting to `registermodel.json` located in the `.cloud/.azure` directory.
    2. Within this parameters file, the `model_file_name` parameter specifies the path to the model file to be registered.
    3. If the `experiment_name` and `run_id` inputs are not provided, the action registers a model from the local GitHub repository.
    4. The action constructs the `model_path` based on the `model_file_name` parameter. If `model_file_name` contains path separators (e.g., `/`, `\`), it's directly used as the `model_path`.
    5. An attacker who can modify the `parameters_file` in the repository can set the `model_file_name` to include path traversal sequences like `../` to point to files outside the intended workspace directory.
    6. When the action executes, it will attempt to register the file specified by the manipulated `model_path` as a machine learning model in Azure Machine Learning.
    7. This allows an attacker to register arbitrary files from the repository as models, potentially including sensitive information, backdoors, or malicious code disguised as a model.

* **Impact:**
    - **High**: An attacker can register arbitrary files from the repository as machine learning models in Azure Machine Learning. This could lead to the exposure of sensitive data if an attacker registers a file containing secrets or confidential information. It could also enable the registration of a backdoor or malicious code as a model, which could be later deployed and executed in an Azure Machine Learning environment, leading to further compromise.

* **Vulnerability Rank:** High

* **Currently Implemented Mitigations:**
    - None. The code does not perform any validation or sanitization of the `model_file_name` to prevent path traversal.

* **Missing Mitigations:**
    - Input validation for `model_file_name` in `main.py` to prevent path traversal. This could include:
        - Validating that the `model_file_name` does not contain path traversal sequences like `../` or `..\\`.
        - Ensuring that the resolved `model_path` is within the expected workspace directory.

* **Preconditions:**
    - The attacker needs to have write access to the GitHub repository to modify the `parameters_file` (e.g., `registermodel.json`) or the ability to control the `parameters_file` input to the GitHub Action workflow.

* **Source Code Analysis:**
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

* **Security Test Case:**
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