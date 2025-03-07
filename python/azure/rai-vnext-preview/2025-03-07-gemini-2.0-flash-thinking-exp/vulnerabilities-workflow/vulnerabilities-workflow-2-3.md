### Vulnerability 1: Unsafe Deserialization of Machine Learning Models

- Description:
    1. A user uploads or specifies a machine learning model for analysis within the Responsible AI Dashboard.
    2. The Responsible AI Dashboard uses MLflow's `load_model` function to load the specified model.
    3. If a malicious user crafts a pickled model and registers it in Azure ML or provides a path to it, and this model is then loaded by the Responsible AI Dashboard, arbitrary Python code embedded in the pickled model can be executed during deserialization.
    4. This can occur when the `rai_insights_constructor` component loads the model using `mlflow.pyfunc.load_model` in `rai_component_utilities.py`.

- Impact:
    - **Critical**
    - Remote Code Execution (RCE). An attacker can execute arbitrary code on the server or the user's machine running the Responsible AI Dashboard. This could lead to:
        - Data exfiltration: Stealing sensitive data, including other models, datasets, and credentials stored in the Azure ML workspace.
        - System compromise: Gaining full control over the server or user's machine, potentially installing malware, creating backdoors, or using it as a launchpad for further attacks.
        - Workspace takeover: Modifying or deleting critical Azure ML workspace resources.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - None identified in the provided project files. The code relies on MLflow's model loading mechanism without adding specific security checks against malicious pickles.

- Missing Mitigations:
    - **Input Validation and Sanitization:** Implement checks to validate the model source and format before loading. For example:
        - Restrict model loading to only registered models within the Azure ML workspace from trusted sources.
        - Implement signature verification or checksum validation for models to ensure integrity and authenticity.
        - Consider using safer model serialization formats instead of pickle if feasible, although MLflow ecosystem heavily relies on pickle.
    - **Sandboxing or Isolation:** Execute the model loading and analysis in a sandboxed environment with restricted permissions to limit the impact of potential RCE. This could involve containerization with security profiles or using secure computing environments.
    - **User Awareness and Documentation:** Clearly document the risks associated with loading models from untrusted sources and advise users to only analyze models from sources they fully trust.

- Preconditions:
    1. The attacker needs to be able to register a malicious model in the Azure ML workspace or have access to a malicious model file that can be provided as input to the Responsible AI Dashboard components.
    2. A user must initiate a Responsible AI Dashboard analysis using this malicious model.

- Source Code Analysis:
    1. **File: `/code/src/responsibleai/rai_analyse/rai_component_utilities.py`**
    2. Function: `load_mlflow_model(workspace: Workspace, use_model_dependency: bool = False, use_separate_conda_env: bool = False, model_id: Optional[str] = None, model_path: Optional[str] = None) -> Any`
    3. Vulnerable code section:
    ```python
    model = mlflow.pyfunc.load_model(model_uri)._model_impl
    return model
    ```
    4. Visualization:
    ```mermaid
    graph LR
        A[User Input: Model ID or Path] --> B(rai_insights_constructor component);
        B --> C[rai_component_utilities.py: load_mlflow_model()];
        C --> D[mlflow.pyfunc.load_model(model_uri)];
        D --> E[Pickle Deserialization in MLflow];
        E --> F{Arbitrary Code Execution?};
    ```
    5. Step-by-step vulnerability trigger:
        a. The `rai_insights_constructor` component receives `model_info_path` or `model_input` from the pipeline YAML or SDK.
        b. Inside `rai_insights_constructor.py`, `load_mlflow_model` is called with the provided model information.
        c. `load_mlflow_model` in `rai_component_utilities.py` uses `mlflow.pyfunc.load_model(model_uri)`.
        d. MLflow's `load_model` internally deserializes the model, which, if it's a pickled format and maliciously crafted, can lead to arbitrary code execution.
        e. The loaded model is then used within the Responsible AI Dashboard components for analysis.

- Security Test Case:
    1. **Pre-requisite:** Attacker creates a malicious pickled scikit-learn model (`malicious_model.pkl`) containing code to execute upon deserialization (e.g., reverse shell, file access, etc.).
    2. **Model Registration (if applicable):** Attacker registers `malicious_model.pkl` as an MLflow model in the Azure ML workspace with a model ID (e.g., `malicious-rai-model:1`). Alternatively, the attacker can host the malicious model file accessible via a URI.
    3. **Dashboard Configuration:** User (attacker or victim user tricked by attacker) creates a Responsible AI Dashboard pipeline or SDK job.
    4. **Model Input Modification:** In the pipeline YAML or SDK script, the user specifies the `model_id` as `malicious-rai-model:1` (or provides the URI to `malicious_model.pkl` if direct path input is supported and exploitable).
    5. **Run Pipeline:** The user runs the Responsible AI Dashboard pipeline.
    6. **Exploit Execution:** When the `rai_insights_constructor` component executes, it calls `load_mlflow_model` to load the specified malicious model.
    7. **Verify RCE:** The malicious code embedded in `malicious_model.pkl` executes on the compute instance running the component. Verify successful RCE by checking for expected malicious activity (e.g., reverse shell connection, file modification, logs indicating code execution).