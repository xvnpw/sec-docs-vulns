## Combined Vulnerability List

### Vulnerability Name: Insecure Deserialization in RAI Insights Dashboard Constructor

- **Description:**
    1. An attacker can craft a malicious MLflow model.
    2. The attacker registers this model in AzureML Model Registry.
    3. The attacker then triggers a Responsible AI Dashboard pipeline job, providing the malicious model's ID as `model_id` input to the `rai_insights_constructor` component.
    4. The `rai_insights_constructor` component uses `mlflow.pyfunc.load_model` to load the registered model.
    5. If the malicious model contains serialized malicious payloads, these payloads will be deserialized during model loading.
    6. This deserialization can lead to arbitrary code execution on the compute instance running the RAI dashboard pipeline.

- **Impact:**
    - Critical: Arbitrary code execution on the AzureML compute instance. This could allow the attacker to steal credentials, access sensitive data, or further compromise the AzureML workspace and associated resources.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - None: The project relies on MLflow's model loading mechanism without additional security measures.

- **Missing Mitigations:**
    - Input validation: The `rai_insights_constructor` component should validate the model ID and potentially the model source before attempting to load it, to ensure it comes from a trusted source.
    - Sandboxing or isolation: The model loading and RAI computation process should be sandboxed or isolated to limit the impact of potential code execution vulnerabilities. Using secure deserialization practices or avoiding deserialization of untrusted data altogether would also mitigate this.

- **Preconditions:**
    - The attacker needs to be able to register a malicious model in the AzureML Model Registry. This might be possible if the attacker has contributor access to the workspace or if there are vulnerabilities in the model registration process itself (though not directly part of this project's code).
    - The user needs to trigger a Responsible AI Dashboard pipeline job using the attacker-controlled model ID.

- **Source Code Analysis:**
    - File: `/code/src/responsibleai/rai_analyse/create_rai_insights.py`
    - Step 1: The `create_rai_insights.py` script is the entry point for the `rai_insights_constructor` component.
    - Step 2: The script parses arguments, including `model_info_path`, `model_input`, and `model_info`. It prioritizes `model_info_path` and uses `fetch_model_id` and `load_mlflow_model` to load the model.
    - Step 3: `load_mlflow_model` function (defined in `/code/src/responsibleai/rai_analyse/rai_component_utilities.py`) uses `mlflow.pyfunc.load_model(model_uri)` to load the model.
    - Step 4: `mlflow.pyfunc.load_model` in MLflow is known to be vulnerable to insecure deserialization if the loaded model contains malicious serialized objects.
    - Visualization:
        ```
        User Input (Malicious Model ID) --> rai_insights_constructor component --> create_rai_insights.py --> load_mlflow_model --> mlflow.pyfunc.load_model (Vulnerable Deserialization) --> Code Execution
        ```

- **Security Test Case:**
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

### Vulnerability Name: Data Input Manipulation - Lack of Input Validation

- **Description:**
    1. An attacker crafts a malicious dataset designed to skew the analysis results of the Responsible AI dashboard. This could involve manipulating feature distributions, introducing deliberate biases, or altering target variable values.
    2. The attacker provides this malicious dataset as input to the Responsible AI dashboard, either through the Python SDK, CLI, or Azure Machine Learning studio UI.
    3. The Responsible AI dashboard processes this malicious dataset without proper input validation or sanitization.
    4. As a result, the dashboard generates skewed and misleading insights into the model's fairness, explainability, and error analysis, reflecting the manipulations introduced in the malicious dataset.
    5. The user, relying on these skewed insights, may be misled into believing their model is robust and unbiased, and proceed to deploy a flawed or biased model into production.

- **Impact:**
    - High: Skewed and misleading insights in the Responsible AI dashboard.
    - Users may be unaware of biases or flaws in their machine learning models.
    - Potential deployment of flawed or biased models into production, leading to unfair or unethical outcomes.
    - Reputational damage and legal liabilities for the user or organization deploying the flawed model.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - None. The project files do not contain any input validation or sanitization mechanisms for user-provided datasets.

- **Missing Mitigations:**
    - Implement robust input validation and sanitization for all datasets provided to the Responsible AI dashboard.
        - Validate data types and formats.
        - Check for data integrity and consistency.
        - Detect and flag potential data biases or anomalies.
        - Consider providing warnings to users about potential data quality issues.

- **Preconditions:**
    - The attacker must have the ability to provide a dataset as input to the Responsible AI dashboard. This is generally the case for users interacting with the dashboard through the SDK, CLI, or UI.

- **Source Code Analysis:**
    - File: `/code/src/responsibleai/rai_analyse/create_rai_insights.py`
        - This script is the entry point for creating RAI Insights. It uses the `load_dataset` function to load both training and test datasets provided as input.
        - ```python
          train_df = load_dataset(args.train_dataset)
          test_df = load_dataset(args.test_dataset)
          ```
    - File: `/code/src/responsibleai/rai_analyse/rai_component_utilities.py`
        - The `load_dataset` function attempts to load the dataset from a given path, supporting both MLTable and Parquet formats.
        - ```python
          def load_dataset(dataset_path: str) -> pd.DataFrame:
              _logger.info(f"Attempting to load: {dataset_path}")
              exceptions = []
              isLoadSuccessful = False

              try:
                  df = load_mltable(dataset_path)
                  isLoadSuccessful = True
              except Exception as e:
                  new_e = UserConfigError(...)
                  exceptions.append(new_e)

              if not isLoadSuccessful:
                  try:
                      df = load_parquet(dataset_path)
                      isLoadSuccessful = True
                  except Exception as e:
                      new_e = UserConfigError(...)
                      exceptions.append(new_e)

              if not isLoadSuccessful:
                  raise UserConfigError(...)
              return df
          ```
        - The `load_dataset` function focuses on loading the data in different formats but lacks any data validation or sanitization steps after the data is loaded into a Pandas DataFrame.
        - The loaded DataFrame is directly used for RAI insights computation without any checks for data quality, biases, or malicious content.
    - Visualization:
        ```mermaid
        graph LR
        A[create_rai_insights.py] --> B(load_dataset);
        B --> C[rai_component_utilities.py];
        C --> D{mltable.load / pd.read_parquet};
        D --> E[Pandas DataFrame];
        E --> F[RAI Insights Computation];
        style D fill:#f9f,stroke:#333,stroke-width:2px
        style E fill:#ccf,stroke:#333,stroke-width:2px
        style F fill:#ccf,stroke:#333,stroke-width:2px
        ```

- **Security Test Case:**
    1. **Prerequisites:**
        - Have an Azure Machine Learning workspace set up and the Responsible AI dashboard components deployed.
        - Train and register a classification model (e.g., using the 'adult' dataset and 'train_logistic_regression_for_rai' component).
    2. **Step 1: Prepare a Benign Dataset:**
        - Use a standard, benign test dataset (e.g., a copy of the 'adult_test' dataset).
    3. **Step 2: Prepare a Malicious Dataset:**
        - Create a copy of the benign test dataset.
        - Introduce a significant skew in a numerical feature, for example, the 'Age' column. Replace 90% of 'Age' values with '1'.
        - Introduce bias in a categorical feature, for example, in the 'Race' column, overwhelmingly favor one race category.
    4. **Step 3: Create RAI Dashboard using SDK with Benign Dataset:**
        - Use the Python SDK to create a Responsible AI dashboard for the registered model, using the *benign* test dataset.
        - Run the pipeline to generate the dashboard.
        - Note the insights generated for the benign dataset as a baseline.
    5. **Step 4: Create RAI Dashboard using SDK with Malicious Dataset:**
        - Use the Python SDK to create *another* Responsible AI dashboard for the *same* registered model, but this time using the *malicious* test dataset.
        - Run the pipeline.
    6. **Step 5: Compare Dashboards in Azure ML Studio:**
        - Access both dashboards in the Azure ML studio UI (under the 'Models' section, 'Responsible AI dashboard (preview)' tab).
        - Compare the insights generated by both dashboards, particularly focusing on:
            - **Error Analysis:** Check if the error tree and heatmap reflect the data manipulation in the malicious dataset. Are error cohorts skewed towards the manipulated features?
            - **Data Explorer:** Examine the feature distributions for the manipulated features in both dashboards. Does the malicious dataset show the intended skewed distribution?
            - **Model Statistics:** Compare the overall model performance metrics. Are they significantly different between the benign and malicious dataset dashboards?
        - **Expected Result:**
            - The dashboard generated with the malicious dataset should display skewed and misleading insights compared to the baseline dashboard.
            - Error analysis should be influenced by the manipulated features, potentially highlighting spurious error cohorts.
            - Data Explorer should clearly visualize the skewed distributions of the manipulated features.
            - Model statistics might show unexpected changes due to the altered dataset, but these changes might not be correctly attributed to data manipulation without proper validation.
        - **Success Condition:** If the dashboard with the malicious dataset presents demonstrably skewed and misleading insights, the vulnerability is confirmed. This indicates a lack of input validation, allowing attackers to manipulate the dashboard's analysis through crafted datasets.

### Vulnerability Name: Dataframe Type Confusion Vulnerability in Dataset Loading

- **Description:**
    1. An attacker crafts a malicious Parquet file.
    2. This Parquet file is designed to exploit type confusion vulnerabilities when loaded by pandas. For example, a column intended to be numerical could be crafted to be interpreted as a string or categorical type under certain conditions.
    3. The user uploads this crafted Parquet file to Azure ML workspace as a dataset or provides a link to it.
    4. The user then creates a Responsible AI dashboard analysis job, pointing to this malicious dataset as input (either train or test dataset).
    5. When the `load_dataset` function in `/code/src/responsibleai/rai_analyse/rai_component_utilities.py` loads this Parquet file using pandas, the type confusion occurs.
    6. This type confusion leads to incorrect data processing within the Responsible AI components. For example, numerical features may be treated as categorical, or vice versa.
    7. Consequently, the Responsible AI dashboard generates misleading insights based on the misinterpreted data, without throwing explicit errors.
    8. The user, relying on these misleading insights, may unknowingly deploy a flawed model, believing it to be properly analyzed by the dashboard.

- **Impact:**
    - High: Users are presented with inaccurate or misleading Responsible AI insights.
    - Users may develop a false sense of security about their ML models, believing them to be fair, explainable, and error-free based on the dashboard's analysis.
    - This can lead to the deployment of flawed or biased models into production, potentially causing harm or unfair outcomes in real-world applications.
    - The credibility and trustworthiness of the Responsible AI Dashboard are undermined.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - None identified in the provided code files that specifically prevent dataframe type confusion during dataset loading.

- **Missing Mitigations:**
    - Strict input validation and sanitization: Implement rigorous checks on the data types and formats of the loaded datasets, especially Parquet files. This should include verifying that column types match expected schemas and handling potential type ambiguities or inconsistencies.
    - Schema enforcement: Define and enforce a strict schema for input datasets. Ensure that the data loaded conforms to this schema, raising errors if discrepancies are found.
    - Type casting and verification: Explicitly cast dataframe columns to the expected types after loading and verify that the casting was successful and data integrity is maintained.
    - Security warnings: Display warnings to users about the risks of using untrusted or externally sourced datasets and models, encouraging them to use datasets from trusted sources.

- **Preconditions:**
    - The attacker needs to be able to craft a malicious Parquet file.
    - The user must use this malicious Parquet file as input to the Responsible AI Dashboard analysis job.
    - The Azure ML workspace needs to be set up and the Responsible AI Dashboard components registered.

- **Source Code Analysis:**
    - File: `/code/src/responsibleai/rai_analyse/rai_component_utilities.py`
    - Function: `load_parquet(parquet_path: str) -> pd.DataFrame`
    - Code Snippet:
    ```python
    def load_parquet(parquet_path: str) -> pd.DataFrame:
        _logger.info(f"Attempting to load {parquet_path} as parquet dataset")
        try:
            df = pd.read_parquet(parquet_path) # Vulnerable line
        except Exception as e:
            _logger.info(f"Failed to load {parquet_path} as MLTable. ")
            raise e
        return df
    ```
    - Analysis:
        - The `load_parquet` function directly uses `pd.read_parquet(parquet_path)` to load Parquet files.
        - `pd.read_parquet` relies on pandas' Parquet parsing capabilities, which, while robust, might be susceptible to type confusion if a malicious file is crafted to exploit pandas' type inference or handling of complex Parquet structures.
        - There is no explicit schema validation or type checking after loading the Parquet file.
        - If a malicious Parquet file is crafted to cause pandas to misinterpret column types, this could lead to downstream components processing data with incorrect assumptions about its type.
    - Visualization:
        ```mermaid
        graph LR
            A[User Uploads Malicious Parquet File] --> B(load_parquet Function);
            B --> C{pandas.read_parquet};
            C --> D[Type Confusion Vulnerability];
            D --> E(Incorrect Dataframe);
            E --> F[RAI Components];
            F --> G[Misleading Insights];
            G --> H[User Deploys Flawed Model];
        ```

- **Security Test Case:**
    1. **Setup:**
        - Create an Azure ML Workspace and register Responsible AI components.
        - Prepare a benign dataset (e.g., Boston Housing dataset).
        - Train and register a simple model (e.g., linear regression on Boston Housing dataset).
    2. **Craft Malicious Parquet File:**
        - Create a Parquet file based on the Boston Housing dataset schema.
        - In the malicious Parquet file, modify the metadata or data encoding of a numerical column (e.g., 'RM' - average number of rooms per dwelling) to potentially cause pandas to misinterpret its type as categorical or string when loaded. This might involve manipulating the Parquet schema metadata or encoding specific values in a way that triggers pandas type inference issues.
    3. **Upload Malicious Dataset:**
        - Upload the crafted malicious Parquet file to the Azure ML workspace as a dataset (e.g., `boston_malicious_pq`).
    4. **Run RAI Pipeline with Malicious Dataset:**
        - Create a pipeline YAML file (similar to `test/rai/pipeline_boston_analyse.yaml`), but modify it to use the malicious dataset (`boston_malicious_pq`) instead of the benign `boston_test_pq` for the `test_dataset` input of the `rai_insights_constructor` component. Ensure the pipeline includes Error Analysis or other components that would be sensitive to data type errors.
    5. **Submit and Monitor Pipeline:**
        - Submit the modified pipeline job to Azure ML.
        - Monitor the pipeline run and its outputs in Azure ML studio.
    6. **Analyze Results:**
        - Check the generated Responsible AI dashboard in Azure ML studio.
        - Analyze the Error Analysis results, explanations, or other insights generated by the dashboard.
        - **Expected Outcome (Vulnerability Valid):**
            - Observe that the dashboard generates misleading insights, for example, Error Analysis might show unexpected error distributions or feature importance values for the 'RM' feature due to its misinterpreted data type.
            - Verify that no explicit errors or crashes occurred during the pipeline execution, indicating silent data corruption and misleading insight generation.
        - **Expected Outcome (Mitigation Present/Vulnerability Invalid):**
            - Observe that the pipeline job fails with a data validation error, or the dashboard displays warnings about data type inconsistencies.
            - Or, if mitigations are effective, the dashboard generates insights based on the *correct* interpretation of data, even with the malicious Parquet file, indicating that type confusion was prevented.