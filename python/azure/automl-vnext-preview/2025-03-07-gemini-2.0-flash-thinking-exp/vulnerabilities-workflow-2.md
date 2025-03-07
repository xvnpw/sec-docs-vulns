## Combined Vulnerability List

### 1. Vulnerability Name: Insecure YAML Parsing in AutoML Job Configuration

- **Description:**
    1. An attacker crafts a malicious YAML configuration file for an AutoML job.
    2. This YAML file contains a payload that exploits insecure YAML parsing, potentially using YAML tags to execute arbitrary Python code or system commands during deserialization.
    3. The attacker submits this crafted YAML file through the AutoML CLI or REST API to create an AutoML job.
    4. The AutoML CLI or REST API, due to insecure YAML parsing practices, processes the malicious YAML file without proper sanitization or safe loading.
    5. During the YAML parsing process, the malicious payload embedded in the YAML configuration is executed on the server or compute environment handling the AutoML job.
    6. This execution can lead to arbitrary command execution, allowing the attacker to run commands on the AutoML infrastructure.

- **Impact:**
    - Arbitrary command execution on the AutoML compute environment.
    - Potential for unauthorized access to sensitive data and resources within the Azure environment.
    - Possible compromise of the model training process and the integrity of trained models.
    - Risk of lateral movement to other Azure services or resources accessible from the compromised environment.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - Based on the provided project files, there are no specific mitigations implemented within these files to address insecure YAML parsing. The files are primarily focused on component definitions, test pipelines, and example configurations, not the core CLI/API parsing logic.

- **Missing Mitigations:**
    - **Secure YAML Loading:** Implement secure YAML parsing practices in the AutoML CLI and REST API. Specifically, use safe YAML loading functions (e.g., `yaml.safe_load` in Python's `PyYAML` library or similar in other languages) that prevent the execution of arbitrary code during deserialization of YAML files.
    - **Input Validation and Sanitization:** Implement strict schema validation for all YAML configuration files to ensure they conform to expected structures and data types. Sanitize all input parameters from YAML files to prevent injection attacks.
    - **Principle of Least Privilege:** Ensure that the AutoML jobs and related processes run with the minimum necessary privileges. This limits the potential impact if arbitrary command execution is achieved.

- **Preconditions:**
    - The attacker must have the ability to interact with the AutoML CLI or REST API to submit YAML configuration files for AutoML job creation.
    - The AutoML CLI or REST API must be vulnerable to insecure YAML parsing, allowing for code or command injection through malicious YAML payloads.

- **Source Code Analysis:**
    - Unfortunately, the provided project files do not include the source code for the AutoML CLI or REST API where YAML parsing would be implemented. Therefore, a detailed source code analysis to pinpoint the exact location of the vulnerability within these files is not possible.
    - To perform a source code analysis, access to the codebase of the AutoML CLI or REST API is required to examine how YAML configuration files are parsed and processed. This analysis should focus on identifying the YAML parsing library used and whether safe loading practices are employed.

- **Security Test Case:**
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

### 2. Vulnerability Name: Insecure Direct Object Reference in RAI Insights Download

- **Description:**
    1. An attacker with valid Azure credentials for an Azure Machine Learning workspace might be able to download Responsible AI (RAI) insights dashboards associated with other users' AutoML runs within the same workspace, without proper authorization.
    2. Step-by-step trigger:
        - An attacker obtains valid Azure credentials that allow them to interact with an Azure Machine Learning workspace using the Azure ML SDK or CLI. This could be through compromised credentials or legitimate access to a workspace.
        - The attacker identifies or guesses a valid `rai_insight_id` (Run ID of a 'gather' type RAI insights run) that belongs to another user's AutoML experiment in the same workspace. Run IDs might be somewhat predictable or discoverable through workspace activity logs or naming conventions if not properly secured.
        - The attacker uses the `azure_ml_rai` Python package, specifically the `download_rai_insights` or `download_rai_insights_ux` functions, providing the targeted `rai_insight_id` and a local path to save the downloaded dashboard.
        - The `download_rai_insights` function, using the attacker's Azure credentials, attempts to download the RAI insights artifacts from Azure Blob Storage associated with the provided `rai_insight_id`.
        - If Azure Machine Learning's access control does not properly restrict download access to RAI insights artifacts based on user-specific permissions at the run level (and only relies on workspace-level access), the attacker will successfully download the RAI insights dashboard, even if they are not authorized to access the original AutoML run or its results.

- **Impact:**
    - Unauthorized access to sensitive information contained within RAI insights dashboards. These dashboards can include model explanations, error analysis, causal analysis, and counterfactual analysis, potentially revealing business-sensitive data, model vulnerabilities, or insights into the data used for model training.
    - Depending on the nature of the data and insights exposed, this could lead to privacy violations, competitive disadvantage, or further exploitation of identified vulnerabilities in the machine learning models or processes.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - None evident in the provided project files. The vulnerability relies on the underlying Azure Machine Learning and MLflow authorization mechanisms. The provided code itself does not implement any explicit access control checks before downloading artifacts based on `rai_insight_id`.

- **Missing Mitigations:**
    - **Run-level Access Control Enforcement:** Azure Machine Learning should enforce granular access control at the Run level. When a user attempts to download artifacts associated with a specific Run ID (like `rai_insight_id`), the system should verify if the user has explicit permissions to access that particular Run and its outputs, beyond just having workspace-level access.
    - **Input Validation and Sanitization:** While not directly mitigating the authorization issue, input validation on `rai_insight_id` could reduce the attack surface by preventing attempts to use clearly invalid or malformed Run IDs. However, this is not a strong security measure and should not be relied upon as the primary mitigation.
    - **Auditing and Logging:** Implement detailed logging of RAI insights download attempts, including the user, the `rai_insight_id` requested, and the outcome (success or failure). This would aid in detecting and investigating potential unauthorized access attempts.

- **Preconditions:**
    - Attacker possesses valid Azure credentials with access to an Azure Machine Learning workspace.
    - The target Azure Machine Learning workspace contains RAI insights dashboards generated by other users.
    - The attacker is able to identify or guess valid `rai_insight_id` values of 'gather' type RAI insights runs from other users within the same workspace.

- **Source Code Analysis:**
    - File: `/code/src/azure-ml-rai/azure_ml_rai/_download_rai_insights.py`
    ```python
    def download_rai_insights(ml_client: MLClient, rai_insight_id: str, path: str) -> None:
        v1_ws = _get_v1_workspace_client(ml_client)

        mlflow.set_tracking_uri(v1_ws.get_mlflow_tracking_uri())

        mlflow_client = MlflowClient()

        output_directory = Path(path)
        output_directory.mkdir(parents=True, exist_ok=False)

        _download_port_files(
            mlflow_client,
            rai_insight_id,
            OutputPortNames.RAI_INSIGHTS_GATHER_RAIINSIGHTS_PORT,
            output_directory,
            ml_client._credential,
        )
    ```
    - The `download_rai_insights` function directly uses the provided `rai_insight_id` to initiate the download process via `_download_port_files`.
    - File: `/code/src/azure-ml-rai/azure_ml_rai/_download_rai_insights.py`
    ```python
    def _download_port_files(
        mlflow_client: MlflowClient,
        run_id: str, # This is rai_insight_id passed from download_rai_insights
        port_name: str,
        target_directory: Path,
        credential: ChainedTokenCredential, # User's Azure credential
    ) -> None:
        port_info = _get_output_port_info(mlflow_client, run_id, port_name) # Using run_id to get port info
        # ... (rest of the function to download using AzureBlobArtifactRepository and credential) ...
    ```
    - The `_download_port_files` function takes `run_id` (which is `rai_insight_id`) and `credential` as input. It retrieves port information using `mlflow_client.download_artifacts(run_id, port_name, temp_dir)` and then uses `AzureBlobArtifactRepository` with the provided `credential` to download artifacts.
    - **Vulnerability Point:** There is no explicit check within these functions to validate if the user associated with `ml_client._credential` is authorized to access the RAI insights dashboard corresponding to the `rai_insight_id`. The functions rely on the underlying authorization mechanisms of MLflow and Azure Blob Storage, which might only enforce workspace-level access instead of run-level access control for downloads.

- **Security Test Case:**
    1. **Setup:**
        - User A and User B both have access to the same Azure ML workspace.
        - User A creates and runs an AutoML pipeline that generates RAI insights. Let's say the 'gather' run ID for User A's RAI insights is `user_a_rai_insight_id`.
        - User B only has workspace-level access and is not explicitly granted access to User A's runs.
    2. **Action:**
        - User B, using their own Azure credentials and the `azure_ml_rai` package, executes the following Python code, replacing `<user_a_rai_insight_id>` with the actual Run ID obtained from User A's run and `<local_download_path>` with a local directory path:
        ```python
        from azure.identity import DefaultAzureCredential
        from azure.ml import MLClient
        from azure_ml_rai import download_rai_insights

        credential = DefaultAzureCredential()
        ml_client_b = MLClient(
            credential=credential,
            subscription_id="<your_subscription_id>", # User B's subscription if different, or same as User A's workspace subscription
            resource_group_name="<workspace_resource_group>",
            workspace_name="<workspace_name>",
        )

        rai_insight_id_to_download = "<user_a_rai_insight_id>" # Run ID of User A's RAI insights run
        download_path = "<local_download_path>"

        download_rai_insights(ml_client=ml_client_b, rai_insight_id=rai_insight_id_to_download, path=download_path)

        print(f"RAI Insights downloaded to: {download_path}")
        ```
    3. **Expected Result:**
        - **Vulnerable Case:** If the system is vulnerable, User B will successfully download the RAI insights dashboard from User A's run to the `<local_download_path>`, even though User B is not explicitly authorized to access User A's run.
        - **Secure Case:** If the system is secure, User B's `download_rai_insights` call will fail with an authorization error, indicating that User B does not have permission to download artifacts for `rai_insight_id_to_download`.

This test case demonstrates how an attacker (User B) could potentially exploit the Insecure Direct Object Reference vulnerability to gain unauthorized access to RAI insights dashboards created by another user (User A) within the same Azure ML workspace.