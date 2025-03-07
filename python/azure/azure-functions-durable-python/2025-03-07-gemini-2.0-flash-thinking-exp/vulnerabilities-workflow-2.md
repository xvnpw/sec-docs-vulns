## Combined Vulnerability List

### Vulnerability 1: Insecure Deserialization in Durable Functions Context

- **Vulnerability Name:** Insecure Deserialization in Durable Functions Context

- **Description:**
    1. An attacker can control the input JSON payload sent to a Durable Function (Orchestrator or Entity).
    2. The Durable Functions framework uses `json.loads` with a custom object hook (`_deserialize_custom_object`) in `DurableOrchestrationContext.from_json` and `DurableEntityContext.from_json` to deserialize the input JSON payload.
    3. If the input JSON payload contains specially crafted data, the `_deserialize_custom_object` hook might be exploited to perform insecure deserialization.
    4. This could lead to arbitrary code execution on the server if a vulnerable class is present in the environment and can be instantiated and manipulated through the deserialization process.
    5. This malicious JSON can be provided as input to an Azure Durable Function, either as orchestration input, activity input, or entity operation input.
    6. The `_deserialize_custom_object` function, intended for handling custom serialized objects, can be exploited to execute arbitrary code if the JSON payload is crafted to represent a malicious custom object.
    7. This leads to arbitrary code execution within the Azure Functions environment.

- **Impact:**
    - Remote Code Execution (RCE). An attacker could potentially execute arbitrary code on the Azure Functions host by crafting a malicious JSON payload, leading to full system compromise.
    - Arbitrary code execution in the serverless environment.
    - Potential data breach, data manipulation, or denial of service depending on the attacker's payload.
    - Full compromise of the Azure Function instance and potentially the underlying infrastructure.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    None. The code uses `json.loads` with a custom hook without any apparent sanitization or validation of the input payload against known safe schemas or types. The library relies on `_deserialize_custom_object` without any input sanitization or validation against malicious payloads.

- **Missing Mitigations:**
    - Input validation: Implement strict input validation and sanitization to ensure that only expected and safe data types are deserialized. Use schemas to define the expected structure and types of input data.
    - Safe deserialization practices: Consider using safer deserialization methods or libraries that are less susceptible to insecure deserialization vulnerabilities. Explore options to restrict the classes that can be deserialized or use allowlists. Consider using safer deserialization methods if custom object handling is not strictly necessary for all input types. If custom object handling is required, implement a secure deserialization mechanism that prevents arbitrary code execution, such as using a whitelist of allowed classes or sandboxing the deserialization process.
    - Sandboxing or isolation: Implement sandboxing or isolation techniques to limit the impact of potential RCE vulnerabilities.

- **Preconditions:**
    - The attacker needs to be able to send a crafted HTTP request or trigger an event that passes a JSON payload to a Durable Function.
    - A vulnerable Python class must be present in the Azure Functions environment that can be exploited through insecure deserialization using `_deserialize_custom_object`.
    - A user-developed Azure Durable Function application using this library must be deployed and accessible to attackers.
    - The application must accept user-controlled input that is processed by Durable Functions runtime and deserialized using vulnerable deserialization mechanism.

- **Source Code Analysis:**
    1. **Entry Points:** The `create` methods in `Orchestrator` (`azure/durable_functions/orchestrator.py`) and `Entity` (`azure/durable_functions/entity.py`) classes are entry points that call `DurableOrchestrationContext.from_json` and `DurableEntityContext.from_json` respectively. These `from_json` methods are responsible for deserializing the context from a JSON string.
    2. **`DurableOrchestrationContext.from_json` (`azure/durable_functions/models/DurableOrchestrationContext.py`):**
    ```python
    @classmethod
    def from_json(cls, json_string: str):
        ...
        json_dict = json.loads(json_string)
        return cls(**json_dict)
    ```
    This method directly uses `json.loads` to parse the input `json_string`.
    3. **`DurableEntityContext.from_json` (`azure/durable_functions/models/DurableEntityContext.py`):**
    ```python
    @classmethod
    def from_json(cls, json_str: str) -> Tuple['DurableEntityContext', List[Dict[str, Any]]]:
        ...
        json_dict = json.loads(json_str)
        ...
        serialized_state = json_dict["state"]
        if serialized_state is not None:
            json_dict["state"] = from_json_util(serialized_state)
        ...
        return cls(**json_dict), batch
    ```
    This method also uses `json.loads` and calls `from_json_util` for deserializing the state.
    4. **`from_json_util` (`azure/durable_functions/models/DurableEntityContext.py` and `azure/durable_functions/models/DurableOrchestrationContext.py`):**
    ```python
    def from_json_util(json_str: str) -> Any:
        """Load an arbitrary datatype from its JSON representation.
        ...
        """
        return json.loads(json_str, object_hook=_deserialize_custom_object)
    ```
    This utility function is used to deserialize arbitrary datatypes and it uses `json.loads` with `object_hook=_deserialize_custom_object`.
    5. **`_deserialize_custom_object` (`azure/functions/_durable_functions.py` - *not provided in project files but mentioned in code comments*):**
    This is the custom object hook that is used during deserialization. Without examining its implementation (as it's not provided), it's highly likely that it allows for instantiation of arbitrary classes based on the JSON input, which is the root cause of insecure deserialization vulnerabilities.
    6. **Vulnerable function:** `azure/durable_functions/models/DurableEntityContext.py` and `azure/durable_functions/models/TaskOrchestrationExecutor.py`
    7. **Code snippet in `TaskOrchestrationExecutor.py`:**
    ```python
    def set_task_value(self, event: HistoryEvent, is_success: bool, id_key: str):
        ...
        def parse_history_event(directive_result):
            ...
            if (event_type == HistoryEventType.SUB_ORCHESTRATION_INSTANCE_COMPLETED
                    and directive_result.Result is not None):
                return json.loads(directive_result.Result, object_hook=_deserialize_custom_object)
            if (event_type == HistoryEventType.TASK_COMPLETED
                    and directive_result.Result is not None):
                return json.loads(directive_result.Result, object_hook=_deserialize_custom_object)
            if (event_type == HistoryEventType.EVENT_RAISED
                    and directive_result.Input is not None):
                # TODO: Investigate why the payload is in "Input" instead of "Result"
                response = json.loads(directive_result.Input,
                                      object_hook=_deserialize_custom_object)
                return response
            return None
        ...
    ```
    This function uses `parse_history_event` which internally uses `json.loads` with `object_hook=_deserialize_custom_object` to process results of activities, sub-orchestrations, and external events, which could originate from external, potentially malicious sources.

    **Visualization:**

    ```mermaid
    graph LR
        A[External Request (JSON Payload) / External Attacker] --> B(Durable Function Endpoint / Malicious JSON Payload);
        B --> C(Orchestrator.create/Entity.create / Azure Durable Function App);
        C --> D(DurableOrchestrationContext.from_json/DurableEntityContext.from_json / Durable Functions Library);
        D --> E(json.loads with object_hook=_deserialize_custom_object / json.loads with _deserialize_custom_object);
        E --> F{Insecure Deserialization Vulnerability? / Arbitrary Code Execution};
        F -- Yes --> G[Remote Code Execution / Arbitrary Code Execution];
    ```

- **Security Test Case:**
    1. **Setup:** Deploy a Durable Functions application using the Python library to Azure Functions. Ensure that the application has an HTTP trigger orchestrator function or entity function that accepts input.
    2. Deploy a simple Azure Durable Function application that uses either Orchestrations or Entities from this library and exposes an HTTP endpoint to trigger the orchestration or interact with the entity. The function should accept user input as orchestration or entity input. For example, use the provided sample code and modify it to take HTTP request body as input.
    3. **Craft Malicious Payload:** Create a malicious JSON payload that exploits insecure deserialization. This payload will depend on the implementation of `_deserialize_custom_object` and the available vulnerable classes in the Azure Functions environment. A typical payload might attempt to instantiate a class that executes commands upon instantiation or during deserialization. Research Python deserialization vulnerabilities to create such a payload.
    4. **Send Malicious Request:** Send an HTTP POST request to the HTTP trigger endpoint of the Durable Function, including the crafted JSON payload as the request body. The orchestrator function name should be specified in the URL. Send an HTTP request to the deployed Azure Function endpoint with the malicious JSON payload as input. For Orchestration, this could be as input to the orchestrator trigger. For Entity, this could be as operation input.
    5. **Observe Behavior:** Monitor the Azure Functions logs and the behavior of the application. If the vulnerability is successfully exploited, you might observe code execution on the server, unexpected errors, or other signs of compromise. Monitor the Azure Function execution logs or the server environment to confirm arbitrary code execution. Successful exploitation might manifest as unexpected system behavior, access to sensitive resources, or execution of attacker-controlled commands.
    6. **Example Payload (Conceptual - needs adaptation based on `_deserialize_custom_object` and environment):**
    ```json
    {
        "__class__": "subprocess.Popen",
        "args": ["whoami"],
        "stdout": -1,
        "stderr": -1,
        "shell": true
    }
    ```
    ```json
    {
      "__class__": "subprocess.Popen",
      "args": ["touch /tmp/pwned"],
      "kwargs": {"shell": true}
    }
    ```
    This is a conceptual example and might not directly work without adjustments for `_deserialize_custom_object` and the target environment. A real exploit would require reverse engineering `_deserialize_custom_object` and identifying exploitable classes within the Azure Functions runtime environment. This is a simplified example. A real exploit might need more sophisticated payloads depending on the exact deserialization logic and environment constraints.
    7. **Expected Outcome:** Successful exploitation would result in remote code execution. If the test is designed to be less intrusive, it should at least demonstrate the ability to deserialize unexpected objects or trigger errors related to deserialization. If the system is patched or mitigations are in place, the test should not result in code execution or unexpected behavior, and input validation or safe deserialization mechanisms should be observed in the code.

### Vulnerability 2: Path Traversal in E2_CopyFileToBlob Activity Function

- **Vulnerability Name:** Path Traversal in File Copy Activity

- **Description:**
    1. An attacker can control the `root_directory` input to the `E2_BackupSiteContent` orchestrator function.
    2. This `root_directory` input is passed to the `E2_GetFileList` activity function.
    3. The `E2_GetFileList` activity function uses `os.walk(rootDirectory)` to traverse the file system based on the user-provided `rootDirectory`.
    4. It then filters paths to only include those containing "E2_", but it still uses `os.path.join(path, name)` to construct file paths without sanitizing or validating the `path` component obtained from `os.walk`.
    5. These unfiltered file paths are then passed to the `E2_CopyFileToBlob` activity function.
    6. The `E2_CopyFileToBlob` activity function uses `pathlib.Path(filePath).parts[-2:]` to extract the last two path components and construct the `blob_name`.
    7. By crafting a malicious `root_directory` input (e.g., "../../../sensitive_data"), an attacker could potentially cause `os.walk` to traverse directories outside of the intended sample code directory.
    8. Due to insufficient validation in `E2_GetFileList` and `E2_CopyFileToBlob`, the attacker could manipulate the `blob_name` to write arbitrary files from the file system (accessible by the function app) to the "backups" Azure Blob Storage container. This is because the `parent_dir` and `fname` are directly used to construct `blob_name` without further sanitization.

- **Impact:**
    - **High:** An attacker could read sensitive files from the function app's accessible file system and upload them to a publicly accessible Azure Blob Storage container ("backups"). This constitutes a data exfiltration vulnerability.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - The `E2_GetFileList` activity function filters paths to include only those containing "E2_", which limits traversal to some extent, but it is insufficient to prevent path traversal within directories containing "E2_" or directories nested under them, and it does not sanitize the path components.

- **Missing Mitigations:**
    - Input validation and sanitization of the `root_directory` in `E2_BackupSiteContent` orchestrator and `E2_GetFileList` activity functions to prevent path traversal.
    - Validation of `filePath` in `E2_CopyFileToBlob` activity function to ensure it is within expected boundaries and sanitize `parent_dir` and `fname` before constructing `blob_name`.

- **Preconditions:**
    - The application must be deployed with the vulnerable sample code (`samples-v2/fan_in_fan_out`).
    - An attacker must be able to trigger the `HttpStart` HTTP endpoint of the Durable Function application and control the request body to provide a malicious `root_directory` input.

- **Source Code Analysis:**
    ```python
    # File: /code/samples-v2/fan_in_fan_out/function_app.py

    @myApp.activity_trigger(input_name="rootDirectory")
    def E2_GetFileList(rootDirectory):
        all_file_paths = []
        # We walk the file system
        for path, _, files in os.walk(rootDirectory): # [!] Potential path traversal starting point, rootDirectory is user-controlled
            # We copy the code for activities and orchestrators
            if "E2_" in path: # [!] Incomplete mitigation, only filters paths containing "E2_"
                # For each file, we add their full-path to the list
                for name in files:
                    if name == "__init__.py" or name == "function.json":
                        file_path = os.path.join(path, name) # [!] Path concatenation without sanitization
                        all_file_paths.append(file_path)

        return all_file_paths

    @myApp.activity_trigger(input_name="filePath")
    def E2_CopyFileToBlob(filePath):
        ...
        parent_dir, fname = pathlib.Path(filePath).parts[-2:] # [!] Extracts path components
        blob_name = parent_dir + "_" + fname # [!] Constructs blob name unsafely using path components
        blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)

        # Upload the created file
        with open(filePath, "rb") as data: # [!] Opens file from potentially traversed path
            blob_client.upload_blob(data)
        ...
    ```
    **Visualization:**

    ```mermaid
    graph LR
        A[HttpStart (Orchestrator Trigger)] --> B(E2_BackupSiteContent Orchestrator);
        B --> C(E2_GetFileList Activity);
        C --> D{os.walk(rootDirectory)};
        D --> E{Path Filter "E2_"};
        E --> F(File Path List);
        F --> G{Loop for each file};
        G --> H(E2_CopyFileToBlob Activity);
        H --> I{pathlib.Path(filePath).parts[-2:]};
        I --> J{blob_name construction};
        J --> K{blob_client.upload_blob(data)};
    ```

- **Security Test Case:**
    1. Deploy the `samples-v2/fan_in_fan_out` sample to Azure Functions.
    2. Identify the HTTP endpoint URL for the `HttpStart` function (e.g., `https://<your-function-app>.azurewebsites.net/api/orchestrators/{functionName}`).
    3. Prepare a malicious JSON payload for the request body, setting `root_directory` to traverse upwards, for example: `{"root_directory": "../../../../../home/site/wwwroot"}`.
    4. Send a POST request to the HTTP endpoint with the crafted payload, replacing `{functionName}` with `E2_BackupSiteContent`. Example using curl:
       ```bash
       curl -X POST -H "Content-Type: application/json" -d '{"root_directory": "../../../../../home/site/wwwroot"}' https://<your-function-app>.azurewebsites.net/api/orchestrators/E2_BackupSiteContent
       ```
    5. Check the Azure Blob Storage container named "backups". If the vulnerability is exploitable, you should find blobs with names derived from files located outside the intended sample directory, potentially including files from `/home/site/wwwroot`. For instance, you might find a blob named "site_secrets___init__.py" if such a file exists and is accessible.