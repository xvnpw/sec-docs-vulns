* Vulnerability name: Deserialization vulnerability in custom object handling

* Description:
    1. An attacker crafts a malicious JSON payload containing instructions to instantiate and execute arbitrary Python code during deserialization.
    2. This malicious JSON is provided as input to an Azure Durable Function, either as orchestration input, activity input, or entity operation input.
    3. The Durable Functions Python library uses `json.loads` with `object_hook=_deserialize_custom_object` to deserialize this input.
    4. The `_deserialize_custom_object` function, intended for handling custom serialized objects, can be exploited to execute arbitrary code if the JSON payload is crafted to represent a malicious custom object.
    5. This leads to arbitrary code execution within the Azure Functions environment.

* Impact:
    - Arbitrary code execution in the serverless environment.
    - Potential data breach, data manipulation, or denial of service depending on the attacker's payload.
    - Full compromise of the Azure Function instance and potentially the underlying infrastructure.

* Vulnerability rank: Critical

* Currently implemented mitigations:
    - None identified in the provided code. The library relies on `_deserialize_custom_object` without any input sanitization or validation against malicious payloads.

* Missing mitigations:
    - Input validation and sanitization for all user-provided inputs that are deserialized using `json.loads` with `object_hook=_deserialize_custom_object`.
    - Consider using safer deserialization methods if custom object handling is not strictly necessary for all input types.
    - If custom object handling is required, implement a secure deserialization mechanism that prevents arbitrary code execution, such as using a whitelist of allowed classes or sandboxing the deserialization process.

* Preconditions:
    - A user-developed Azure Durable Function application using this library must be deployed and accessible to attackers.
    - The application must accept user-controlled input that is processed by Durable Functions runtime and deserialized using vulnerable deserialization mechanism.

* Source code analysis:
    1. Vulnerable function: `azure/durable_functions/models/DurableEntityContext.py` and `azure/durable_functions/models/TaskOrchestrationExecutor.py`
    2. Code snippet in `DurableEntityContext.py`:
    ```python
    def from_json_util(json_str: str) -> Any:
        """Load an arbitrary datatype from its JSON representation.
        ...
        """
        return json.loads(json_str, object_hook=_deserialize_custom_object)
    ```
    This function is used in `DurableEntityContext.from_json` to deserialize the entity state and operation inputs, which can be influenced by external input.
    3. Code snippet in `TaskOrchestrationExecutor.py`:
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
    4. Visualization:

    ```mermaid
    graph LR
        A[External Attacker] --> B(Malicious JSON Payload);
        B --> C(Azure Durable Function App);
        C --> D(Durable Functions Library);
        D --> E(json.loads with _deserialize_custom_object);
        E --> F{Arbitrary Code Execution};
    ```

* Security test case:
    1. Deploy a simple Azure Durable Function application that uses either Orchestrations or Entities from this library and exposes an HTTP endpoint to trigger the orchestration or interact with the entity. The function should accept user input as orchestration or entity input. For example, use the provided sample code and modify it to take HTTP request body as input.
    2. Craft a malicious JSON payload that exploits the deserialization vulnerability. This payload would typically contain a specially crafted JSON string that, when deserialized using `_deserialize_custom_object`, triggers arbitrary code execution. Research Python deserialization vulnerabilities to create such a payload.
    3. Send an HTTP request to the deployed Azure Function endpoint with the malicious JSON payload as input. For Orchestration, this could be as input to the orchestrator trigger. For Entity, this could be as operation input.
    4. Monitor the Azure Function execution logs or the server environment to confirm arbitrary code execution. Successful exploitation might manifest as unexpected system behavior, access to sensitive resources, or execution of attacker-controlled commands.
    5. Example malicious payload structure (proof-of-concept, might need adjustments):
    ```json
    {
      "__class__": "subprocess.Popen",
      "args": ["touch /tmp/pwned"],
      "kwargs": {"shell": true}
    }
    ```
    This is a simplified example. A real exploit might need more sophisticated payloads depending on the exact deserialization logic and environment constraints.