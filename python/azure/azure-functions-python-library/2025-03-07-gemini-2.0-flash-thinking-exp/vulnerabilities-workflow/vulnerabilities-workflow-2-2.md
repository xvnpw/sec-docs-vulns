### 1. Code Injection via Deserialization of Custom Objects in Activity Functions

- **Description:**
    1. An attacker crafts a malicious JSON payload designed to be processed by an Azure Function using the Activity Trigger.
    2. This payload includes specially crafted keys (`__class__`, `__module__`, `__data__`) that are intended to be deserialized by the `_deserialize_custom_object` function within the `azure-functions-durable` extension.
    3. When the Azure Function runtime deserializes the input data for the Activity Function using `json.loads` with the `object_hook=_durable_functions._deserialize_custom_object`, the malicious payload triggers dynamic module importing and object instantiation.
    4. By controlling the `__module__` and `__class__` values in the JSON, the attacker can attempt to load and execute arbitrary Python code within the Azure Functions environment.
    5. If successful, this can lead to arbitrary code execution on the Azure Functions host.

- **Impact:**
    - **Critical:** Successful exploitation allows for arbitrary code execution within the Azure Functions environment. This could lead to full compromise of the function app, including data exfiltration, resource manipulation, and potentially broader access to the Azure environment depending on the function app's permissions and network configuration.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - The project uses `pip-audit` in CI pipelines (official-build.yml, build.yml) to scan for dependency vulnerabilities. This can help identify known vulnerable dependencies but does not protect against code injection vulnerabilities within the library's code or logic.
    - Security guidelines are provided in `SECURITY.md` for reporting vulnerabilities through MSRC, but no specific mitigations for code injection are implemented in the code itself.

- **Missing Mitigations:**
    - **Input Validation and Sanitization:** The `_deserialize_custom_object` function should validate the `__module__` and `__class__` values against a whitelist of allowed modules and classes. This would prevent the dynamic loading of arbitrary code.
    - **Secure Deserialization Practices:** Consider alternatives to dynamic object deserialization if possible, or implement robust security checks to prevent exploitation.

- **Preconditions:**
    - An Azure Function must be deployed that utilizes the Activity Trigger from the `azure-functions-durable` extension.
    - The Activity Function's code must allow the deserialization of input data using the default `ActivityTriggerConverter`, which employs the vulnerable `_deserialize_custom_object` function.
    - An attacker must be able to send input data to this Activity Function. This is typically achieved through orchestration functions calling the activity function, and the orchestration function's input being controllable by an external attacker (e.g., via HTTP trigger).

- **Source Code Analysis:**
    - Vulnerable code is located in `/code/azure/functions/_durable_functions.py`:

    ```python
    def _deserialize_custom_object(obj: dict) -> object:
        """Deserialize a user-defined object from JSON.
        ...
        """
        if ("__class__" in obj) and ("__module__" in obj) and ("__data__" in obj):
            class_name = obj.pop("__class__")
            module_name = obj.pop("__module__")
            obj_data = obj.pop("__data__")

            # Importing the clas
            module = import_module(module_name) # [VULNERABILITY] Dynamic import based on user-controlled input
            class_ = getattr(module, class_name) # [VULNERABILITY] Dynamic attribute access based on user-controlled input

            if not hasattr(class_, "from_json"):
                raise TypeError(f"class {type(obj)} does not expose a `from_json` "
                                "function")

            # Initialize the object using its `from_json` deserializer
            obj = class_.from_json(obj_data)
        return obj
    ```

    - The `_deserialize_custom_object` function dynamically imports a module and gets a class attribute based on the `__module__` and `__class__` keys from the JSON input. This allows an attacker to control which module and class are loaded.
    - The `ActivityTriggerConverter.decode` function in `/code/azure/functions/durable_functions.py` uses this vulnerable deserialization:

    ```python
    class ActivityTriggerConverter(meta.InConverter,
                                   meta.OutConverter,
                                   binding='activityTrigger',
                                   trigger=True):
        ...
        @classmethod
        def decode(cls,
                   data: meta.Datum, *,
                   trigger_metadata) -> typing.Any:
            data_type = data.type

            # Durable functions extension always returns a string of json
            # See durable functions library's call_activity_task docs
            if data_type in ['string', 'json']:
                try:
                    callback = _durable_functions._deserialize_custom_object # [VULNERABILITY] Vulnerable deserialization function
                    result = json.loads(data.value, object_hook=callback) # [VULNERABILITY] User controlled data passed to json.loads
                    ...
    ```

    - The `ActivityTriggerConverter.decode` method uses `json.loads` with the `object_hook` parameter set to the vulnerable `_deserialize_custom_object` function, making Activity Functions vulnerable to code injection if they process untrusted input.

- **Security Test Case:**

    1. **Setup:** Deploy an Azure Function App with the Python library and the `azure-functions-durable` extension installed.
    2. **Create a Durable Function:** Define an Orchestrator Function that calls an Activity Function. The Orchestrator Function should be triggered by an HTTP request and should pass user-controlled input to the Activity Function.
    3. **Craft Malicious Payload:** Create a JSON payload that exploits the `_deserialize_custom_object` function. For example, to execute `os.system('touch /tmp/pwned')`, the payload might look like this:

    ```json
    {
        "__class__": "system",
        "__module__": "os",
        "__data__": "touch /tmp/pwned"
    }
    ```

    4. **Trigger the Orchestration:** Send an HTTP request to trigger the Orchestrator Function, passing the malicious JSON payload as input that will eventually be passed to the Activity Function.
    5. **Verify Code Execution:** Check if the command `touch /tmp/pwned` was executed on the Azure Functions host. In a real-world scenario, you would check for more subtle indicators of code execution or information leakage. For testing purposes, creating a file in `/tmp` is a simple way to verify execution.

    **Example Python code for vulnerable Azure Function:**

    ```python
    import azure.durable_functions as df
    import logging
    import json

    def orchestrator_function(context: df.DurableOrchestrationContext):
        user_input = context.get_input()
        result = yield context.call_activity('ActivityFunction', user_input)
        return result

    main = df.Orchestrator.create(orchestrator_function)

    def activity_function(user_input: str): # Expecting string, but will accept malicious json
        logging.info(f"Received input: {user_input}")
        # Vulnerable deserialization happens here due to default ActivityTriggerConverter
        return user_input

    activity_function_app = df.Activity.create(activity_function)
    ```

    **HTTP Trigger to call Orchestrator (for test setup):**

    ```python
    import azure.functions as func
    import azure.durable_functions as df
    import logging

    async def main(req: func.HttpRequest, starter: str) -> func.HttpResponse:
        client = df.DurableOrchestrationClient(starter)

        # Get user input from the HTTP request body - potentially malicious JSON
        try:
            request_body = req.get_json()
        except ValueError:
            return func.HttpResponse(
                 "Please pass a JSON payload in the request body",
                 status_code=400
            )

        instance_id = await client.start_new(req.route_params.get('functionName'), client_input=request_body)

        logging.info(f"Started orchestration with ID = '{instance_id}'.")

        return df.HttpResponse(
            client.create_check_status_response(req, instance_id),
            headers={"Content-Type": "application/json"}
        )


    http_start = func.Blueprint()
    http_start.route('/orchestrators/{functionName}').functions = [main]
    ```

    **To run the test case:**

    1. Deploy the above Azure Functions code.
    2. Send a POST request to the HTTP endpoint of the Orchestrator Function (e.g., `https://<your-function-app>.azurewebsites.net/api/orchestrators/orchestrator_function`) with the malicious JSON payload in the request body.
    3. Check the Azure Functions logs or the `/tmp` directory (if accessible in your testing environment) to confirm if the `touch /tmp/pwned` command was executed.