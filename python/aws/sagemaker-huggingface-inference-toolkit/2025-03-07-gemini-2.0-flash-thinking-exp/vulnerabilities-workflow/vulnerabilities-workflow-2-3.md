### Vulnerability 1: Arbitrary Code Execution via User-Provided `inference.py` and Unsafe Deserialization

- Description:
    1. A user deploys a SageMaker endpoint using the Hugging Face Inference Toolkit and provides a custom `inference.py` script within their `model.tar.gz` archive.
    2. Within this `inference.py` script, specifically in the `input_fn` or `transform_fn` functions, the user implements deserialization of the input data using unsafe methods like `pickle.loads`, `yaml.load`, `eval`, or `exec`.
    3. An attacker sends a crafted request to the SageMaker endpoint with a malicious serialized payload (e.g., a pickled object).
    4. The `input_fn` or `transform_fn` in the user's `inference.py` script unsafely deserializes this payload.
    5. This unsafe deserialization leads to arbitrary code execution on the SageMaker endpoint's server instance, under the permissions of the inference container.

- Impact:
    - **Critical:**  Successful exploitation allows for complete control of the SageMaker endpoint's server instance. An attacker can execute arbitrary commands, potentially leading to data exfiltration, system compromise, denial of service, or further lateral movement within the AWS environment if the instance role is overly permissive.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - None explicitly within the toolkit itself to prevent users from writing vulnerable `inference.py` scripts. The toolkit provides flexibility to override inference logic, inherently trusting user-provided code.

- Missing Mitigations:
    - **Input validation and sanitization guidance:** Documentation should strongly warn users against using unsafe deserialization methods in their `inference.py` scripts and recommend secure alternatives like JSON or safe parsers if deserialization is necessary.
    - **Security examples and best practices:** Provide example `inference.py` scripts that demonstrate secure input handling and highlight potential pitfalls of unsafe deserialization.
    - **Static code analysis or vulnerability scanning:**  Consider suggesting or integrating static analysis tools that could detect potentially unsafe deserialization patterns in user-provided `inference.py` scripts before deployment. This might be challenging to enforce but could be offered as a best practice.

- Preconditions:
    1. The user must deploy a SageMaker endpoint using the Hugging Face Inference Toolkit.
    2. The user must provide a custom `inference.py` script in their `model.tar.gz`.
    3. The `inference.py` script must contain an `input_fn` or `transform_fn` that uses an unsafe deserialization method on the input data.
    4. The attacker must be able to send requests to the deployed SageMaker endpoint.

- Source Code Analysis:
    - **`src/sagemaker_huggingface_inference_toolkit/handler_service.py`**: This file defines the `HuggingFaceHandlerService` class, which is responsible for handling inference requests. The `handle` method in this class calls `transform_fn`, which in turn calls `preprocess`, `predict`, and `postprocess`. Importantly, the `validate_and_initialize_user_module` method loads and uses user-provided implementations of `model_fn`, `input_fn`, `predict_fn`, `output_fn`, and `transform_fn` from the `inference.py` script if it exists.
    - **`handler_service.py` - `handle` method**:
        ```python
        def handle(self, data, context):
            # ...
            input_data = data[0].get("body")
            # ...
            content_type = utils.retrieve_content_type_header(request_property)
            accept = request_property.get("Accept") or request_property.get("accept")
            # ...
            if content_type in content_types.UTF8_TYPES:
                input_data = input_data.decode("utf-8")
            # ...
            response = self.transform_fn(*([self.model, input_data, content_type, accept] + self.transform_extra_arg))
            # ...
            return [response]
        ```
    - **`handler_service.py` - `transform_fn` method**:
        ```python
        def transform_fn(self, model, input_data, content_type, accept, context=None):
            # ...
            processed_data = self.preprocess(*([input_data, content_type] + self.preprocess_extra_arg))
            # ...
            predictions = self.predict(*([processed_data, model] + self.predict_extra_arg))
            # ...
            response = self.postprocess(*([predictions, accept] + self.postprocess_extra_arg))
            # ...
            return response
        ```
    - **`handler_service.py` - `validate_and_initialize_user_module` method**:
        ```python
        def validate_and_initialize_user_module(self):
            # ...
            user_module = importlib.import_module(user_module_name)

            load_fn = getattr(user_module, MODEL_FN, None)
            preprocess_fn = getattr(user_module, INPUT_FN, None)
            predict_fn = getattr(user_module, PREDICT_FN, None)
            postprocess_fn = getattr(user_module, OUTPUT_FN, None)
            transform_fn = getattr(user_module, TRANSFORM_FN, None)

            if load_fn is not None:
                self.load_extra_arg = self.function_extra_arg(self.load, load_fn)
                self.load = load_fn
            if preprocess_fn is not None:
                self.preprocess_extra_arg = self.function_extra_arg(self.preprocess, preprocess_fn)
                self.preprocess = preprocess_fn
            # ... (similar for predict_fn, postprocess_fn, transform_fn)
        ```
        - **Visualization**:
          ```mermaid
          graph LR
              A[Request to Endpoint] --> B(handle in HuggingFaceHandlerService);
              B --> C{User-provided inference.py?};
              C -- Yes --> D[Load user's input_fn/transform_fn];
              C -- No --> E[Default preprocess];
              D --> F(input_fn/transform_fn);
              E --> F;
              F --> G{Unsafe Deserialization in input_fn/transform_fn?};
              G -- Yes --> H[Arbitrary Code Execution];
              G -- No --> I[Normal Inference Flow];
              H --> J[System Compromise];
              I --> K[Prediction];
          ```
    - The code clearly shows that if a user provides an `inference.py` with a vulnerable `input_fn` or `transform_fn`, the toolkit will use it. There is no built-in mechanism to prevent users from introducing deserialization vulnerabilities in their custom code.

- Security Test Case:
    1. **Create a malicious `inference.py`**:
        ```python
        import pickle
        import base64
        import os

        def model_fn(model_dir):
            return "dummy_model"

        def input_fn(request_body, request_content_type):
            if request_content_type == 'application/octet-stream':
                command_exec = pickle.loads(request_body) # Vulnerability: unsafe deserialization
                os.system(command_exec) # Execute command - for demonstration, avoid harmful commands
                return {"command_executed": command_exec}
            else:
                raise ValueError("Unsupported content type")

        def predict_fn(input_object, model):
            return {"status": "Command execution attempted"}

        def output_fn(prediction, accept):
            return prediction
        ```
    2. **Create a malicious pickled payload**:
        ```python
        import pickle
        import base64
        import os

        command_to_execute = 'touch /tmp/pwned.txt' # Harmless command for testing
        payload = pickle.dumps(command_to_execute)
        encoded_payload = base64.b64encode(payload).decode()
        print(encoded_payload)
        ```
    3. **Create a `model.tar.gz`**: Package the malicious `inference.py` and a dummy model (e.g., empty `pytorch_model.bin`) into a `model.tar.gz` archive, ensuring the `inference.py` is in a `code/` subdirectory.
    4. **Deploy the SageMaker endpoint**: Use the SageMaker Python SDK to deploy a Hugging Face model, specifying the `model_data` as the S3 URI of the created `model.tar.gz`.
    5. **Send a crafted request**: Use `aws sagemaker-runtime invoke-endpoint` or the `client.invoke_endpoint` method to send a POST request to the deployed endpoint. Set the `ContentType` to `application/octet-stream` and the `Body` to the base64 encoded pickled payload from step 2 after decoding it from base64.
    6. **Verify code execution**: After sending the request, SSH into the SageMaker instance (if possible and permitted by your setup) or check the endpoint logs for evidence that the command `touch /tmp/pwned.txt` was executed. Alternatively, modify the malicious script to return the output of a command to the response body for easier verification. In this test case, check if `/tmp/pwned.txt` file is created inside the container.

This vulnerability highlights the critical importance of user responsibility in securing their `inference.py` scripts, especially when dealing with deserialization of input data. The toolkit provides the flexibility, but security must be a primary concern for users.