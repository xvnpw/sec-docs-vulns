### Vulnerability List

- Vulnerability Name: Deserialization vulnerability in online scoring endpoint leading to Remote Code Execution
- Description:
    1. The online scoring endpoint, defined in `/src/deploy/online/score.py`, loads the machine learning model using `joblib.load` in the `init()` function.
    2. The `init()` function is executed when the online endpoint's container is initialized or started, typically during deployment or after an update.
    3. `joblib.load` is known to be vulnerable to deserialization attacks. If a serialized object from an untrusted source is loaded, it can lead to arbitrary code execution.
    4. If an attacker manages to replace the legitimate model file (`model.pkl`) within the deployed environment with a maliciously crafted serialized object, the `joblib.load` call in `init()` will execute arbitrary code on the server hosting the online endpoint when the container starts or restarts.
    5. This can be achieved if the model registry or model deployment pipeline is compromised, allowing the attacker to inject a malicious model.
- Impact:
    - Critical. Successful exploitation allows for arbitrary code execution on the server hosting the online endpoint.
    - An attacker can gain complete control over the machine learning inference server, potentially leading to:
        - Data breach and exfiltration of sensitive information, including training data, user data, or secrets stored on the server.
        - System compromise, allowing the attacker to modify system configurations, install backdoors, or pivot to other internal systems.
        - Denial of service by crashing the endpoint or consuming excessive resources.
- Vulnerability Rank: Critical
- Currently implemented mitigations:
    - None. The provided code and configurations do not include any specific mitigations against deserialization vulnerabilities. The security relies on the underlying Azure Machine Learning platform and the security of the model deployment pipeline, but the code itself does not implement any checks or secure loading practices.
- Missing mitigations:
    - Model origin validation and integrity checks: Before loading the model using `joblib.load`, the scoring script should verify the origin and integrity of the model file to ensure it comes from a trusted source and has not been tampered with. This could involve cryptographic signatures or checksums.
    - Secure model serialization format: Consider using safer serialization formats that are less prone to deserialization attacks if possible. If `joblib` is necessary, ensure that the model loading process is strictly controlled and isolated.
    - Principle of least privilege: Ensure that the online endpoint service account and container environment have the minimum necessary privileges to reduce the potential impact of a successful exploit.
    - Regular security scanning: Implement regular security scanning of the model deployment pipeline and deployed endpoints to detect and prevent the introduction of malicious models.
- Preconditions:
    - The online endpoint must be deployed using the provided configurations, which include the vulnerable scoring script (`/src/deploy/online/score.py`) and the use of `joblib.load`.
    - An attacker needs to compromise the model deployment pipeline or model registry to replace the legitimate `model.pkl` file with a malicious one. This could involve exploiting vulnerabilities in CI/CD systems, access control weaknesses, or insider threats.
- Source code analysis:
    1. **File:** `/src/deploy/online/score.py`
    2. **Function:** `init()`
    3. **Line:** `model = joblib.load(model_path)`
    ```python
    def init():
        global model
        model_path = os.path.join(os.getenv("AZUREML_MODEL_DIR"), "models/model.pkl")
        model = joblib.load(model_path) # Vulnerable line
        logging.info("Init complete")
    ```
    - The `init()` function is executed during container startup.
    - `model_path` is constructed using the environment variable `AZUREML_MODEL_DIR`, which points to the deployed model directory.
    - `joblib.load(model_path)` deserializes the model from the `model.pkl` file.
    - `joblib.load` is susceptible to deserialization vulnerabilities, allowing for arbitrary code execution if a malicious `model.pkl` is loaded.
- Security test case:
    1. **Prepare a malicious model file:**
        - Create a Python script `malicious_model_generator.py` with the following content to generate a malicious `model.pkl` file:
        ```python
        import joblib
        import os

        class MaliciousObject:
            def __reduce__(self):
                return (os.system, ('touch /tmp/pwned',)) # Command to execute: create /tmp/pwned file

        malicious_model = MaliciousObject()
        joblib.dump(malicious_model, 'model.pkl')
        ```
        - Run the script: `python malicious_model_generator.py`
        - This will create a file named `model.pkl` in the same directory. This file is a malicious serialized object.
    2. **Deploy the online endpoint (or simulate local deployment):**
        - For a real test, you would need to deploy the online endpoint using the provided configurations. However, replacing the model in a deployed Azure ML endpoint might be restricted. For a local simulation:
            - Assume you have a local directory structure mimicking the deployed environment, where the scoring script `/src/deploy/online/score.py` is used.
            - Locate the directory where the `model.pkl` would be placed during a real deployment (within `AZUREML_MODEL_DIR/models/`). For local testing, you might need to adjust `model_path` in `score.py` to a local, writable path.
        - **Replace the legitimate `model.pkl` with the malicious `model.pkl` generated in step 1.**
    3. **Trigger the endpoint initialization:**
        - In a real deployment, restarting the endpoint or updating the deployment might trigger the `init()` function again. For a local simulation, you might need to manually run the `init()` function from `score.py` after setting up the environment variables or simulate endpoint invocation.
    4. **Check for successful code execution:**
        - After triggering the endpoint initialization (and thus the `init()` function in `score.py`), check if the command embedded in the malicious `model.pkl` was executed. In our example, the command is `touch /tmp/pwned`.
        - Access the server or container hosting the online endpoint and check if the file `/tmp/pwned` exists.
        - If the file `/tmp/pwned` is present, it confirms that arbitrary code execution was achieved through deserialization of the malicious model file.

This security test case demonstrates that if a malicious `model.pkl` file is placed in the expected location, the `joblib.load` function in the scoring script will execute arbitrary code during endpoint initialization, confirming the deserialization vulnerability and potential for Remote Code Execution.