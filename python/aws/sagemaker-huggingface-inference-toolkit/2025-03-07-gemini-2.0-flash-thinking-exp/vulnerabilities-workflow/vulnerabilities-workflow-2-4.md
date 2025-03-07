### Vulnerability List:

- Vulnerability Name: Hugging Face Hub Model Arbitrary Code Execution via `HF_TRUST_REMOTE_CODE`
- Description:
    - An attacker can compromise a SageMaker endpoint by leveraging the `HF_TRUST_REMOTE_CODE` and `HF_MODEL_ID` features.
    - A user deploys a SageMaker endpoint using the Hugging Face Inference Toolkit, intending to serve a model from the Hugging Face Hub.
    - During deployment, the user sets the environment variable `HF_TRUST_REMOTE_CODE` to `True`. This setting is intended to allow loading custom models with code from the Hub.
    - The user also specifies the `HF_MODEL_ID` environment variable to point to a specific Hugging Face model repository on the Hub.
    - When the SageMaker endpoint starts, the toolkit downloads the specified model from the Hugging Face Hub using the `HF_MODEL_ID`.
    - If a malicious actor has created a Hugging Face model repository and uploaded it to the Hub, they can include malicious code within the model files (e.g., in `model.py`, or within configuration files if the model loading process executes code from configurations).
    - With `HF_TRUST_REMOTE_CODE=True`, the Hugging Face Transformers library, used by the toolkit, will execute this custom code during the model loading process.
    - This malicious code executes within the security context of the SageMaker endpoint's environment.
- Impact:
    - **Critical**: Arbitrary code execution on the SageMaker endpoint instance.
    - This can lead to a complete compromise of the SageMaker endpoint.
    - An attacker could potentially gain access to sensitive data processed by the endpoint.
    - Depending on the IAM role assigned to the SageMaker endpoint, the attacker might be able to access other AWS resources, escalate privileges, or perform other unauthorized actions within the AWS environment.
- Vulnerability Rank: critical
- Currently Implemented Mitigations:
    - Documentation: The README.md file mentions the `HF_TRUST_REMOTE_CODE` environment variable and states: "The `HF_TRUST_REMOTE_CODE` environment variable defines wether or not to allow for custom models defined on the Hub in their own modeling files. Allowed values are `"True"` and `"False"`". This implicitly warns users about trusting remote code, but it is not a strong mitigation.
    - No code-level mitigations are implemented within the project to prevent arbitrary code execution when `HF_TRUST_REMOTE_CODE=True` is enabled. The toolkit relies on the Hugging Face Transformers library's behavior.
- Missing Mitigations:
    - Default `HF_TRUST_REMOTE_CODE=False`: The default value for `HF_TRUST_REMOTE_CODE` should be `False`. This ensures that users must explicitly opt-in to allow remote code execution, making it a conscious security decision.
    - Stronger Warnings: Enhance documentation and potentially add deployment-time warnings when `HF_TRUST_REMOTE_CODE=True` is set, clearly outlining the severe security risks.
    - Input Validation/Model Scanning: Explore options for scanning or analyzing model repositories from the Hub for potentially malicious code patterns before downloading and loading them. This is a complex mitigation, but could reduce risk.
    - Sandboxing/Isolation: Investigate running the model loading and inference processes in a sandboxed or more isolated environment to limit the potential impact of arbitrary code execution. For example, using restricted containers or security policies.
    - Principle of Least Privilege IAM Roles: Encourage users to assign the least privilege IAM roles to SageMaker endpoints to limit the blast radius in case of compromise.
- Preconditions:
    - `HF_TRUST_REMOTE_CODE` is set to `True` during SageMaker endpoint creation.
    - `HF_MODEL_ID` is used to specify a model from the Hugging Face Hub.
    - A malicious Hugging Face model repository exists on the Hub, containing exploitable code.
- Source Code Analysis:
    - The vulnerability originates in the design of the Hugging Face `transformers` library, which allows execution of custom code from model repositories when `trust_remote_code=True`.
    - The `sagemaker-huggingface-inference-toolkit` project exposes this functionality through the `HF_TRUST_REMOTE_CODE` environment variable without adding any additional security layers.
    - Key files involved:
        - `src/sagemaker_huggingface_inference_toolkit/transformers_utils.py`:
            - `get_pipeline` function:
                ```python
                def get_pipeline(task: str, device: int, model_dir: Path, **kwargs) -> Pipeline:
                    ...
                    elif TRUST_REMOTE_CODE and os.environ.get("HF_MODEL_ID", None) is not None and device == 0:
                        tokenizer = AutoTokenizer.from_pretrained(os.environ["HF_MODEL_ID"])

                        hf_pipeline = pipeline(
                            task=task,
                            model=os.environ["HF_MODEL_ID"],
                            tokenizer=tokenizer,
                            trust_remote_code=TRUST_REMOTE_CODE, # TRUST_REMOTE_CODE is passed here
                            model_kwargs={"device_map": "auto", "torch_dtype": "auto"},
                        )
                    ...
                    else:
                        # load pipeline
                        hf_pipeline = pipeline(
                            task=task, model=model_dir, device=device, trust_remote_code=TRUST_REMOTE_CODE, **kwargs # TRUST_REMOTE_CODE is passed here
                        )
                    return hf_pipeline
                ```
                - The `get_pipeline` function in `transformers_utils.py` takes the `TRUST_REMOTE_CODE` variable (which is derived from the `HF_TRUST_REMOTE_CODE` environment variable) and directly passes it to the `pipeline()` function of the `transformers` library. This enables the remote code execution feature if `HF_TRUST_REMOTE_CODE=True`.
        - `src/sagemaker_huggingface_inference_toolkit/handler_service.py`:
            - `load` function: This function calls `get_pipeline` to load the Hugging Face pipeline, and thus indirectly uses the `TRUST_REMOTE_CODE` setting.
        - `src/sagemaker_huggingface_inference_toolkit/mms_model_server.py`:
            - `start_model_server` function: This function sets up the environment and starts the MMS server, making the environment variables, including `HF_TRUST_REMOTE_CODE`, effective.

- Security Test Case:
    1. **Create a Malicious Model Repository on Hugging Face Hub:**
        - Create a new Hugging Face Hub repository (e.g., named `malicious-model`).
        - Add a file named `inference.py` to the repository with the following malicious code:
            ```python
            import os
            import subprocess

            def model_fn(model_dir):
                subprocess.run(["touch", "/tmp/pwned"], check=True) # Malicious command to create a file in /tmp
                return "Malicious Model Loaded"

            def predict_fn(data, model):
                return "Inference from Malicious Model"
            ```
        - Commit and push these files to the `malicious-model` repository.
    2. **Deploy SageMaker Endpoint with `HF_TRUST_REMOTE_CODE=True`:**
        - Use the SageMaker Python SDK to deploy a Hugging Face model.
        - Set the `HF_MODEL_ID` environment variable to the name of your malicious repository, e.g., `"<your-huggingface-username>/malicious-model"`.
        - Crucially, set the `HF_TRUST_REMOTE_CODE` environment variable to `"True"`.
        - Deploy the endpoint to SageMaker (e.g., using `ml.m5.xlarge` instance).
        ```python
        from sagemaker.huggingface import HuggingFaceModel
        import sagemaker

        role = sagemaker.get_execution_role()
        hub = {
            'HF_MODEL_ID': '<your-huggingface-username>/malicious-model', # Replace with your malicious model repo
            'HF_TASK': 'text-classification', # Task doesn't matter for this test
            'HF_TRUST_REMOTE_CODE': 'True' # Enable remote code execution
        }
        huggingface_model = HuggingFaceModel(
            transformers_version='4.28',
            pytorch_version='1.13',
            py_version='py39',
            env=hub,
            role=role,
        )
        predictor = huggingface_model.deploy(
            initial_instance_count=1,
            instance_type='ml.m5.xlarge'
        )
        ```
    3. **Send Inference Request:**
        - Send a dummy inference request to the deployed SageMaker endpoint to trigger model loading.
        ```python
        predictor.predict({"inputs": "test"})
        ```
    4. **Verify Malicious Code Execution:**
        - SSH into the SageMaker endpoint instance (if possible, or use SageMaker Studio/Notebook to execute commands on the instance if direct SSH is restricted).
        - Check for the existence of the `/tmp/pwned` file.
        - If the file `/tmp/pwned` exists, it confirms that the malicious code within `model_fn` in `inference.py` from the Hugging Face Hub repository was executed during model loading, proving the arbitrary code execution vulnerability.

This test case demonstrates how a malicious model from the Hugging Face Hub, combined with `HF_TRUST_REMOTE_CODE=True`, can lead to arbitrary code execution on a SageMaker endpoint.