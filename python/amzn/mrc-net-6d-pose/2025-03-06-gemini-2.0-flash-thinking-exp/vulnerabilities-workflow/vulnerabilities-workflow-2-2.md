- Vulnerability Name: Malicious Pre-trained Model Weights - Supply Chain Attack
- Description:
  1. The project `README.md` instructs users to download pre-trained model weights from a provided Google Drive link.
  2. Users are expected to manually download the weights and place them in the `chkpt_<dataset>` directory within the project structure.
  3. The `run_inference.sh` script is then used to execute inference, which loads the pre-trained model weights from the local `chkpt_<dataset>` directory using `torch.load()` in `inference.py`.
  4. An attacker could perform a supply chain attack by compromising the provided Google Drive link and replacing the legitimate pre-trained model weights file with a malicious one.
  5. If a user follows the instructions and downloads the compromised weights, the `inference.py` script will load these malicious weights during inference execution.
  6. Due to the insecure nature of `torch.load()`, a malicious model weights file could contain embedded code that gets executed on the user's machine when the model is loaded, leading to arbitrary code execution.
- Impact:
  - Arbitrary code execution on the user's machine.
  - Full compromise of the user's system is possible depending on the attacker's payload in the malicious model weights.
  - Potential data exfiltration, malware installation, or denial of service.
- Vulnerability rank: Critical
- Currently implemented mitigations:
  - None. The project directly uses the downloaded pre-trained weights without any integrity checks or secure download mechanisms.
- Missing mitigations:
  - **Integrity checks:** Implement integrity checks for the downloaded pre-trained model weights. This could involve providing a checksum (e.g., SHA256 hash) of the legitimate weights in the `README.md` and verifying this checksum after downloading the file.
  - **Secure hosting:** Host the pre-trained weights on a more secure and controlled platform, such as GitHub releases, which offers better version control and integrity.
  - **Code review and hardening:** Conduct a thorough security code review of the model loading process in `inference.py` and explore safer alternatives to `torch.load()` or implement sandboxing/isolation techniques if `torch.load()` must be used.
  - **User warnings:** Include a clear warning in the `README.md` about the potential security risks of downloading pre-trained models from external sources and advise users to manually verify the integrity of the downloaded files if checksums are provided, or to download from trusted sources if available.
- Preconditions:
  - The user must download the pre-trained model weights by clicking the provided Google Drive link in `README.md`.
  - The attacker must have successfully compromised the Google Drive link and replaced the legitimate model weights file with a malicious file.
- Source code analysis:
  - `/code/README.md`: The `README.md` file contains the vulnerable Google Drive download link in the "Inference" section:
    ```markdown
    Our pretrained model weights can be downloaded from [this link](https://drive.google.com/file/d/1Bz2ZFAoTHk-pjCcr3HceCLIcj0ugYYia/view?usp=sharing).
    ```
    This link is the entry point for the supply chain attack.
  - `/code/scripts/run_inference.sh`: This script executes the inference process and utilizes the downloaded weights. It sets up the inference command:
    ```bash
    python inference.py \
        --dataset $DATASET \
        --checkpoint_name chkpt_${DATASET} \
        --model_name tless \
        --output_suffix $SUFFIX
    ```
    The `--checkpoint_name chkpt_${DATASET}` argument indicates that the weights are loaded from the `chkpt_${DATASET}` directory, which is where the user is instructed to place the downloaded weights.
  - `/code/inference.py`: The `inference.py` script is where the model weights are actually loaded. While the provided snippet doesn't explicitly show the `torch.load()` call, it's implied that the model loading happens within the `models` module or `inference_func`. Assuming standard PyTorch model loading practices, `torch.load()` is the likely function used, which is vulnerable. Further code analysis of `models.py` would be needed to confirm how the model is initialized and if weights are loaded directly within the model definition, but the vulnerability is primarily due to the untrusted source of the weights and the inherent risks of `torch.load()`.
- Security test case:
  1. **Environment Setup:** Follow the instructions in the `README.md` to set up the environment and install dependencies.
  2. **Malicious Model Weight Creation:** Create a malicious PyTorch model weights file (e.g., `tless.pth`). This file should contain code that will execute arbitrary commands when `torch.load()` is called. A simple proof-of-concept payload could be to print a message to the console or create a file in the user's temporary directory. For example, the malicious `tless.pth` could be crafted to include code that executes `os.system('touch /tmp/pwned')` when loaded.
  3. **Simulate Weights Replacement:** Since direct modification of the Google Drive link is not possible in this context, simulate the attack by manually placing the malicious `tless.pth` file into the `chkpt_tless` directory within the project. Ensure to remove or rename any legitimate `tless.pth` file that might already be present from previous steps.
  4. **Execute Inference Script:** Run the inference script using the command: `bash scripts/run_inference.sh`.
  5. **Verify Code Execution:** After running the inference script, check for the indicators of malicious code execution. In the example payload, verify if the file `/tmp/pwned` has been created. If the file exists, it confirms that the malicious code embedded in the `tless.pth` was executed when `torch.load()` processed the file during the inference process, thus validating the vulnerability.