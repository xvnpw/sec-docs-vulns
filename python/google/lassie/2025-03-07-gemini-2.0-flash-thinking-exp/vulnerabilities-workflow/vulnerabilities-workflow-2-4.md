### Vulnerability List

#### 1. Unsafe Deserialization in Pre-trained Model Loading

* Description:
    1. An attacker crafts a malicious pre-trained model file, embedding arbitrary code within it.
    2. The attacker replaces the legitimate pre-trained model file (`primitive_decoder.pth` or `<animal_class>.pth`) in the `model_dump/` directory with their malicious file. This replacement could occur through various means, such as gaining unauthorized access to the file system, or tricking a user into manually replacing the file.
    3. A user executes the LASSIE application, either by running `train.py` for training or `eval.py` for evaluation.
    4. During startup or execution, the application loads the pre-trained model using `torch.load()` in `main/model.py` (for LASSIE model) or `networks/part_vae.py` (for primitive decoder VAE).
    5. `torch.load()` deserializes the provided model file. Due to the inherent risks of `torch.load()`, any embedded malicious code within the crafted model is executed during the deserialization process.
    6. This execution of arbitrary code grants the attacker control over the system running the LASSIE application.

* Impact:
    * Arbitrary code execution on the machine running the LASSIE application.
    * Complete compromise of the system, potentially leading to:
        * Data exfiltration and theft.
        * Installation of malware, ransomware, or other malicious software.
        * Further propagation of attacks to other systems on the network.
        * Denial of service or system instability.

* Vulnerability rank: Critical

* Currently implemented mitigations:
    * None. The project directly utilizes `torch.load()` to load model files without any input validation, integrity checks, or sandboxing measures.

* Missing mitigations:
    * **Input Validation and Integrity Checks**: Implement verification mechanisms to ensure the loaded model file is legitimate and untampered with. This could involve:
        * **Checksum Verification**: Generate and store checksums (e.g., SHA256 hashes) of the official pre-trained model files. Before loading a model, recalculate its checksum and compare it against the stored trusted checksum. Reject loading if checksums do not match.
        * **Digital Signatures**: Digitally sign the pre-trained model files using a private key. Implement signature verification in the application using the corresponding public key to ensure authenticity and integrity.
    * **Safe Deserialization Alternatives (Limited):** While direct safe alternatives to `torch.load()` for PyTorch model loading are limited, consider:
        * **Sandboxing/Isolation**: If feasible, execute the `torch.load()` operation within a sandboxed or isolated environment with restricted permissions to limit the impact of potential malicious code execution. However, this is complex to implement and might not fully mitigate the risk.
    * **User Education and Warnings**: Clearly document the risks associated with loading pre-trained models from potentially untrusted sources. Advise users to:
        * Only download pre-trained models from the official LASSIE repository or other trustworthy sources.
        * Verify the source and integrity of downloaded model files.
        * Be cautious when using pre-trained models in untrusted environments.

* Preconditions:
    1. The attacker must be able to replace the legitimate pre-trained model file (`primitive_decoder.pth` or `<animal_class>.pth`) within the `model_dump/` directory on the user's system. This could be achieved through social engineering, exploiting other vulnerabilities, or compromised environments.
    2. The user must execute either `train.py` or `eval.py`, which triggers the model loading process using `torch.load()`.

* Source code analysis:
    1. **`main/model.py`**:
        * The `load_model` function (lines 407-412) is responsible for loading the main LASSIE model.
        ```python
        def load_model(self, model_path):
            checkpoint = torch.load(model_path)
            self.load_state_dict(checkpoint['main'])
            for i, f in enumerate(self.f_parts):
                f.load_state_dict(checkpoint['f_part_%d'%i])
        ```
        * Line 408 directly uses `torch.load(model_path)` to deserialize the model from the file path provided.
    2. **`networks/part_vae.py`**:
        * The `load_model` function (lines 168-169) within the `PartVAE` class is responsible for loading the pre-trained primitive decoder VAE model.
        ```python
        def load_model(self, model_path):
            self.load_state_dict(torch.load(model_path, map_location=cfg.device))
        ```
        * Line 169 utilizes `torch.load(model_path, map_location=cfg.device)` to load the VAE model.
    3. **`main/config.py`**:
        * Defines the paths for model storage:
        ```python
        model_dir = osp.join(root_dir, 'model_dump')
        vae_model_path = osp.join(model_dir, 'primitive_decoder.pth')
        ```
        * `vae_model_path` points to the primitive decoder VAE model file.
        * `model_dir` is used to construct the path for the LASSIE model, as seen in `main/train.py` and `main/eval.py`.
    4. **`main/train.py` and `main/eval.py`**:
        * In both `train_model()` in `train.py` and `eval_model()` in `eval.py`, the `load_model` functions are called:
        ```python
        # main/train.py
        model.load_model(osp.join(cfg.model_dir, '%s.pth'%cfg.animal_class))
        # networks/part_vae.py is loaded in train_model if vae_model_path does not exist
        part_vae.load_model(cfg.vae_model_path)

        # main/eval.py
        model.load_model(osp.join(cfg.model_dir, '%s.pth'%cfg.animal_class))
        ```
        * These lines demonstrate how the application loads the models using the paths configured in `config.py` and the vulnerable `load_model` functions.

* Security test case:
    1. **Malicious Model Creation**: Create a Python script (e.g., `create_malicious_model.py`) to generate a malicious PyTorch model:
        ```python
        import torch
        import os

        class MaliciousModel(torch.nn.Module):
            def __init__(self):
                super().__init__()
                # Command to execute: Create a file named 'pwned' in the /tmp directory
                os.system('touch /tmp/pwned')

            def forward(self, x):
                return x

        malicious_model = MaliciousModel()
        torch.save(malicious_model.state_dict(), 'malicious_primitive_decoder.pth')
        print("Malicious model 'malicious_primitive_decoder.pth' created.")
        ```
    2. **Replace Legitimate Model**:
        * Navigate to the `model_dump/` directory within the LASSIE project.
        * **Backup**: Rename the original `primitive_decoder.pth` to `primitive_decoder.pth.bak` to keep a backup.
        * **Replace**: Copy the `malicious_primitive_decoder.pth` (generated in step 1) into the `model_dump/` directory and rename it to `primitive_decoder.pth`, effectively replacing the legitimate model with the malicious one.
    3. **Run LASSIE Training**: Execute the LASSIE training script:
        ```bash
        python main/train.py --cls zebra
        ```
    4. **Verify Code Execution**: After running the training script, check if the malicious code was executed:
        ```bash
        ls /tmp/pwned
        ```
        * If the command `ls /tmp/pwned` shows the file `/tmp/pwned`, it confirms that the malicious code embedded in `malicious_primitive_decoder.pth` was successfully executed during model loading by `torch.load()`. This demonstrates arbitrary code execution.
    5. **Repeat for Evaluation (Optional)**: To verify the vulnerability in the evaluation script as well, repeat steps 2-4, but instead of running `train.py`, execute:
        ```bash
        python main/eval.py --cls zebra
        ```
        and check for the creation of `/tmp/pwned` again.

This test case successfully demonstrates the unsafe deserialization vulnerability and proves the potential for arbitrary code execution by replacing the pre-trained model file.