- Vulnerability Name: Malicious Model Injection via Insecure Weight Download
- Description:
    - The MRC-Net project instructs users to download pre-trained model weights from an external Google Drive link provided in the README.md file.
    - This download process is inherently insecure because:
        - It relies on manual user download and placement of the file.
        - There is no mechanism to verify the integrity or authenticity of the downloaded file.
    - An attacker could potentially replace the legitimate model weights file hosted on the Google Drive link with a malicious file.
    - If a user unknowingly downloads and places the malicious weights file as instructed, and then runs the inference script, the malicious model will be loaded and executed.
    - This could allow the attacker to execute arbitrary code on the user's system or compromise the user's data.
    - Step-by-step trigger:
        1. An attacker gains control over or compromises the Google Drive link provided in the README.md or finds another way to distribute a malicious `tless.pth` file.
        2. The attacker replaces the legitimate `tless.pth` file with a malicious file containing backdoors or malicious code.
        3. A user, following the project's README.md instructions, downloads the malicious `tless.pth` file, believing it to be the legitimate pre-trained weights.
        4. The user places the downloaded `tless.pth` file in the `chkpt_tless` directory as instructed.
        5. The user executes the inference script `scripts/run_inference.sh`.
        6. The `inference.py` script, executed by `run_inference.sh`, loads the malicious model weights file `tless.pth` from the `chkpt_tless` directory using `torch.load()`.
        7. The malicious code embedded in the model weights is executed when the model is loaded, potentially compromising the user's system or data.
- Impact:
    - Critical.
    - Successful exploitation of this vulnerability could lead to:
        - Arbitrary code execution on the user's machine. An attacker could gain complete control over the system.
        - Data compromise. An attacker could steal sensitive data from the user's system.
        - System instability or malfunction depending on the nature of the malicious code.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None.
    - The project lacks any security measures to validate the downloaded model weights.
    - There is no integrity check, signature verification, or secure download mechanism in place.
- Missing Mitigations:
    - Integrity Check:
        - Implement a mechanism to verify the integrity of the downloaded model weights.
        - This could be achieved by providing a checksum (e.g., SHA256 hash) of the legitimate weights file in the README.md.
        - The `inference.py` script should then be modified to calculate the checksum of the downloaded weights file and compare it against the provided checksum before loading the model.
    - Secure Download:
        - Ideally, transition to a more secure method of distributing model weights.
        - Hosting the weights on a secure, project-controlled server and downloading them via HTTPS during setup would be a stronger mitigation.
        - For now, as the project uses Google Drive, providing checksums is a more practical immediate step.
    - Security Warning Documentation:
        - Add a clear and prominent security warning in the README.md file.
        - This warning should explicitly state the risk of downloading and using pre-trained weights from untrusted sources.
        - Advise users to verify the source and integrity of downloaded files, and ideally provide the correct checksum there.
- Preconditions:
    - User downloads the pre-trained model weights from the provided Google Drive link.
    - Attacker successfully replaces the legitimate weights file on the Google Drive link (or a similar distribution point) with a malicious one.
    - User places the (malicious) downloaded weights file in the `chkpt_<dataset>` directory.
    - User executes the inference script `scripts/run_inference.sh`.
- Source Code Analysis:
    - File: `/code/README.md`
        - The README.md provides instructions for downloading pre-trained weights from a Google Drive link and placing them in the `chkpt_<dataset>` directory.
        - This manual download and placement process is the entry point for the vulnerability as it relies on user trust and provides no security guarantees.
    - File: `/code/scripts/run_inference.sh`
        - This script executes `inference.py` and passes arguments specifying the dataset, checkpoint directory (`chkpt_${DATASET}`), and model name.
        - It sets up the execution environment for the vulnerable inference process.
    - File: `/code/inference.py`
        - This script is responsible for loading the model weights and performing inference.
        - Line: `checkpoint = torch.load(p['checkpoint'], map_location=device)` loads the model weights file. `p['checkpoint']` is constructed based on user-provided arguments (`--checkpoint_name`, `--model_name`) which point to the directory where the user is instructed to place downloaded weights.
        - **Vulnerability Point**: The `torch.load()` function directly loads and deserializes the Python objects from the provided file path without any integrity or authenticity checks. If a malicious file is placed at this path, `torch.load()` will execute its contents.
        - There is no code to verify the integrity or source of the `tless.pth` file before loading it.
    - Files: `/code/models.py`, `/code/main.py`, `/code/bop_dataset.py`, `/code/config.py`, `/code/utils.py`, `/code/precompute_quaternion_labels.py`, `/code/requirements.txt`
        - These files define the model architecture, training process, dataset handling, configurations, utility functions, and dependencies.
        - They are not directly involved in the weight loading vulnerability itself but are relevant to the project's functionality and the context of the vulnerability.
- Security Test Case:
    1. Prepare Environment:
        - Set up the MRC-Net project environment by following the instructions in `README.md` (steps under "Setup"), but **do not download the pre-trained weights** yet.
        - Ensure you have the necessary dependencies installed as per `scripts/install_deps.sh`.
    2. Create Malicious Weights File:
        - Create a Python script (e.g., `malicious_payload.py`) to generate a malicious `tless.pth` file. This file should contain code that will be executed when loaded by `torch.load()`. For example, the malicious code could create a marker file in the `/tmp` directory or attempt to establish a network connection.
        ```python
        import torch
        import os

        class MaliciousModel(torch.nn.Module):
            def __init__(self):
                super().__init__()
                # Malicious payload: create a marker file
                os.system('touch /tmp/mrcnet_vulnerable')

            def forward(self, x):
                return x # Dummy forward pass

        malicious_model = MaliciousModel()
        torch.save({'network': malicious_model.state_dict()}, 'tless.pth')
        print("Malicious model weights 'tless.pth' created.")
        ```
        - Run `python malicious_payload.py` to generate the `tless.pth` file.
    3. Simulate Attack:
        - Navigate to the project's root directory.
        - Create the checkpoint directory: `mkdir chkpt_tless`
        - Copy the generated malicious weights file `tless.pth` into the checkpoint directory: `mv tless.pth chkpt_tless/`. This simulates an attacker replacing the legitimate weights file, and the user unknowingly downloading the malicious version.
    4. Run Inference Script:
        - Execute the inference script: `bash scripts/run_inference.sh`
    5. Verify Exploitation:
        - Check for the marker file: `ls /tmp/mrcnet_vulnerable`
        - If the file `/tmp/mrcnet_vulnerable` exists, it confirms that the malicious code embedded in `tless.pth` was executed when `torch.load()` loaded the weights during inference. This demonstrates the vulnerability.