### Vulnerability List

- Vulnerability Name: Path Traversal in Checkpoint Loading
- Description:
    1. The application uses command-line arguments such as `--load_ckpt_path`, `--visual_encoder_ckpt_path`, and `--ckpt_path` to specify the directory or path from which to load model checkpoints.
    2. In the `load` functions within `/code/detection/model.py` and `/code/classification/model.py`, these user-provided paths are directly used with `os.path.join` to construct the full checkpoint file path.
    3. The `torch.load` function is then called on this constructed path to load the checkpoint file.
    4. An attacker can exploit this by providing a maliciously crafted path containing path traversal sequences (e.g., `../`, `../../`) as a value for `--load_ckpt_path` or related arguments.
    5. This allows the attacker to bypass intended directory restrictions and point `torch.load` to load files from arbitrary locations on the file system, outside the designated checkpoint directories.
- Impact:
    - Arbitrary File Read: A successful path traversal exploit allows an attacker to read arbitrary files from the system's file system, limited by the permissions of the user running the training or testing scripts.
    - Information Disclosure: This can lead to the disclosure of sensitive information, including configuration files, source code, data files, or other potentially confidential system files accessible to the user running the script.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The code directly uses user-provided paths without any sanitization or validation before using them in file operations.
- Missing Mitigations:
    - Input Sanitization: Implement sanitization of user-provided file paths to prevent path traversal. This could involve:
        - Validating that the provided path does not contain path traversal sequences like `../` or `..\\`.
        - Using `os.path.abspath` to resolve the path and then verifying that the resolved path is within an expected base directory (e.g., the project's checkpoint directory).
    - Input Validation: Implement strict input validation to ensure that the provided paths conform to expected patterns and formats, further reducing the risk of malicious path manipulation.
- Preconditions:
    - An attacker must be able to influence the command-line arguments passed to the Python training or testing scripts (`classification/run.py`, `detection/run.py`). This could be achieved by:
        - Social engineering: Persuading a user to execute a script with attacker-controlled arguments.
        - Supply chain attack: Compromising a script or configuration file that invokes these training/testing scripts, allowing modification of the arguments.
- Source Code Analysis:
    - File: `/code/detection/model.py`
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
    - File: `/code/classification/model.py`
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

- Security Test Case:
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