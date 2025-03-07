* Vulnerability Name: Path Traversal in Checkpoint Loading
* Description:
    1. The `detection/run.py` and `classification/run.py` scripts accept user-provided paths for loading checkpoints via arguments like `--load_ckpt_path` and `--visual_encoder_ckpt_path`.
    2. These paths are directly passed to the `model.load()` function without sufficient validation or sanitization.
    3. In `model.py`, the `load()` function in both `BaseModel` for detection and classification uses `os.path.join(ckpt_path, 'embed_{}.pth'.format(epoch))` to construct the checkpoint file path.
    4. If a malicious user provides a crafted path like `../../../../malicious_ckpt` as `--load_ckpt_path`, the `os.path.join` will resolve to a path outside the intended checkpoint directory.
    5. When `torch.load(path)` is called with this manipulated path, it will attempt to load a checkpoint from an arbitrary location on the file system, potentially leading to reading sensitive files if the user running the script has the necessary permissions.
* Impact:
    An attacker could potentially read arbitrary files from the server's filesystem by exploiting the path traversal vulnerability in the checkpoint loading mechanism. This is possible if the user running the training or testing scripts provides a maliciously crafted `--load_ckpt_path` argument. Sensitive information such as configuration files, private keys, or other application data could be exposed.
* Vulnerability Rank: High
* Currently Implemented Mitigations:
    None. The code directly uses user-provided paths without validation.
* Missing Mitigations:
    Input validation and sanitization for all file path arguments (`--ckpt_path`, `--load_ckpt_path`, `--visual_encoder_ckpt_path`, `--dset_path`). Specifically, for checkpoint loading, the provided path should be validated to be within the expected checkpoint directory and prevent directory traversal. Using absolute paths and ensuring that user-provided paths are resolved relative to a safe base directory would be effective mitigations.
* Preconditions:
    1. The attacker needs to be able to execute either `detection/run.py` or `classification/run.py`.
    2. The attacker must be able to provide command-line arguments to these scripts, specifically the checkpoint path arguments.
* Source Code Analysis:
    * **File: `/code/detection/run.py` and `/code/classification/run.py`**
        These scripts use `argparse` to handle command-line arguments, including `--load_ckpt_path` and `--visual_encoder_ckpt_path`. These arguments are directly passed to the model's `load` function. No validation or sanitization is performed on these paths in the `run.py` scripts.
    * **File: `/code/detection/model.py` and `/code/classification/model.py`**
        ```python
        def load(self, load_ckpt_paths, options, epoch=200): # detection/model.py
        def load(self, load_ckpt_paths, epoch=200): # classification/model.py
            ...
            for i in range(len(self.embeds)): # detection/model.py
            for i, ckpt_path in enumerate(load_ckpt_paths): # classification/model.py
              ckpt_path = load_ckpt_paths[i] # detection/model.py - inside loop
              if len(ckpt_path) > 0:
                path = os.path.join(ckpt_path, 'embed_{}.pth'.format(epoch))
                ckpt = torch.load(path)
                try:
                  self.embeds[i].load_state_dict(ckpt)
                except:
                  utils.warn('Check that the "modalities" argument is correct.')
                  exit(0)
                utils.info('{}: ckpt {} loaded'.format(self.modalities[i], path))
        ```
        The `load` functions in `detection/model.py` and `classification/model.py` directly use `os.path.join(ckpt_path, 'embed_{}.pth'.format(epoch))` to construct the full path. The `ckpt_path` variable comes directly from the `--load_ckpt_path` or `--visual_encoder_ckpt_path` arguments without any checks. This allows path traversal.

* Security Test Case:
    1.  Assume the project is set up and the user can run the `detection/run.py` script.
    2.  Craft a malicious path payload: `../../../../tmp`
    3.  Execute the `detection/run.py` script with the crafted payload for `--load_ckpt_path`:
        ```bash
        python -m detection.run --gpus 0 --split test --dset pku-mmd --load_ckpt_path '../../../../tmp' --modalities depth
        ```
    4.  Create a dummy file named `embed_200.pth` in the `/tmp` directory on the server:
        ```bash
        mkdir /tmp
        touch /tmp/embed_200.pth
        ```
    5.  Run the command from step 3. If the script attempts to load `/tmp/embed_200.pth` without errors related to path resolution, it indicates a path traversal vulnerability.  A successful exploit will attempt to load the dummy checkpoint from `/tmp` instead of the intended checkpoint directory.  To verify file read, you could place sensitive data into `/tmp/embed_200.pth` (as text) and check if the error message changes or if the script behaves differently, indicating it tried to process the content of `/tmp/embed_200.pth`. A more robust test would be to modify the code temporarily to print the resolved `path` variable before `torch.load(path)`.