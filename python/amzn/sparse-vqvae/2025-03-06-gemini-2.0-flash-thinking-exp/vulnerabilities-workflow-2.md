## Vulnerability List

### 1. Deserialization of Untrusted Data in Model Checkpoint Loading

*   **Vulnerability Name:** Deserialization of Untrusted Data in Model Checkpoint Loading
*   **Description:**
    - The project utilizes the `torch.load` function in PyTorch to load model checkpoints from disk. By default, `torch.load` relies on Python's `pickle` module for deserialization, which is known to be vulnerable when handling data from untrusted sources.
    - A malicious actor can craft a manipulated model checkpoint file containing malicious code.
    - When a user loads this malicious checkpoint file using `torch.load` through project scripts such as `sample.py`, `mt_sample.py`, `train_vqvae.py`, `train_pixelsnail.py`, `train_fista_pixelsnail.py`, `extract_code.py`, it can lead to arbitrary code execution on the user's system.
    - This is possible because `pickle` can deserialize arbitrary Python objects, including those that execute system commands or other malicious actions. The vulnerability can be triggered by loading a malicious checkpoint file through any script that uses the `load_model` function or directly loads checkpoints using `torch.load`.
    - An attacker can also supply a malicious checkpoint path as a command-line argument or configuration setting if exposed by the application, potentially leveraging path traversal techniques to load checkpoints from unexpected locations.

*   **Impact:**
    - Critical. Successful exploitation allows for arbitrary code execution on the system of the user loading the malicious model checkpoint.
    - This could lead to a complete compromise of the user's machine, including data theft, malware installation, or unauthorized access.
    - It can also lead to denial of service or other malicious actions depending on the attacker's payload.

*   **Vulnerability Rank:** Critical

*   **Currently Implemented Mitigations:**
    - None. The codebase directly uses `torch.load` to load checkpoint files without any form of security validation or sanitization in multiple scripts and functions.

*   **Missing Mitigations:**
    - **Input Validation and Origin Verification:** Implement checks to validate the integrity and authenticity of model checkpoint files before loading. This could include:
        - Using checksums or digital signatures to verify that the checkpoint file has not been tampered with and originates from a trusted source.
        - Implement validation for checkpoint file paths to ensure they conform to expected filename and path patterns, restricting potentially harmful characters or path traversal sequences.
        - Sanitize provided paths to prevent directory traversal exploits. Utilize functions like `os.path.basename` to extract only the filename and ensure the path remains within the designated `checkpoint` directory.
    - **Secure Deserialization Practices:**
        - Utilize `torch.load` with the `pickle_module=None` option. This restricts `torch.load` to only loading state dictionaries and prevents the execution of arbitrary code through `pickle`. However, this might not be compatible with all checkpoints if they rely on pickling other data beyond state dictionaries.
        - Explore using `torch.serialization.safeload` if available in the PyTorch version, as a potentially safer alternative to `torch.load`.
        - Consider migrating to a more secure serialization format, such as `safetensors`, which is designed to be safe for loading untrusted model weights and is recommended by PyTorch security guidelines. Using `torch.load` with `pickle_module=safetensors` if the safetensors library is suitable for the project's needs.
    - **Sandboxing or Isolation:**
        - Isolate the model loading and inference processes within a sandboxed environment. This would limit the permissions and system access available to the process, reducing the potential damage from successful code execution.
    - **User Security Awareness:**
        - Provide clear warnings and documentation to users about the security risks associated with loading model checkpoints from untrusted or unknown sources. Emphasize the importance of only using checkpoints from verified and trusted providers.
    - **Principle of Least Privilege:** Deploy the application with minimal necessary permissions to restrict the potential damage from code execution vulnerabilities.

*   **Preconditions:**
    - A user must download or otherwise obtain a maliciously crafted model checkpoint file from an untrusted source.
    - The malicious checkpoint file needs to be accessible to the application, typically by being placed in the expected checkpoint directory or by providing its path as a command-line argument.
    - The victim must execute one of the project's scripts that loads the checkpoint file using `torch.load`.
    - The attacker must be able to influence the `checkpoint` argument, typically through command-line arguments or configuration settings if exposed by the application.

*   **Source Code Analysis:**
    - Vulnerability is present in multiple files where model checkpoints are loaded, as `torch.load` is directly used without security measures:
        - File: `/code/mt_sample.py`
            - Function: `load_model`
            - Code Snippet: `ckpt = torch.load(os.path.join('checkpoint', checkpoint))`
        - File: `/code/sample.py`
            - Function: `load_model`
            - Code Snippet: `ckpt = torch.load(os.path.join('checkpoint', checkpoint))`
        - File: `/code/scripts/visualize_encodings.py`
            - Function: `create_run` -> `load_datasets` -> `load_model`
            - Code Snippet: `model.load_state_dict(torch.load(os.path.join('..', checkpoint_path)), strict=False)`
        - File: `/code/scripts/calculate_model_psnr.py`
            - Function: `get_PSNR`
            - Code Snippet: `model.load_state_dict(torch.load(os.path.join('..', checkpoint_path), map_location='cuda:0'), strict=False)`
        - File: `/code/train_fista_pixelsnail.py`
            - Function: `create_run` -> `prepare_model_parts`
            - Code Snippet: `ckpt = torch.load(args.pixelsnail_ckpt)` and `vqvae_model.load_state_dict(torch.load(os.path.join(checkpoint_path)), strict=False)`
        - File: `/code/train_pixelsnail.py`
            - Function: `create_run` -> `prepare_model_parts`
            - Code Snippet: `ckpt = torch.load(args.pixelsnail_ckpt)` and `vqvae_model.load_state_dict(torch.load(os.path.join(checkpoint_path)), strict=False)`
        - File: `/code/extract_code.py`
            - Function: `create_extraction_run`
            - Code Snippet: `model.load_state_dict(torch.load(checkpoint_path), strict=False)`

    - In `sample.py` (and similarly in `mt_sample.py`), the `load_model` function uses `torch.load(os.path.join('checkpoint', checkpoint))` to load model checkpoints. The `checkpoint` variable, derived directly from user input, is concatenated with 'checkpoint' using `os.path.join` and passed to `torch.load` without any validation or sanitization.
    - In all these instances, `torch.load` is directly used to load checkpoint files specified by a path, without any prior validation or security measures. The subsequent use of `load_state_dict` does not mitigate the initial risk introduced by `torch.load` as arbitrary code execution can occur during the `torch.load` call itself before `load_state_dict` is reached.

*   **Security Test Case:**
    1.  **Craft a malicious checkpoint file:**
        - Create a Python file (e.g., `malicious_payload.py`) with the following code to create a malicious payload:
          ```python
          import torch
          import pickle
          import os

          class MaliciousPayload:
              def __reduce__(self):
                  return (os.system, ('touch /tmp/pwned',)) # command to execute

          payload = MaliciousPayload()
          torch.save({'model': payload}, 'malicious_checkpoint.pt')
          ```
        - Run `python malicious_payload.py` to generate `malicious_checkpoint.pt`. This script creates a checkpoint that, when loaded, will execute the command `touch /tmp/pwned` on a Linux system, creating a file `/tmp/pwned` as proof of concept.
        - Alternatively, to demonstrate path manipulation, craft a checkpoint file named `malicious.pt` with similar malicious payload.
    2.  **Prepare the environment:**
        - Set up the SparseVQVAE project environment as described in the `README.md`.
        - Place the `malicious_checkpoint.pt` file in the `checkpoint/` directory of the project, or in a location that can be specified to the scripts (e.g., `/tmp/malicious.pt`).
    3.  **Run a vulnerable script with the malicious checkpoint:**
        - Execute `sample.py` (or any other script that loads a checkpoint, e.g., `mt_sample.py`, `train_vqvae.py`, `extract_code.py`) and point it to load the malicious checkpoint.
        - **Scenario 1: Replace legitimate checkpoint (for scripts using default checkpoint paths):** Replace the legitimate checkpoint file (if it exists) in the `checkpoint` directory with the `malicious_checkpoint.pt` file, renaming `malicious_checkpoint.pt` to the expected checkpoint filename (e.g., `pixelsnail_vqvae_imagenet_num_embeddings[512]_neighborhood[1]_selectionFN[vanilla]_size[128]_bottom_420.pt`).
        - **Scenario 2: Path manipulation (for scripts accepting checkpoint path as argument):** Execute the script providing the malicious checkpoint path via command-line argument. For example, in `sample.py`:
           ```bash
           python sample.py --pixelsnail_ckpt '/tmp/malicious.pt' --ckpt_epoch 1 --pixelsnail_ckpt_epoch 1 --dataset cifar10 --architecture vqvae --selection_fn vanilla
           ```
    4.  **Verify the exploit:**
        - After running the script, check if the file `/tmp/pwned` exists on the system. If the file exists, it confirms that the malicious code embedded in `malicious_checkpoint.pt` was executed when `torch.load` was called, demonstrating the deserialization vulnerability.
        - For path manipulation test, ensure the malicious code executes even when the checkpoint path is outside the expected `checkpoint` directory.