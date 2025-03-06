### Vulnerability List

- Vulnerability Name: Deserialization of Untrusted Data in Model Checkpoint Loading
- Description:
    - The project utilizes the `torch.load` function in PyTorch to load model checkpoints from disk.
    - By default, `torch.load` relies on Python's `pickle` module for deserialization, which is known to be vulnerable when handling data from untrusted sources.
    - A malicious actor can craft a manipulated model checkpoint file.
    - When a user loads this malicious checkpoint file using `torch.load`, it can lead to arbitrary code execution on the user's system.
    - This is possible because `pickle` can deserialize arbitrary Python objects, including those that execute system commands or other malicious actions.
- Impact:
    - Critical. Successful exploitation allows for arbitrary code execution on the system of the user loading the malicious model checkpoint.
    - This could lead to a complete compromise of the user's machine, including data theft, malware installation, or unauthorized access.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None. The codebase directly uses `torch.load` to load checkpoint files without any form of security validation or sanitization.
- Missing Mitigations:
    - **Input Validation and Origin Verification:** Implement checks to validate the integrity and authenticity of model checkpoint files before loading. This could include:
        - Using checksums or digital signatures to verify that the checkpoint file has not been tampered with and originates from a trusted source.
    - **Secure Deserialization Practices:**
        - Utilize `torch.load` with the `pickle_module=None` option. This restricts `torch.load` to only loading state dictionaries and prevents the execution of arbitrary code through `pickle`. However, this might not be compatible with all checkpoints if they rely on pickling other data beyond state dictionaries.
        - Explore using `torch.serialization.safeload` if available in the PyTorch version, as a potentially safer alternative to `torch.load`.
        - Consider migrating to a more secure serialization format, such as `safetensors`, which is designed to be safe for loading untrusted model weights.
    - **Sandboxing or Isolation:**
        - Isolate the model loading and inference processes within a sandboxed environment. This would limit the permissions and system access available to the process, reducing the potential damage from successful code execution.
    - **User Security Awareness:**
        - Provide clear warnings and documentation to users about the security risks associated with loading model checkpoints from untrusted or unknown sources. Emphasize the importance of only using checkpoints from verified and trusted providers.
- Preconditions:
    - A user must download and attempt to load a maliciously crafted model checkpoint file.
    - The malicious checkpoint file needs to be accessible to the application, typically by being placed in the expected checkpoint directory or by providing its path as a command-line argument.
- Source Code Analysis:
    - Vulnerability is present in multiple files where model checkpoints are loaded:
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

    - In all these instances, `torch.load` is directly used to load checkpoint files specified by a path, without any prior validation or security measures. The subsequent use of `load_state_dict` does not mitigate the initial risk introduced by `torch.load` as arbitrary code execution can occur during the `torch.load` call itself before `load_state_dict` is reached.

- Security Test Case:
    1.  Create a malicious PyTorch checkpoint file named `malicious_checkpoint.pt` using the following Python script:
        ```python
        import torch
        import os

        class MaliciousPayload:
            def __reduce__(self):
                return (os.system, ('touch /tmp/pwned',))

        torch.save({'model': MaliciousPayload()}, 'malicious_checkpoint.pt')
        ```
    2.  Identify a checkpoint file path used by one of the scripts, for example, in `/code/mt_sample.py`, the `checkpoint` argument in `load_model` function. Let's assume the script is configured to load `pixelsnail_vqvae_imagenet_num_embeddings[512]_neighborhood[1]_selectionFN[vanilla]_size[128]_bottom_420.pt` from the `checkpoint` directory.
    3.  Replace the legitimate checkpoint file (if it exists) in the `checkpoint` directory with the `malicious_checkpoint.pt` file, renaming `malicious_checkpoint.pt` to `pixelsnail_vqvae_imagenet_num_embeddings[512]_neighborhood[1]_selectionFN[vanilla]_size[128]_bottom_420.pt`.
    4.  Run the `mt_sample.py` script (or any other script that loads a model). For example:
        ```bash
        python mt_sample.py --pixelsnail_ckpt_epoch 420 --ckpt_epoch 200 --dataset imagenet --architecture vqvae --num_embeddings 512 --neighborhood 1 --selection_fn vanilla --size 128 --hier bottom --device cuda
        ```
    5.  After running the script, check for the existence of the file `/tmp/pwned`. If the file `/tmp/pwned` exists, it indicates that the malicious code within `malicious_checkpoint.pt` was successfully executed when `torch.load` was called, confirming the vulnerability.