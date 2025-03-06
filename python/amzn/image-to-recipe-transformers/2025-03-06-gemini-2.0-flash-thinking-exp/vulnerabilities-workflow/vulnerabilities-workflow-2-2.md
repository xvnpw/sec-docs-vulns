- vulnerability name: Insecure Deserialization in Model Checkpoint Loading
- description: The application loads model checkpoints and training arguments from disk using `torch.load` and `pickle.load` in the `load_checkpoint` function within `/code/src/utils/utils.py`. These functions are vulnerable to insecure deserialization. A malicious actor could craft a malicious checkpoint file (`model-best.ckpt`, `model-curr.ckpt`) or arguments file (`args.pkl`) and replace the legitimate files in the checkpoint directory. When a user downloads and uses this malicious checkpoint (either pretrained or to resume training), arbitrary code embedded within the checkpoint file will be executed on their machine during the model loading process. The vulnerability can be triggered when `train.py` or `test.py` scripts are executed, as they both utilize the `load_checkpoint` function to load model states and configurations.
- impact: Arbitrary code execution on the user's machine. Successful exploitation could allow an attacker to gain full control over the user's system, potentially leading to data theft, malware installation, or further unauthorized activities.
- vulnerability rank: critical
- currently implemented mitigations: None. The project does not implement any specific measures to prevent insecure deserialization when loading model checkpoints.
- missing mitigations:
    - Input Validation: Implement integrity checks to verify the authenticity and integrity of checkpoint files before loading. This could include cryptographic signatures to ensure that the files originate from a trusted source and haven't been tampered with. However, this is complex to implement properly and doesn't fundamentally solve the deserialization issue.
    - Secure Deserialization: Migrate away from `pickle` for loading arguments and, if possible, for model states. For `torch.load`, consider using `torch.load(..., weights_only=True)` when loading model weights if applicable and if the PyTorch version is >= 1.12.0. For general data serialization, explore safer alternatives to `pickle` such as `safetensors` or JSON for configurations, ensuring that data is treated as data and not executable code during loading.
    - User Warnings: Provide prominent warnings in the documentation (e.g., README, usage instructions) about the security risks associated with downloading and using pre-trained models from untrusted sources. Advise users to only utilize checkpoints from verified and reputable sources.
- preconditions:
    - The user must download and attempt to use a maliciously crafted model checkpoint file (`model-best.ckpt`, `model-curr.ckpt`) or arguments file (`args.pkl`).
    - The malicious file must be placed in the directory where the application expects to find checkpoints, typically within the path specified by `--save_dir` and `--model_name` arguments, potentially overwriting or replacing legitimate checkpoint files.
- source code analysis:
    - The vulnerability exists in the `/code/src/utils/utils.py` file within the `load_checkpoint` function.
    - Step-by-step code analysis:
        1. The `load_checkpoint` function is called in `train.py` and `test.py` to load model checkpoints.
        2. Inside `load_checkpoint`, `torch.load` is used to load `model_state_dict` from `model-*.ckpt` files:
        ```python
        model_state_dict = torch.load(os.path.join(checkpoints_dir, 'model-'+suff+'.ckpt'), map_location=map_loc)
        ```
        `torch.load` with default settings (using `pickle` module) is vulnerable to insecure deserialization. If a malicious `model-*.ckpt` file is provided, it can execute arbitrary code during loading.
        3. Similarly, `torch.load` is used to load optimizer state from `optim-*.ckpt` files:
        ```python
        opt_state_dict = torch.load(os.path.join(checkpoints_dir, 'optim-'+suff+'.ckpt'), map_location=map_loc)
        ```
        This is also vulnerable to insecure deserialization if a malicious `optim-*.ckpt` file is provided.
        4. `pickle.load` is used to load training arguments from `args.pkl` file:
        ```python
        args = pickle.load(open(os.path.join(checkpoints_dir, 'args.pkl'), 'rb'))
        ```
        `pickle.load` is inherently insecure and can execute arbitrary code if a malicious `args.pkl` file is loaded.
    - Visualization: The attack flow is as follows:
        ```
        Attacker crafts malicious checkpoint files (model-*.ckpt, optim-*.ckpt, args.pkl)
        -> Attacker replaces legitimate checkpoint files in the repository or distribution
        -> User downloads the project and potentially the malicious checkpoints (e.g., via `git lfs pull` for pretrained models) or uses a project that was already compromised.
        -> User runs train.py or test.py, which calls load_checkpoint
        -> load_checkpoint uses torch.load and pickle.load to load the malicious files
        -> Insecure deserialization in torch.load and pickle.load triggers arbitrary code execution on the user's machine.
        ```
- security test case:
    1. **Setup:** Ensure you have the project environment set up as described in the README.md.
    2. **Malicious Payload Creation:** Create a malicious `args.pkl` file. You can use the following Python code to generate a malicious `args.pkl` file that executes `touch /tmp/pwned` when loaded:
        ```python
        import pickle
        import argparse
        import os

        class MaliciousArgs:
            def __reduce__(self):
                return (os.system, ('touch /tmp/pwned',))

        # Create dummy args object to mimic the structure of original args.pkl
        parser = argparse.ArgumentParser()
        parser.add_argument('--dummy_arg', type=str, default='dummy_value')
        args = parser.parse_args([])
        args.__dict__.update({'dummy_arg': 'dummy_value', 'malicious_payload': MaliciousArgs()})

        with open('args.pkl', 'wb') as f:
            pickle.dump(args, f)
        ```
    3. **Replace `args.pkl`:** Navigate to the checkpoints directory of a model (e.g., if you are using the pretrained models, it would be `checkpoints/MODEL_NAME`). Replace the existing `args.pkl` file with the malicious `args.pkl` file created in the previous step.
    4. **Execute `test.py`:** Run the `test.py` script using a pretrained model name. For example:
        ```bash
        python src/test.py --model_name MODEL_NAME --eval_split test --root DATASET_PATH --save_dir ../checkpoints
        ```
        Replace `MODEL_NAME` with the name of the pretrained model you are testing and `DATASET_PATH` with the path to your Recipe1M dataset.
    5. **Verify Exploitation:** Check if the file `/tmp/pwned` has been created. If the file exists, it indicates that the malicious payload in `args.pkl` was executed during the model loading process, confirming the insecure deserialization vulnerability.
    6. **Cleanup:** Remove the `/tmp/pwned` file after testing.