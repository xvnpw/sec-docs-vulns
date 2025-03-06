- **Vulnerability Name:** Insecure Deserialization in Checkpoint Loading
- **Description:**
    - The application utilizes `pytorch_lightning`'s `load_from_checkpoint` function to load model checkpoints from disk.
    - This function internally uses `torch.load` for deserialization of checkpoint files.
    - `torch.load` is known to be vulnerable to insecure deserialization, as it can execute arbitrary code during the deserialization process if the input data is maliciously crafted.
    - An attacker can create a malicious checkpoint file containing embedded malicious code.
    - If a user is tricked into using this malicious checkpoint file with the project's scripts (e.g., for testing or training), `torch.load` will deserialize the file and execute the attacker's embedded code.
- **Impact:**
    - Arbitrary code execution on the user's system.
    - This could lead to complete system compromise, including data theft, malware installation, or further propagation of attacks.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    - None. The project does not implement any specific mitigations against insecure deserialization during checkpoint loading.
- **Missing Mitigations:**
    - **Secure Checkpoint Loading:** Implement a secure mechanism for loading checkpoints. This could involve:
        - Using `torch.load` with `map_location='cpu'` to mitigate GPU-related exploits, although this does not fully prevent insecure deserialization.
        - Manually loading the state dictionary from the checkpoint file after verifying its integrity and authenticity.
        - Exploring alternative serialization methods that are not vulnerable to arbitrary code execution, if feasible within the `pytorch_lightning` framework.
    - **User Warnings:** Display clear warnings to users about the security risks of loading checkpoints from untrusted sources. This should be highlighted in the documentation and potentially during runtime when a checkpoint is loaded.
    - **Checkpoint Integrity Verification:** Provide guidance and tools for users to verify the integrity and authenticity of checkpoint files before loading them. This could involve suggesting the use of cryptographic signatures or checksums for checkpoints.
- **Preconditions:**
    - The victim must download and attempt to use a maliciously crafted checkpoint file provided by an attacker.
    - The victim must execute one of the project's scripts (`test.py`, `matrix_plugin.py`, `mtc_model.py`, `predict.py`, `benchmark.py`, or `lm_pretrain.py`) that loads the checkpoint file using `pytorch_lightning`'s `load_from_checkpoint` function.
- **Source Code Analysis:**
    - The following files and lines of code are vulnerable because they use `pytorch_lightning`'s `load_from_checkpoint` which relies on `torch.load`:
        - `/code/test.py`: Line 68: `model = Generation.load_from_checkpoint(ckpt).cuda()`
        - `/code/matrix_plugin.py`: Line 120: `test_model = MatrixDecoder.load_from_checkpoint(ckpt_path, model=matrix).cuda().eval()`
        - `/code/matrix_plugin.py`: Line 248: `test_model = MatrixDecoder.load_from_checkpoint(ckpt, model=matrix).cuda().eval()`
        - `/code/mtc_model.py`: Line 440: `model = Seq2Seq.load_from_checkpoint(config['ckpt'])`
        - `/code/predict.py`: Line 70: `model = Generation.load_from_checkpoint(ckpt or get_latest_ckpt()).cuda()`
        - `/code/benchmark.py`: Line 62: `model = Generation.load_from_checkpoint(ckpt).cuda().eval()`
        - `/code/generation.py`: Line 32: `class Generation(Seq2Seq, GenerationMixin):` inherits from `Seq2Seq` which can use `load_from_checkpoint`.
        - `/code/lm_pretrain.py`: Implicitly through usage of `Seq2Seq`, although not directly loading in the provided `lm_pretrain.py` script itself, the model definition is vulnerable if checkpoints are loaded elsewhere.
    - `pytorch_lightning`'s `load_from_checkpoint` function, by default, utilizes `torch.load` to load the checkpoint file.
    - `torch.load` deserializes Python objects from the file using `pickle` or `pickle5` modules in more recent versions of PyTorch. These deserialization processes are inherently unsafe when dealing with untrusted data because they can be exploited to execute arbitrary code.
    - When a script calls `load_from_checkpoint` with a path to a malicious checkpoint file, `torch.load` will be invoked, and if the checkpoint is crafted to include malicious serialized objects, code execution will occur during the loading process, before the model is even used.
- **Security Test Case:**
    1. **Malicious Checkpoint Creation (`malicious_ckpt_gen.py`):**
        ```python
        import torch
        import subprocess
        import pickle

        class MaliciousCheckpoint:
            def __reduce__(self):
                return (subprocess.Popen, (('echo', 'зломано'),)) # Executes 'echo зломано' command

        malicious_ckpt = MaliciousCheckpoint()
        checkpoint_data = {'state_dict': malicious_ckpt, 'hparams': {'model': 'bert-base-cased'}} # Include hparams to mimic real checkpoint
        torch.save(checkpoint_data, 'malicious_checkpoint.ckpt')
        ```
        - Save the above code as `malicious_ckpt_gen.py`.
        - Run `python malicious_ckpt_gen.py` to generate `malicious_checkpoint.ckpt`. This script creates a checkpoint file that, when loaded, will attempt to execute the command `echo зломано`.

    2. **Victim Execution:**
        - Assume the attacker distributes `malicious_checkpoint.ckpt` (e.g., via a compromised website or email).
        - The victim downloads `malicious_checkpoint.ckpt` and places it in the project directory.
        - The victim executes the `test.py` script, pointing it to the malicious checkpoint:
        ```bash
        python test.py --ckpt malicious_checkpoint.ckpt
        ```

    3. **Verification of Code Execution:**
        - After running the `test.py` command with the malicious checkpoint, observe the console output.
        - If the vulnerability is successfully exploited, the output "зломано" (or equivalent depending on system and command) will be printed to the console, indicating arbitrary code execution.
        - Note: The exact output and success might depend on the environment and permissions. A more robust test might involve a command that creates a file or performs a network request to definitively prove code execution. However, for demonstration purposes, `echo` is sufficient.