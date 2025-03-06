- Vulnerability Name: Insecure Deserialization via Pickle Files

- Description:
    1. The project uses `torch.load` function from PyTorch to load pre-trained model weights. This function, by default, deserializes Python objects from pickle files.
    2. The application allows users to specify the path to pre-trained model files through command-line arguments `--load_pretrained_extractor` and `--load_pretrained_memory` in scripts `train_attr_pred.py`, `train_attr_manip.py`, and `eval.py`.
    3. A malicious actor can create a specially crafted pickle file containing malicious Python code.
    4. The attacker can replace legitimate pre-trained model files (e.g., in the `models` directory or any user-specified path) with their malicious pickle file.
    5. When a user, either unknowingly uses the replaced file or is tricked into specifying the path to the malicious file via command-line arguments, the `torch.load` function will execute the malicious code during deserialization.
    6. This allows the attacker to achieve arbitrary code execution on the user's machine with the privileges of the user running the script.

- Impact:
    - Arbitrary code execution on the machine running the training or evaluation scripts.
    - Potential compromise of the user's system and data.
    - Complete control over the application's execution environment.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - None. The code directly uses `torch.load` without any checks or security measures on the loaded files.
    - The `README.md` mentions that pretrained model weights are provided under the `models` directory and are downloaded via git-lfs. This suggests an intended source of trusted models, but does not technically prevent loading of malicious pickles if a user replaces these files or provides a different path.
    - The `CONTRIBUTING.md` provides a link to report security vulnerabilities to AWS/Amazon Security, which is a reactive measure, not a proactive mitigation.

- Missing Mitigations:
    - **Input validation:** The application should validate the source and integrity of the files loaded via `--load_pretrained_extractor` and `--load_pretrained_memory`. However, due to the nature of pickle deserialization vulnerabilities, input validation of the filename alone is insufficient to prevent the attack.
    - **Secure deserialization:**  Ideally, the application should avoid using `torch.load` with pickle for loading pre-trained models from potentially untrusted sources. If pickle is necessary, consider using `torch.load` with `pickle_module=safepickle` or a similar safer pickle loading library, although the security of `safepickle` itself might also be debated.  A better approach would be to explore alternative serialization formats that are not susceptible to arbitrary code execution during deserialization, if feasible for PyTorch model weights.
    - **Warning to users:**  The documentation should include a prominent warning about the security risks of loading pre-trained models from untrusted sources and advise users to only use models from trusted origins.

- Preconditions:
    1. The attacker needs to create a malicious pickle file that exploits the insecure deserialization vulnerability in `torch.load`.
    2. The attacker needs to make the user load this malicious pickle file. This could be achieved by:
        - Replacing the legitimate pre-trained model files in the `models` directory or any other location where the user might expect to find models.
        - Tricking the user into downloading and using a malicious model file from an untrusted source.
        - Socially engineering the user to provide a path to the malicious file via the `--load_pretrained_extractor` or `--load_pretrained_memory` command-line arguments.

- Source Code Analysis:
    - **File: `/code/src/train_attr_pred.py`**
        ```python
        if args.load_pretrained_extractor:
            print('load %s\n' % args.load_pretrained_extractor)
            model.load_state_dict(torch.load(args.load_pretrained_extractor))
        else:
            print('Pretrained extractor not provided. Use --load_pretrained_extractor or the model will be randomly initialized.')
        ```
        - The code checks if the `--load_pretrained_extractor` argument is provided. If it is, it directly passes the user-supplied path (`args.load_pretrained_extractor`) to `torch.load()`.
        - `torch.load()` will attempt to deserialize the file pointed to by this path using pickle, which is vulnerable to code execution if the file is malicious.

    - **File: `/code/src/train_attr_manip.py`**
        ```python
        if args.load_pretrained_extractor:
            print('load %s\n' % args.load_pretrained_extractor)
            model.load_state_dict(torch.load(args.load_pretrained_extractor))
        else:
            print('Pretrained extractor not provided. Use --load_pretrained_extractor or the model will be randomly initialized.')
        if args.load_pretrained_memory:
            print('load %s\n' % args.load_pretrained_memory)
            memory.load_state_dict(torch.load(args.load_pretrained_memory))
        else:
            print('Pretrained memory not provided. Use --load_pretrained_memory or the model will be randomly initialized.')
        ```
        - Similar to `train_attr_pred.py`, this script uses `torch.load()` with paths provided by `--load_pretrained_extractor` and `--load_pretrained_memory` arguments, making it vulnerable.

    - **File: `/code/src/eval.py`**
        ```python
        if args.load_pretrained_extractor:
            print('load {path} \n'.format(path=args.load_pretrained_extractor))
            model.load_state_dict(torch.load(args.load_pretrained_extractor))
        else:
            print('Pretrained extractor not provided. Use --load_pretrained_extractor or the model will be randomly initialized.')
        if args.load_pretrained_memory:
            print('load {path} \n'.format(path=args.load_pretrained_memory))
            memory.load_state_dict(torch.load(args.load_pretrained_memory))
        else:
            print('Pretrained memory not provided. Use --load_pretrained_memory or the model will be randomly initialized.')
        ```
        - The `eval.py` script also uses `torch.load()` in the same insecure manner, using paths from `--load_pretrained_extractor` and `--load_pretrained_memory`.

- Security Test Case:
    1. **Create a malicious pickle file:**
        ```python
        import torch
        import os

        class MaliciousPayload(object):
            def __reduce__(self):
                return (os.system, ('touch /tmp/pwned',)) # Command to execute: create a file /tmp/pwned

        payload = MaliciousPayload()
        torch.save(payload, 'malicious.pkl')
        ```
        - This Python script creates a `malicious.pkl` file. When this file is deserialized by `torch.load`, it will execute the `touch /tmp/pwned` command on a Linux-like system, creating an empty file named `pwned` in the `/tmp` directory. On Windows, you could use a command like `os.system('type nul > C:\\temp\\pwned')`.

    2. **Run `train_attr_pred.py` (or `train_attr_manip.py` or `eval.py`) and load the malicious pickle file:**
        ```bash
        export DATASET_PATH="/path/to/dataset/folder/that/contain/img/subfolder" # Replace with a valid dataset path, even if it's dummy data for testing.
        export FILE_ROOT="/path/to/splits/folder" # Replace with a valid splits folder path, even if dummy data.
        python src/train_attr_pred.py --dataset_name Shopping100k --file_root ${FILE_ROOT} --img_root ${DATASET_PATH} --load_pretrained_extractor malicious.pkl
        ```
        - Replace `/path/to/dataset/folder/that/contain/img/subfolder` and `/path/to/splits/folder` with actual paths or create dummy folders and files to satisfy the script's requirements. The important part is to provide `malicious.pkl` as the `--load_pretrained_extractor` argument.

    3. **Check for successful code execution:**
        - After running the command, check if the file `/tmp/pwned` (or `C:\\temp\\pwned` on Windows if you adapted the payload) has been created.
        - If the file exists, it confirms that the malicious code within `malicious.pkl` was executed when `torch.load` deserialized it, proving the insecure deserialization vulnerability.

This test case demonstrates that loading a pickle file via the `--load_pretrained_extractor` argument allows for arbitrary code execution, confirming the insecure deserialization vulnerability. The same test can be adapted for `--load_pretrained_memory` in `train_attr_manip.py` and `eval.py`.