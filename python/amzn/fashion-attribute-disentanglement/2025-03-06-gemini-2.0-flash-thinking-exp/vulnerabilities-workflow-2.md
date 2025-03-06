## Combined Vulnerability List

### 1. Path Traversal in Image Loading

- **Description:**
    The application is vulnerable to path traversal in image loading due to insecure handling of file paths provided through command-line arguments and read from configuration files.
    1. The application accepts `--file_root` and `--img_root` command-line arguments to specify directories for pre-processed files and raw images respectively.
    2. The `dataloader.py` scripts utilize these paths to load image file names from files located within `--file_root` (e.g., `imgs_train.txt`, `imgs_test.txt`).
    3. When loading images, the code uses `os.path.join(img_root_path, path)` where `img_root_path` is derived from `--img_root` and `path` is read from files within `--file_root`.
    4. An attacker who can control the content of files in `--file_root` (e.g., by providing a crafted `imgs_train.txt` file) and the application uses a user-provided or attacker-controlled `--file_root` and `--img_root` without validation, can inject path traversal sequences (e.g., `../../`) into the image paths within `imgs_train.txt`.
    5. Consequently, when the application attempts to load these images, `os.path.join` resolves the path traversal sequences, potentially granting access to files outside the intended `img_root_path`.

- **Impact:**
    Successful exploitation of this vulnerability allows an attacker to read arbitrary files from the server's filesystem. This information disclosure can expose sensitive data, including source code, configuration files, and potentially credentials or other confidential information.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:** None

- **Missing Mitigations:**
    - Implement input validation for both `--file_root` and `--img_root` command-line arguments. This validation should ensure that the provided paths are valid, safe, and within expected boundaries.
    - Sanitize image paths read from files within `--file_root`. This sanitization process should remove or neutralize any path traversal sequences before these paths are used in `os.path.join`.

- **Preconditions:**
    - The attacker must be able to provide or influence the content of files within the directory specified by the `--file_root` argument. For example, if the application processes files provided by a user or fetched from an untrusted source.
    - The application must be deployed in a configuration where it processes user-provided or untrusted `--file_root` and `--img_root` arguments without proper validation.

- **Source Code Analysis:**
    - In `/code/src/argument_parser.py`, the `add_base_args` function defines `--file_root` and `--img_root` using `parser.add_argument(...)`.
    - In `/code/src/dataloader.py`, the classes `Data`, `DataQuery`, and `DataTriplet` accept `file_root` and `img_root_path` as arguments in their `__init__` methods.
    - Within `/code/src/dataloader.py`, the `_load_dataset` methods in these classes read image file names from files within `file_root` using `os.path.join(self.file_root, "imgs_%s.txt" % self.mode)`.
    ```python
    with open(os.path.join(self.file_root, "imgs_%s.txt" % self.mode)) as f:
        img_data = f.read().splitlines()
    ```
    - In `/code/src/dataloader.py`, the `__getitem__` methods in these classes use `os.path.join(self.img_root_path, self.img_data[index])` to open image files.
    ```python
    img = Image.open(os.path.join(self.img_root_path, self.img_data[index]))
    ```
    - Critically, there is no validation or sanitization performed on `file_root`, `img_root_path`, or `self.img_data[index]` before they are used in `os.path.join`, leading to the path traversal vulnerability.

- **Security Test Case:**
    1. Create a malicious `imgs_train.txt` file within a directory, for example `/tmp/malicious_files`. This file should contain a path traversal string like `../../../../../../../../etc/passwd`.
    2. Create a dummy image file (e.g., `dummy.jpg`) and place it in a separate directory, for example `/tmp/images`.
    3. Execute a training script, such as `train_attr_pred.py`, with the following command-line arguments:
    ```bash
    python src/train_attr_pred.py --file_root /tmp/malicious_files --img_root /tmp/images --dataset_name Shopping100k --ckpt_dir test_output
    ```
    4. Monitor the output and logs for error messages related to accessing system files like `/etc/passwd`. If the vulnerability is present, the application will attempt to access `/etc/passwd`, and you might observe an `IOError: [Errno 13] Permission denied: /etc/passwd` error if run as a non-root user, indicating a successful path traversal attempt.

### 2. Insecure Deserialization via Pickle Files

- **Description:**
    The application is susceptible to insecure deserialization vulnerabilities due to its use of `torch.load()` with pickle files for loading pre-trained model weights. This function, by default, utilizes Python's `pickle` module, which is known to be unsafe when handling data from untrusted sources because it can execute arbitrary code during deserialization.
    1. The application uses `torch.load` to load pre-trained model weights from files specified via the command-line arguments `--load_pretrained_extractor` and `--load_pretrained_memory` in scripts such as `train_attr_pred.py`, `train_attr_manip.py`, and `eval.py`.
    2. An attacker can craft a malicious pickle file containing embedded Python code.
    3. The attacker can then replace legitimate pre-trained model files (e.g., located in the `models` directory or any user-specified path) with this malicious pickle file. Alternatively, the attacker could trick a user into providing a path to the malicious file.
    4. When a user executes one of the vulnerable scripts and loads the malicious model file using the `--load_pretrained_extractor` or `--load_pretrained_memory` arguments, `torch.load` will deserialize the file, and the embedded malicious Python code will be executed on the user's machine with the privileges of the user running the script.
    5. This insecure deserialization can lead to arbitrary code execution, allowing the attacker to compromise the user's system.

- **Impact:**
    Successful exploitation of this vulnerability results in **critical** impact, allowing for arbitrary code execution on the machine running the training or evaluation scripts. This can lead to:
    - Full control over the user's system.
    - Theft of sensitive data, including training datasets, personal files, and credentials.
    - Installation of malware, backdoors, or ransomware.
    - Unauthorized access to other systems and networks accessible from the compromised machine.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    None. The application directly uses `torch.load()` to load model files without any input validation, integrity checks, or security warnings regarding the potential risks of loading untrusted model files.

- **Missing Mitigations:**
    - **Secure Deserialization:** Replace the usage of `torch.load()` with pickle for loading model weights, especially when dealing with potentially untrusted sources. Consider safer alternatives such as:
        - **`torch.jit.load()` for TorchScript models:** If feasible, convert models to TorchScript format and use `torch.jit.load()`, which is designed to be safer.
        - **`safetensors` library:** Adopt the `safetensors` library for serializing and deserializing tensors. `safetensors` is specifically designed to mitigate pickle deserialization vulnerabilities in machine learning model loading.
        - **Manual `state_dict` loading from safer formats:** Save model weights in a safer format like JSON or binary formats without pickle and implement manual loading of the `state_dict`.
    - **User Warnings:** Implement clear warnings in the documentation and `README.md` about the security risks associated with loading pre-trained models from untrusted sources. Advise users to only download and use models from official and verified sources, and to verify the integrity of downloaded models if possible (e.g., using cryptographic signatures).

- **Preconditions:**
    1. The attacker must be able to create a malicious pickle file that exploits the insecure deserialization vulnerability.
    2. The attacker needs to make the user load this malicious pickle file. This can be achieved by:
        - Replacing legitimate pre-trained model files in locations where the user might expect to find them.
        - Tricking the user into downloading and using a malicious model file from an untrusted source, potentially through social engineering.
        - Socially engineering the user into providing a path to the malicious file via the `--load_pretrained_extractor` or `--load_pretrained_memory` command-line arguments.

- **Source Code Analysis:**
    - The following files are vulnerable because they use `torch.load()` to load pretrained models from user-provided paths:
        - `/code/src/train_attr_pred.py`
        - `/code/src/train_attr_manip.py`
        - `/code/src/eval.py`

    - **Example from `/code/src/train_attr_pred.py`:**
        ```python
        if args.load_pretrained_extractor:
            print('load %s\n' % args.load_pretrained_extractor)
            model.load_state_dict(torch.load(args.load_pretrained_extractor))
        ```
        - The code directly passes the user-controlled path from `args.load_pretrained_extractor` to `torch.load()`.
        - `torch.load()` uses `pickle` by default, and if the provided file is a malicious pickle, arbitrary code execution will occur during deserialization.
        - Similar vulnerable code patterns exist in `train_attr_manip.py` and `eval.py` for both `--load_pretrained_extractor` and `--load_pretrained_memory` arguments.

- **Security Test Case:**
    1. **Create a malicious pickle file (`malicious.pkl`)**:
        ```python
        import torch
        import os
        import pickle

        class MaliciousPayload(object):
            def __reduce__(self):
                return (os.system, ('touch /tmp/pwned.txt',)) # Example command: create /tmp/pwned.txt

        payload = MaliciousPayload()
        torch.save(payload, 'malicious.pkl')
        ```
        This script creates a `malicious.pkl` file that, when loaded, will execute the command `touch /tmp/pwned.txt` on a Linux-like system.

    2. **Run `train_attr_pred.py` and load the malicious pickle file**:
        ```bash
        export DATASET_PATH="/path/to/dataset/folder/that/contain/img/subfolder" # Replace with a valid dataset path, even dummy data
        export FILE_ROOT="/path/to/splits/folder" # Replace with a valid splits folder path, even dummy data
        python src/train_attr_pred.py --dataset_name Shopping100k --file_root ${FILE_ROOT} --img_root ${DATASET_PATH} --load_pretrained_extractor malicious.pkl
        ```
        Replace `/path/to/dataset/folder/that/contain/img/subfolder` and `/path/to/splits/folder` with actual or dummy paths to satisfy script requirements.

    3. **Verify code execution**:
        - After running the script, check if the file `/tmp/pwned.txt` has been created:
        ```bash
        ls /tmp/pwned.txt
        ```
        - If the file exists, it confirms that the malicious code within `malicious.pkl` was executed during deserialization by `torch.load()`, demonstrating the insecure deserialization vulnerability.