- **Vulnerability Name:** Pickle Deserialization Vulnerability in Model Loading
- **Description:**
    - The application loads pretrained model weights from pickle files using `torch.load()`.
    - An attacker can create a malicious pickle file containing arbitrary code.
    - By replacing legitimate pretrained model files (like `extractor_best.pkl` or `memory_best.pkl`) with these malicious files, or by tricking a user into specifying a path to a malicious file, the attacker can inject and execute arbitrary code on the user's machine when the application attempts to load the model using `torch.load()`.
    - This occurs because the `pickle` module in Python is inherently unsafe when loading data from untrusted sources, as it can execute arbitrary code during deserialization.
- **Impact:**
    - **Critical:** Successful exploitation of this vulnerability allows for arbitrary code execution on the machine running the training or evaluation scripts.
    - This can lead to a range of severe consequences, including:
        - **Data theft:**  An attacker could steal sensitive data accessible to the user running the script.
        - **Malware installation:** The attacker could install malware, backdoors, or ransomware on the user's system.
        - **System compromise:** Full control of the user's machine could be gained, leading to further malicious activities.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    - None. The project currently lacks any specific mitigations against pickle deserialization vulnerabilities. The code directly uses `torch.load()` to load model weights from files specified by command-line arguments without any security checks or warnings.
- **Missing Mitigations:**
    - **Input Validation:** Implement checks to validate the file type and potentially the source of the model files before loading them. At a minimum, warn users if they are loading files from untrusted sources.
    - **Secure Deserialization:** Replace `torch.load()` with safer alternatives for loading model weights, such as:
        - **`torch.jit.load()` for TorchScript models:** If the models can be converted to TorchScript, using `torch.jit.load()` is a safer option as it avoids arbitrary code execution during loading.
        - **`safetensors` library:**  Consider using the `safetensors` library, which is designed for safe serialization and deserialization of tensors and is specifically aimed at mitigating pickle vulnerabilities in machine learning model loading.
        - **Manual state_dict loading from safer formats:** Save model weights in a safer format (like JSON or binary formats without pickle) and implement manual loading of the `state_dict`.
    - **User Warnings:**  Clearly document and warn users about the security risks associated with loading pretrained models from untrusted sources. Recommend downloading pretrained models only from trusted sources and verifying their integrity.
- **Preconditions:**
    - **Attacker Access:** The attacker needs to be able to provide or trick the user into using a malicious pickle file in place of a legitimate model file. This could be achieved through various means:
        - **Man-in-the-middle attack:** If model files are downloaded over an insecure network, an attacker could intercept and replace them.
        - **Compromised download source:** If the official download source is compromised, malicious files could be distributed.
        - **Social engineering:**  An attacker could trick a user into downloading and using a malicious file disguised as a legitimate model.
    - **User Action:** The user must execute one of the provided Python scripts (`train_attr_pred.py`, `train_attr_manip.py`, `eval.py`) and specify the path to the malicious pickle file using the command-line arguments `--load_pretrained_extractor` or `--load_pretrained_memory`.

- **Source Code Analysis:**
    - The following files are vulnerable due to the use of `torch.load()` to load pretrained models:
        - `/code/src/train_attr_pred.py`
        - `/code/src/train_attr_manip.py`
        - `/code/src/eval.py`

    - **Example from `/code/src/train_attr_pred.py`:**
        ```python
        if args.load_pretrained_extractor:
            print('load %s\n' % args.load_pretrained_extractor)
            model.load_state_dict(torch.load(args.load_pretrained_extractor))
        ```
        - In this code snippet, the `args.load_pretrained_extractor` variable, which is directly controlled by user input via the command line, is passed to `torch.load()`.
        - `torch.load()` by default uses Python's `pickle` module to deserialize the file.
        - If the file specified by `args.load_pretrained_extractor` is a malicious pickle file, `pickle.load()` will execute any embedded code during the deserialization process, leading to arbitrary code execution.
        - Similar vulnerable patterns exist in `train_attr_manip.py` and `eval.py` for both `--load_pretrained_extractor` and `--load_pretrained_memory` arguments.

- **Security Test Case:**
    1. **Create a malicious pickle file (`malicious_extractor_best.pkl`) using the following Python script:**
        ```python
        import torch
        import pickle
        import os

        class MaliciousPayload(object):
            def __reduce__(self):
                return (os.system, ('echo "Vulnerable!" > /tmp/pwned.txt',))

        torch.save({'extractor': MaliciousPayload()}, 'malicious_extractor_best.pkl')
        ```
        - This script creates a pickle file that, when loaded, will execute the command `echo "Vulnerable!" > /tmp/pwned.txt` on a Linux-like system.  Adjust the payload for other operating systems if needed. This command is just an example; a real attacker could execute much more harmful commands.

    2. **Run the `train_attr_pred.py` script, providing the malicious pickle file path:**
        ```bash
        python src/train_attr_pred.py --dataset_name Shopping100k --file_root splits/Shopping100k --img_root <path_to_dataset> --ckpt_dir test_ckpt --load_pretrained_extractor malicious_extractor_best.pkl
        ```
        - Replace `<path_to_dataset>` with the actual path to your dataset.

    3. **Check for successful code execution:**
        - After running the script, check if the file `/tmp/pwned.txt` has been created and contains the text "Vulnerable!".
        ```bash
        cat /tmp/pwned.txt
        ```
        - If the file exists and contains "Vulnerable!", this confirms that arbitrary code execution was achieved through the pickle deserialization vulnerability.

This test case demonstrates how an attacker can exploit the `torch.load()` function to execute arbitrary commands by providing a malicious pickle file as a pretrained model.