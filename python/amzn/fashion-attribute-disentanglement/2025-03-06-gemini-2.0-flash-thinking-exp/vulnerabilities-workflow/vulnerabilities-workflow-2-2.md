### Vulnerability List:

#### 1. Malicious Model Deserialization Vulnerability

- **Description:**
    1. The project loads pretrained model weights from files specified by the `--load_pretrained_extractor` and `--load_pretrained_memory` command-line arguments using `torch.load()`.
    2. `torch.load()` in PyTorch, by default, uses Python's `pickle` module for deserialization.
    3. Python's `pickle` module is known to be vulnerable to arbitrary code execution if used to load data from untrusted sources.
    4. A malicious attacker could replace the legitimate pretrained model files (e.g., `extractor_best.pkl`, `memory_best.pkl`) with maliciously crafted pickle files.
    5. When a user runs any of the provided scripts (e.g., `train_attr_pred.py`, `train_attr_manip.py`, `eval.py`) and loads these malicious model files using the `--load_pretrained_extractor` or `--load_pretrained_memory` arguments, arbitrary Python code embedded in the malicious pickle file will be executed on the user's machine.
    6. This can lead to full system compromise, data theft, or other malicious activities.

- **Impact:**
    - **Critical**. Successful exploitation allows for arbitrary code execution on the machine running the training or evaluation scripts. This can lead to:
        - Full control of the user's system.
        - Theft of sensitive data, including training data, personal files, and credentials.
        - Installation of malware or backdoors.
        - Unauthorized access to other systems or networks accessible from the compromised machine.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - None. The code directly uses `torch.load()` to load model files without any input validation or security checks on the model files themselves. The `README.md` and `CONTRIBUTING.md` do not contain any security warnings related to model loading or suggest any methods for users to verify the integrity of the pretrained models.

- **Missing Mitigations:**
    - **Input Validation:** The project should implement checks to validate the integrity and source of the model files before loading them. This could include:
        - **Cryptographic Signatures:** Providing cryptographic signatures for the official pretrained model files and verifying these signatures before loading. This would require a mechanism for users to obtain and check the official signatures.
        - **Secure Deserialization Methods:** Exploring safer alternatives to `pickle` for model serialization and deserialization if possible. If `pickle` is necessary, consider using safer loading practices if available in PyTorch.
        - **Warning to Users:** Clearly warn users in the `README.md` and documentation about the potential risks of loading pretrained models from untrusted sources and advise them to only use models from the official repository or verified sources.

- **Preconditions:**
    - The attacker needs to be able to replace the legitimate pretrained model files with malicious ones. This could be achieved through various means:
        - **Man-in-the-Middle Attack:** If the models are downloaded over an insecure network, an attacker could intercept and replace the files during download.
        - **Compromised Download Source:** If the download source for pretrained models is compromised, users downloading from this source would receive malicious files.
        - **Social Engineering:** Tricking users into downloading and using malicious model files from unofficial or untrusted sources, perhaps by misleading them into thinking they are legitimate.
        - **Local File System Access:** If an attacker has write access to the file system where the user stores or downloads the pretrained models, they can directly replace the files.

- **Source Code Analysis:**
    - **File: `/code/src/train_attr_pred.py`**
        ```python
        if args.load_pretrained_extractor:
            print('load %s\n' % args.load_pretrained_extractor)
            model.load_state_dict(torch.load(args.load_pretrained_extractor))
        else:
            print('Pretrained extractor not provided. Use --load_pretrained_extractor or the model will be randomly initialized.')
        ```
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
        - In all three scripts, the code uses `torch.load()` to load model weights from the file paths provided via command-line arguments `--load_pretrained_extractor` and `--load_pretrained_memory`.
        - There is no validation of the content or source of these files before loading them with `torch.load()`.
        - `torch.load()` will deserialize the pickle file and execute any embedded code during the loading process.

- **Security Test Case:**
    1. **Prepare a malicious model file:** Create a Python script (e.g., `malicious_model_generator.py`) to generate a malicious pickle file that will execute arbitrary code when loaded by `torch.load()`. This script would create a dummy PyTorch model and then modify its state dictionary to include malicious code that gets executed during deserialization.
        ```python
        import torch
        import os

        class MaliciousModel(torch.nn.Module):
            def __init__(self):
                super().__init__()
                self.linear = torch.nn.Linear(10, 1)

            def forward(self, x):
                return self.linear(x)

        def create_malicious_model(filename):
            model = MaliciousModel()
            state_dict = model.state_dict()
            state_dict['malicious_code'] = """
            import os
            os.system('touch /tmp/pwned') # Example: create a file to indicate compromise
            """
            torch.save(state_dict, filename)

        if __name__ == '__main__':
            create_malicious_model("malicious_extractor_best.pkl")
            print("Malicious model 'malicious_extractor_best.pkl' created.")
        ```
    2. **Run the malicious model generator:** Execute `python malicious_model_generator.py` to create `malicious_extractor_best.pkl`.
    3. **Run the evaluation script with the malicious model:** Execute the `eval.py` script, providing the path to the malicious model file using the `--load_pretrained_extractor` argument. For example:
        ```bash
        export DATASET_PATH="/path/to/dataset/folder/that/contain/img/subfolder" # Replace with a valid path if needed, even dummy
        export MODELS_DIR="./models/Shopping100k" # Or any directory
        export DATASET_NAME="Shopping100k"

        python src/eval.py --dataset_name ${DATASET_NAME} --file_root splits/${DATASET_NAME} --img_root ${DATASET_PATH} --load_pretrained_extractor malicious_extractor_best.pkl --load_pretrained_memory ${MODELS_DIR}/memory_best.pkl
        ```
        *(Note: You might need to create dummy `splits` and `img` folders to satisfy path requirements, even if the dataset loading is not the focus of this test. The goal is to trigger model loading.)*
    4. **Verify code execution:** After running the `eval.py` command, check if the malicious code was executed. In the example above, check if the file `/tmp/pwned` was created. If it exists, it confirms that the arbitrary code within the malicious pickle file was executed when `torch.load()` deserialized the model file, demonstrating the vulnerability.