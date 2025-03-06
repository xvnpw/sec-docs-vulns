## Combined Vulnerability List

This document outlines critical and high-severity vulnerabilities identified within the project. These vulnerabilities pose significant security risks and require immediate attention and mitigation.

### 1. Insecure Deserialization via Pickle in Object Identification

* Vulnerability Name: Insecure Deserialization via Pickle in Object Identification
* Description:
    1. The `/code/identification/test.py` script uses `pickle.load` to load pre-computed feature embeddings from files named `embedding.pkl` and `testcase_embedding.pkl`, and also `train-test-split.pickle`.
    2. These pickle files are loaded from the dataset path, specifically `os.path.join(args.dataset_path, "embedding.pkl")`, `os.path.join(args.dataset_path, "testcase_embedding.pkl")` and `os.path.join(args.dataset_path, "train-test-split.pickle")`.
    3. If a user provides a dataset path that contains a malicious pickle file (either `embedding.pkl`, `testcase_embedding.pkl` or `train-test-split.pickle`), arbitrary Python code embedded within the pickle file will be executed during the deserialization process by `pickle.load`.
    4. An attacker can craft a malicious pickle file that, when loaded by `pickle.load`, executes arbitrary code on the user's machine.
* Impact:
    - Arbitrary code execution on the user's machine.
    - Full compromise of the user's system if the attacker's code gains sufficient privileges.
    - Data exfiltration, malware installation, or denial of service.
* Vulnerability Rank: Critical
* Currently Implemented Mitigations: None
* Missing Mitigations:
    - Input validation: Implement checks to ensure the pickle files originate from a trusted source and haven't been tampered with. This could involve verifying a digital signature or checksum of the pickle files if they are distributed as part of the official dataset. If these are generated locally, consider warning users about dataset origin.
    - Secure deserialization practices: If possible, avoid using `pickle` for deserialization, especially for data from untrusted sources. Consider using safer serialization formats like JSON or protobuf, or implement robust input sanitization and validation if pickle is necessary.
    - Documentation: Clearly warn users about the risks of using datasets from untrusted sources, as these datasets might contain malicious pickle files. Advise users to only use datasets from the official repository or trusted sources.
* Preconditions:
    - The user must download and run the `/code/identification/test.py` script.
    - The user must use a dataset path that contains a malicious `embedding.pkl`, `testcase_embedding.pkl` or `train-test-split.pickle` file. This could be achieved by downloading a compromised dataset or by manually placing a malicious pickle file in the dataset directory.
* Source Code Analysis:
    ```python
    File: /code/identification/test.py
    def run_test(args):
        ...
        testset_path = os.path.join(args.dataset_path, "train-test-split.pickle")
        embedding_location = os.path.join(args.dataset_path, "embedding.pkl")
        testcase_embedding_location = os.path.join(args.dataset_path, "testcase_embedding.pkl")

        with open(testset_path, 'rb') as f:
            train_test_split = pickle.load(f) # [VULNERABLE LINE]

        feature_embeddings = {}
        if os.path.exists(embedding_location):
            feature_embeddings_file = open(embedding_location, 'rb')
            feature_embeddings_saved = pickle.load(feature_embeddings_file) # [VULNERABLE LINE]

        testcase_embeddings = {}
        if os.path.exists(testcase_embedding_location):
            testcase_embeddings_file = open(testcase_embedding_location, 'rb')
            testcase_embeddings_saved = pickle.load(testcase_embeddings_file) # [VULNERABLE LINE]
    ```
    The code uses `pickle.load` to load `train-test-split.pickle`, `embedding.pkl` and `testcase_embedding.pkl` files from the path specified by `args.dataset_path`. If a malicious user provides a dataset path containing crafted pickle files, it will lead to arbitrary code execution.
* Security Test Case:
    1. **Prepare a malicious pickle file:** Create a Python script to generate a malicious pickle file (e.g., `malicious_embedding.pkl`). This file should contain code to be executed during deserialization.
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
    2. **Prepare a malicious dataset directory:** Create a directory (e.g., `malicious_dataset`) and place the `malicious_embedding.pkl` file inside it, renaming it to `embedding.pkl`.
    3. **Run the vulnerable code:** Execute the object identification test script, providing the path to the malicious dataset directory using the `-d` or `--dataset_path` argument. For example, run `python /code/identification/test.py -d /path/to/malicious_dataset`.
    4. **Verify code execution:** Check if the malicious code was executed. In the example above, check if the file `/tmp/pickle_pwned` was created. Successful creation of the file indicates arbitrary code execution.

### 2. Insecure Deserialization in PyTorch Model Checkpoints

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
* Currently Implemented Mitigations: None
* Missing Mitigations:
    - Input validation: Implement checks to ensure the checkpoint file originates from a trusted source and hasn't been tampered with. This could involve verifying a digital signature or checksum of the checkpoint file.
    - Secure loading practices: Explore safer alternatives to `torch.load` if available, or implement sandboxing or containerization when loading checkpoints from untrusted sources.
    - Documentation: Clearly warn users about the risks of loading checkpoints from untrusted sources and advise them to only use checkpoints from the official repository or trusted sources.
* Preconditions:
    - The user must download and run the provided sample code.
    - The user must be tricked into using a malicious checkpoint file, either by replacing a legitimate one or by being directed to load a malicious checkpoint via command-line arguments.
* Source Code Analysis:
    ```python
    File: /code/defect_detection/defect_videos/src/model.py
    if args.model == "SlowFast":
        pretrained_ckpt = torch.load("pretrained_ckpt/SLOWFAST_8x8_R50_ssv2.pyth") # [VULNERABLE LINE]
    elif args.model == "R(2+1)D":
        pretrained_ckpt = torch.load("pretrained_ckpt/R2PLUS1D_16x4_R50.pyth") # [VULNERABLE LINE]
    elif args.model == "MViT_B":
        pretrained_ckpt = torch.load("pretrained_ckpt/MVIT_B_32x3.pyth") # [VULNERABLE LINE]

    File: /code/defect_detection/defect_videos/src/train.py & test.py
    model = VideoClassificationLightningModule.load_from_checkpoint(checkpoint_path=args.ckpt, args=args) # [VULNERABLE LINE]

    File: /code/defect_detection/defect_images/train.py
    trainer.fit(model, train_dataloader, test_dataloader, ckpt_path=args.checkpoint) # [VULNERABLE LINE]
    model = ARMBenchImageDefectModule.load_from_checkpoint(args.checkpoint) # [VULNERABLE LINE]

    File: /code/segmentation/test_mask_rcnn.py & train_mask_rcnn.py
    checkpoint = torch.load(args.resume_from) # [VULNERABLE LINE]
    ```
    The code uses `torch.load` in multiple locations to load pretrained checkpoints and resume training from checkpoints. Using `torch.load` on untrusted checkpoint files can lead to arbitrary code execution.
* Security Test Case:
    1. **Prepare a malicious PyTorch checkpoint file:** Create a Python script that generates a malicious PyTorch checkpoint.
        ```python
        import torch
        import os

        class MaliciousPayload:
            def __reduce__(self):
                return (os.system, ('touch /tmp/pwned',))

        torch.save({'state_dict': MaliciousPayload()}, 'malicious_checkpoint.ckpt')
        ```
    2. **Place the malicious checkpoint:** Replace one of the pretrained checkpoint files in the `pretrained_ckpt` directory (e.g., `pretrained_ckpt/MVIT_B_32x3.pyth`) with the `malicious_checkpoint.ckpt` and rename it to `MVIT_B_32x3.pyth`.
    3. **Run the vulnerable code:** Execute the video defect detection training script. For example, run `./code/defect_detection/defect_videos/train.sh`.
    4. **Verify code execution:** Check if the malicious code was executed. In the example above, check if the file `/tmp/pwned` was created.

### 3. Image Processing Vulnerability via `torchvision.io.read_image` in Video Defect Detection Dataset Loading

* Vulnerability Name: Image Processing Vulnerability via `torchvision.io.read_image` in Video Defect Detection Dataset Loading
* Description:
    1. An attacker crafts a malicious image file (e.g., PNG, JPEG) designed to exploit a potential vulnerability in the `torchvision.io.read_image` function.
    2. The attacker includes this malicious image file within the ARMBench Defect Detection (videos) dataset, specifically within a frame folder for a video.
    3. A user downloads and extracts the ARMBench Defect Detection (videos) dataset and executes code that loads the dataset.
    4. During dataset loading in `FrameVideoDataset.__getitem__`, the code uses `torchvision.io.read_image` to load each frame.
    5. When `torchvision.io.read_image` processes the malicious image file, it triggers a vulnerability (e.g., buffer overflow, arbitrary code execution).
* Impact:
    - **Code Execution**: The attacker could potentially achieve arbitrary code execution on the user's machine.
    - **Denial of Service**: The image processing vulnerability might cause the application to crash.
* Vulnerability Rank: High
* Currently Implemented Mitigations: None
* Missing Mitigations:
    - **Input Validation and Sanitization**: Implement checks to validate image file formats and potentially sanitize image data before processing with `torchvision.io.read_image`.
    - **Using Secure Image Processing Libraries**: Ensure that `torchvision` and its underlying image processing libraries are up-to-date to patch known vulnerabilities.
    - **Sandboxing or Virtualization**: Running the dataset processing and model training in a sandboxed environment or virtual machine.
* Preconditions:
    1. The user must download and use the ARMBench Defect Detection (videos) dataset.
    2. The ARMBench Defect Detection (videos) dataset must contain a maliciously crafted image file.
    3. The user must execute the provided sample code that loads and processes the dataset using `FrameVideoDataset`.
* Source Code Analysis:
    ```python
    File: /code/defect_detection/defect_videos/src/dataset.py
    def __getitem__(self, idx) -> Dict:
        # ...
        frame_folder = os.path.join(self.dataset_path, 'cropped_frames', id)
        frame_files = sorted(os.listdir(frame_folder))
        # ...
        frames = []
        for idx in unique_sampled_indices:
            frames.append(read_image(os.path.join(frame_folder, frame_files[idx]))) # Vulnerable line
        # ...
    ```
    The vulnerability lies in the use of `read_image` to load image files from user-provided datasets without validation. A malicious image file in the dataset can exploit vulnerabilities in `torchvision.io.read_image`.
* Security Test Case:
    1. **Setup:** Create a directory structure mimicking the ARMBench Defect Detection (videos) dataset and place a maliciously crafted PNG image file named `0000.png` inside.
    2. **Execution:** Set the environment variable `$AB_DD_VIDEOS_DATA` to point to the created dataset directory and run the training script: `./train.sh`.
    3. **Verification:** Observe the execution and check for crashes or unexpected errors during dataset loading, specifically when processing the malicious image. Examine system logs for errors related to image processing.

### 4. Video Processing Vulnerability via `av.open` and `av.container.InputContainter.decode` in Video Preprocessing Script

* Vulnerability Name: Video Processing Vulnerability via `av.open` and `av.container.InputContainter.decode` in Video Preprocessing Script
* Description:
    1. An attacker crafts a malicious video file (e.g., MP4, AVI) designed to exploit a potential vulnerability in the `av.open` or `av.container.InputContainter.decode` functions of the PyAV library.
    2. The attacker includes this malicious video file within the ARMBench Defect Detection (videos) dataset, specifically in the `videos` directory.
    3. A user downloads and extracts the ARMBench Defect Detection (videos) dataset and executes the `preprocess_video.py` script.
    4. The `preprocess_video.py` script uses `av.open(video_path)` to open each video file and `container.decode(video=0)` to decode video frames.
    5. When `av.open` or `container.decode` processes the malicious video file, it triggers a vulnerability (e.g., buffer overflow, arbitrary code execution).
* Impact:
    - **Code Execution**: Arbitrary code execution on the user's machine.
    - **Denial of Service**: Crash of the preprocessing script.
* Vulnerability Rank: High
* Currently Implemented Mitigations: None
* Missing Mitigations:
    - **Input Validation and Sanitization**: Implement checks to validate video file formats and potentially sanitize video data before processing with PyAV.
    - **Using Secure Video Processing Libraries**: Ensure PyAV and its underlying libraries are up-to-date.
    - **Sandboxing or Virtualization**: Running the preprocessing script in a sandboxed environment.
* Preconditions:
    1. The user must download and use the ARMBench Defect Detection (videos) dataset.
    2. The ARMBench Defect Detection (videos) dataset must contain a maliciously crafted video file in the `videos` directory.
    3. The user must execute the `preprocess_video.py` script.
* Source Code Analysis:
    ```python
    File: /code/defect_detection/defect_videos/scripts/preprocess_video.py
    def extract_frames_pyav(video_path, num_samples=None, cut_frames=0, max_frames=None):
        container = av.open(video_path) # Vulnerable line
        for idx, frame in enumerate(container.decode(video=0)): # Vulnerable line
            # ...
    ```
    The `extract_frames_pyav` function uses `av.open` and `container.decode` to process video files from the dataset without validation. A malicious video file can exploit vulnerabilities in PyAV.
* Security Test Case:
    1. **Setup:** Create a directory structure mimicking the ARMBench Defect Detection (videos) dataset and place a maliciously crafted MP4 video file named `malicious_video.mp4` inside.
    2. **Execution:** Set the environment variable `$AB_DD_VIDEOS_DATA` and run the preprocessing script: `python preprocess_video.py --dataset_path $AB_DD_VIDEOS_DATA`.
    3. **Verification:** Observe the execution and check for crashes or unexpected errors during video processing, specifically when processing the malicious video. Examine system logs for errors related to video processing.