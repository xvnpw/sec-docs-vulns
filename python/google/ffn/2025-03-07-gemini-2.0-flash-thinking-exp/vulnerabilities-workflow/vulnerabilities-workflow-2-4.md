### Vulnerability List

* Vulnerability Name:  Path Traversal in Segmentation Output Directory
* Description: The `segmentation_output_dir` parameter in the inference request configuration file (`.pbtxt`) is used to specify the directory where segmentation results are saved. The `run_inference.py` script directly uses this parameter to create the output directory using `gfile.makedirs(request.segmentation_output_dir)`. If an attacker provides a malicious path like '../../output_dir', the `gfile.makedirs` function might create directories outside of the intended output directory, potentially leading to files being written to arbitrary locations on the file system.
* Impact: An attacker could potentially write segmentation results to arbitrary locations on the server's file system, possibly overwriting critical system files or placing files in sensitive directories. This could lead to unauthorized file access or modification, and in severe cases, potentially lead to arbitrary code execution if executable files are overwritten.
* Vulnerability Rank: High
* Currently Implemented Mitigations: None
* Missing Mitigations:
    - Input validation and sanitization of the `segmentation_output_dir` parameter to ensure it is a valid path within the intended output directory and does not contain path traversal characters like '..' or absolute paths.
    - Using a safe path joining function that prevents path traversal vulnerabilities, although `gfile.makedirs` itself might be vulnerable if the input is not sanitized.
    - Implementing chroot or similar sandboxing techniques to restrict the script's file system access.
* Preconditions:
    - The attacker needs to be able to provide a crafted inference request configuration file (`.pbtxt`).
    - The `run_inference.py` script must be executed with the attacker-provided configuration.
* Source Code Analysis:
    - In `/code/run_inference.py`:
    ```python
    if not gfile.exists(request.segmentation_output_dir):
        gfile.makedirs(request.segmentation_output_dir)
    ```
    - The code directly uses `request.segmentation_output_dir` from the parsed `.pbtxt` file as the argument to `gfile.makedirs`.
    - There is no validation or sanitization of the `segmentation_output_dir` before using it in `gfile.makedirs`.
    - `gfile.makedirs` in TensorFlow (and potentially the underlying implementation) might follow path traversal sequences, creating directories outside the intended scope if provided in `request.segmentation_output_dir`.

* Security Test Case:
    1. Create a malicious inference request configuration file named `malicious_inference.pbtxt` with the following content:
    ```
    image {
      volume_path: "third_party/neuroproof_examples/validation_sample/grayscale_maps.h5:raw"
    }
    segmentation_output_dir: "../../tmp/ffn_output"
    model_name: "convstack_3d.ConvStack3DFFNModel"
    model_args: "{\"depth\": 12, \"fov_size\": [33, 33, 33], \"deltas\": [8, 8, 8]}"
    inference_options {
      init_activation: 0.95
      pad_value: 0.05
      move_threshold: 0.9
    }
    ```
    2. Run the `run_inference.py` script with the malicious configuration and a bounding box:
    ```shell
    python run_inference.py --inference_request="$(cat malicious_inference.pbtxt)" --bounding_box 'start { x:0 y:0 z:0 } size { x:10 y:10 z:10 }'
    ```
    3. After execution, check if a directory `ffn_output` has been created in the `/tmp` directory (or a directory outside the intended project directory).
    4. If the `ffn_output` directory is created in `/tmp`, it confirms the path traversal vulnerability, as the intended output directory should have been within the project's `results` directory or a subdirectory within.
    5. Further, attempt to write to more sensitive directories (within `/tmp` for testing purposes, avoid system critical paths) to demonstrate full path traversal impact. For example, try setting `segmentation_output_dir: "../../tmp/sensitive_dir/ffn_output"` and check if the directory and files are created there.