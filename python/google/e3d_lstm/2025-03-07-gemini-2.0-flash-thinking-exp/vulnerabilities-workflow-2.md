## Combined Vulnerability List

This document outlines critical and high severity vulnerabilities identified across multiple lists, consolidated into a single report with detailed descriptions, impacts, mitigations, and test cases.

### 1. Unsafe Image and Video File Processing Leading to Arbitrary Code Execution

- **Vulnerability Name:** Unsafe Image and Video File Processing Leading to Arbitrary Code Execution
- **Description:**
    1. The application processes image and video files using libraries like PIL (Pillow) and OpenCV. These libraries are used in data loading processes, particularly within the `src/data_provider/kth_action.py` file, where `PIL.Image.open` and `cv2.resize` are employed to handle image frames.
    2. An attacker crafts a malicious image or video file (e.g., PNG, JPG, or video formats processed frame-by-frame) specifically designed to exploit known vulnerabilities in PIL or OpenCV. These vulnerabilities can include buffer overflows, heap overflows, or other memory corruption issues triggered during image or video decoding and processing.
    3. The attacker provides a path to a directory containing this malicious file as input to the application. This can be achieved by manipulating command-line arguments such as `--train_data_paths` or `--valid_data_paths` when running training or testing scripts, especially when processing the KTH dataset or any video data.
    4. When the application loads data, specifically using functions like `DataProcess.load_data` in `src/data_provider/kth_action.py`, it processes files identified as images or video frames.
    5. For each identified image or frame, the application utilizes `PIL.Image.open()` to open the file and `cv2.resize()` to resize it. These operations are performed without sufficient input validation or sanitization.
    6. Processing the malicious file through vulnerable versions of `PIL.Image.open()`, `np.array()` (used implicitly after `Image.open`), or `cv2.resize()` can trigger the exploitation of underlying vulnerabilities within these libraries, leading to arbitrary code execution.
- **Impact:**
    - **Arbitrary code execution.** A successful exploit allows the attacker to execute arbitrary code on the machine running the E3D-LSTM model. This grants the attacker complete control over the system, potentially enabling them to:
        - Install malware or backdoors for persistent access.
        - Steal sensitive data, including model weights, training data, or system credentials.
        - Pivot to other systems within the network.
        - Disrupt operations or cause denial of service (though primary impact is code execution).
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    - None. The codebase lacks any input validation or sanitization mechanisms for image and video files processed from datasets. The application directly relies on PIL and OpenCV to handle potentially untrusted file inputs without security precautions.
- **Missing Mitigations:**
    - **Input Validation:** Implement robust checks to validate the format, integrity, and safety of image and video files before processing. This should include:
        - Verifying file headers and magic numbers to ensure they match expected file types.
        - Checking file sizes and dimensions against reasonable limits.
        - Employing safer image/video decoding methods or libraries if available.
    - **Secure Image and Video Processing Libraries:**
        - Ensure that PIL and OpenCV libraries are updated to the latest versions to patch known vulnerabilities.
        - Consider using alternative, more security-focused image/video processing libraries if suitable alternatives exist.
    - **Sandboxing and Isolation:**
        - Isolate image and video processing operations within a sandboxed environment. This could involve using containerization (e.g., Docker) or virtualization to limit the impact of a successful exploit by restricting the compromised process's access to system resources and the network.
    - **Principle of Least Privilege:**
        - Run the application with the minimum necessary privileges. This limits the scope of damage an attacker can inflict even if arbitrary code execution is achieved.
- **Preconditions:**
    - The E3D-LSTM model must be configured to process datasets that include image or video files, such as the KTH dataset, or be configured to process user-provided video input.
    - The attacker must be able to provide a path to a directory or file containing a malicious image or video file. This could be achieved through:
        - Social engineering to trick a user into using a malicious dataset path.
        - Exploiting other vulnerabilities to modify application configurations or command-line arguments.
        - Compromising the system to directly place malicious files in accessible locations.
- **Source Code Analysis:**
    - **File:** `/code/src/data_provider/kth_action.py`
    - **Function:** `DataProcess.load_data(self, paths, mode='train')`
    ```python
    def load_data(self, paths, mode='train'):
        ...
        for cur_file in filelist:  # image_0257
          if not cur_file.startswith('image'):
            continue

          frame_im = Image.open(os.path.join(dir_path, cur_file)) # Vulnerable point: PIL.Image.open - potential vulnerability in image decoding.
          frame_np = np.array(frame_im)  # Vulnerable point: np.array - potential vulnerability during array conversion triggered by malformed image from PIL.
          frame_np = frame_np[:, :, 0]
          frames_np.append(frame_np)
          frames_file_name.append(cur_file)
          frames_person_mark.append(person_mark)
          frames_category.append(frame_category_flag)
        ...
        frames_np = np.asarray(frames_np)
        data = np.zeros((frames_np.shape[0], self.image_width, self.image_width, 1))
        for i in range(len(frames_np)):
          temp = np.float32(frames_np[i, :, :])
          data[i, :, :, 0] = cv2.resize(temp, (self.image_width, self.image_width)) / 255 # Vulnerable point: cv2.resize - potential vulnerability in image resizing with OpenCV.
        ...
    ```
    - **Analysis:** The code directly uses `PIL.Image.open`, `np.array`, and `cv2.resize` to process image files without any prior validation. These functions are known to have had vulnerabilities, especially when dealing with malformed or crafted image/video files. The lack of input validation makes this code vulnerable to arbitrary code execution if a malicious file is processed.
- **Security Test Case:**
    1. **Prepare a Malicious File:** Create a specially crafted image file (e.g., `malicious.png`) or video file designed to exploit a known vulnerability in either `PIL.Image.open` or `cv2.resize`. Use security tools or resources to craft a file targeting vulnerabilities like buffer overflows or heap overflows in image/video processing libraries.
    2. **Create Malicious Dataset Directory:** Construct a directory structure mimicking the KTH dataset format or a structure suitable for video processing. Place the malicious file within this structure where image or video frames are expected to be loaded. For example, for KTH dataset, create `kth_malicious/boxing/person01_boxing_d1_uncomp/malicious.png` and include other valid KTH images renamed to `image_XXXX.png` to avoid file loading errors.
    3. **Modify Script to Use Malicious Dataset:** Edit a training or testing script (e.g., `scripts/e3d_lstm_kth_train.sh`). Modify the command-line arguments to point to the malicious dataset directory by changing `--train_data_paths` or `--valid_data_paths` to the path of the malicious dataset.
    4. **Run the Modified Script:** Execute the modified script.
    5. **Observe for Code Execution or Crash:** Monitor the script execution. Successful exploitation can manifest as arbitrary code execution (e.g., creating a file, network connection) or a crash due to memory corruption.
    6. **Verify and Document:** If code execution or a crash occurs, the vulnerability is confirmed. Document the steps, malicious file used, and the observed impact to reproduce the vulnerability.


### 2. Deserialization of Untrusted Data in MNIST Dataset Loading

- **Vulnerability Name:** Deserialization of Untrusted Data in MNIST Dataset Loading
- **Description:**
    1. The `mnist.py` data provider, specifically within the `InputHandle.load()` function, utilizes `numpy.load()` to load data from `.npz` files. These files are specified via the command-line arguments `--train_data_paths` and `--valid_data_paths` when running `run.py` with the `--dataset_name mnist` option.
    2. `numpy.load()` by default is configured to allow loading pickled Python objects from `.npz` files (`allow_pickle=True`). This feature is intended for convenience but poses a significant security risk when processing untrusted data.
    3. An attacker can craft a malicious `.npz` file containing a specially serialized (pickled) Python object. This object, when deserialized by `numpy.load()`, can be designed to execute arbitrary Python code.
    4. To exploit this vulnerability, an attacker needs to convince a user to use a malicious `.npz` file for training or testing. This can be achieved by tricking the user into providing the path to the malicious file via the `--train_data_paths` or `--valid_data_paths` arguments when running `run.py` or the provided shell scripts.
- **Impact:**
    - **Arbitrary code execution.** Successful exploitation allows the attacker to execute arbitrary Python code on the machine running the training or testing script. This can lead to:
        - Full system compromise, granting the attacker complete control.
        - Data exfiltration and theft of sensitive information.
        - Installation of malware, backdoors, or ransomware.
        - Denial of service by crashing the application or system (though primarily focused on code execution).
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    - None. The code directly uses `np.load()` without any security considerations. The default behavior of `numpy.load()` with `allow_pickle=True` is inherently insecure when handling potentially untrusted input files.
- **Missing Mitigations:**
    - **Disable `allow_pickle` in `np.load()`:** The most effective mitigation is to explicitly set `allow_pickle=False` when calling `numpy.load()` in `mnist.py`. This will prevent the deserialization of pickled objects and limit `.npz` loading to only NumPy arrays and related safe data structures, eliminating the arbitrary code execution risk.
    - **Input Validation and Sanitization:** While challenging for complex binary formats like `.npz`, basic validation could include checks for unexpected file structures or unusually large data chunks. However, this is not a reliable defense against sophisticated malicious pickles.
    - **Sandboxing or Containerization:** Run training and testing processes within a sandboxed environment (e.g., Docker, VMs). This limits the damage if code execution occurs by restricting the attacker's access to the host system. This is a containment strategy, not a prevention of the vulnerability itself.
- **Preconditions:**
    - The user must execute `run.py` or a provided training/testing script (e.g., `e3d_lstm_mm_train.sh`, `e3d_lstm_kth_train.sh`).
    - The user must provide or be tricked into providing a path to a malicious `.npz` file as either `--train_data_paths` or `--valid_data_paths` command-line argument.
    - The attacker needs a method to deliver or make the malicious `.npz` file accessible to the user. Common methods include social engineering, compromised websites, or man-in-the-middle attacks.
- **Source Code Analysis:**
    - **File:** `/code/src/data_provider/mnist.py`
    ```python
    def load(self):
        """Load the data."""
        dat_1 = np.load(self.paths[0]) # Vulnerable line: np.load() with default allow_pickle=True
        for key in dat_1.keys():
            self.data[key] = dat_1[key]
        if self.num_paths == 2:
            dat_2 = np.load(self.paths[1]) # Vulnerable line: np.load() with default allow_pickle=True
            num_clips_1 = dat_1['clips'].shape[1]
            dat_2['clips'][:, :, 0] += num_clips_1
            self.data['clips'] = np.concatenate((dat_1['clips'], dat_2['clips']),
                                                axis=1)
            self.data['input_raw_data'] = np.concatenate(
                (dat_1['input_raw_data'], dat_2['input_raw_data']), axis=0)
            self.data['output_raw_data'] = np.concatenate(
                (dat_1['output_raw_data'], dat_2['output_raw_data']), axis=0)
    ```
    - **Analysis:** The lines `dat_1 = np.load(self.paths[0])` and `dat_2 = np.load(self.paths[1])` within the `load` function of the `InputHandle` class in `/code/src/data_provider/mnist.py` are vulnerable. They use `numpy.load()` without explicitly setting `allow_pickle=False`, thus inheriting the insecure default. This allows for the deserialization of pickled objects from `.npz` files, enabling arbitrary code execution.
- **Security Test Case:**
    1. **Create a malicious `.npz` file:**
        ```python
        import numpy as np
        import pickle
        import os

        command_to_execute = "touch /tmp/pwned_e3dlstm"  # Command to execute on the system

        class MaliciousObject:
            def __reduce__(self):
                return (os.system, (command_to_execute,))

        malicious_data = {'clips': np.array([[[0, 10]], [[10, 10]]]),
                          'input_raw_data': np.zeros((20, 64, 64, 1)),
                          'output_raw_data': np.zeros((20, 64, 64, 1)),
                          'dims': np.array([(64, 64, 1), (64, 64, 1)]) ,
                          'malicious_code': MaliciousObject()}

        np.savez('malicious.npz', **malicious_data)
        ```
    2. **Run the training script with the malicious `.npz` file:**
        ```bash
        python run.py \
            --is_training True \
            --dataset_name mnist \
            --train_data_paths malicious.npz \
            --valid_data_paths malicious.npz \
            --save_dir checkpoints/_mnist_e3d_lstm \
            --gen_frm_dir results/_mnist_e3d_lstm \
            --model_name e3d_lstm \
            --allow_gpu_growth True \
            --img_channel 1 \
            --img_width 64 \
            --input_length 10 \
            --total_length 20 \
            --filter_size 5 \
            --num_hidden 64,64,64,64 \
            --patch_size 4 \
            --layer_norm True \
            --sampling_stop_iter 50000 \
            --sampling_start_value 1.0 \
            --sampling_delta_per_iter 0.00002 \
            --lr 0.001 \
            --batch_size 4 \
            --max_iterations 1 \
            --display_interval 1 \
            --test_interval 1 \
            --snapshot_interval 10000
        ```
    3. **Verify code execution:**
        ```bash
        ls /tmp/pwned_e3dlstm
        ```
        - If the file `/tmp/pwned_e3dlstm` exists, it confirms arbitrary code execution from the malicious `.npz` file.


### 3. Path Traversal in Data Loading via `train_data_paths` and `valid_data_paths`

- **Vulnerability Name:** Path Traversal in Data Loading via `train_data_paths` and `valid_data_paths`
- **Description:**
    1. The application is susceptible to path traversal vulnerabilities due to insufficient validation of user-supplied file paths. The command-line arguments `--train_data_paths` and `--valid_data_paths` allow users to specify paths to dataset files.
    2. When the training script `run.py` is executed, these paths are directly passed to the data loading mechanism, particularly in `src/data_provider/mnist.py` when the `--dataset_name mnist` option is used.
    3. The `InputHandle` class in `mnist.py` utilizes `numpy.load()` to load data from these provided paths without proper validation or sanitization.
    4. An attacker can exploit this by manipulating the `--train_data_paths` or `--valid_data_paths` arguments to include path traversal sequences (e.g., `../`) or absolute paths pointing outside the intended dataset directory.
    5. By providing a path to a sensitive file (e.g., `/etc/passwd`) instead of a legitimate dataset file, the attacker can potentially trick the application into attempting to access and process unauthorized files. While `numpy.load()` is designed for `.npy`, `.npz`, or pickled files, the vulnerability lies in the application's attempt to open and potentially read arbitrary files based on user-provided paths.
- **Impact:**
    - **Information Disclosure.** An attacker can potentially read arbitrary files from the server's filesystem that the user running the script has read access to. This can lead to the disclosure of sensitive information, including:
        - Configuration files containing credentials or sensitive settings.
        - Application source code, potentially revealing further vulnerabilities.
        - System files like `/etc/passwd` or other sensitive data files.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - No mitigations are implemented. The application directly uses user-provided paths with `np.load` without any validation or sanitization to restrict file access.
- **Missing Mitigations:**
    - **Input Validation and Sanitization:** Implement robust input validation and sanitization for the `train_data_paths` and `valid_data_paths` arguments. This should include:
        - **Path Whitelisting:** Validate that the provided paths are within an expected base directory or a predefined set of allowed directories.
        - **Path Traversal Prevention:** Sanitize paths to remove or reject path traversal sequences like `../` and ensure they are not absolute paths pointing outside the allowed data directories.
        - **File Type Validation:** Verify that the files specified by the paths conform to the expected file type (e.g., `.npz`, `.npy`) to prevent processing of arbitrary file types.
- **Preconditions:**
    - The attacker must be able to influence the command-line arguments passed to `run.py`. This typically involves a scenario where a user is running the training script based on instructions that could be manipulated, or if the script is integrated into a system where command-line arguments can be indirectly controlled.
    - The user running the script must have read permissions to the files the attacker is attempting to access. The vulnerability allows the attacker to access files readable by the user executing the script.
- **Source Code Analysis:**
    - **Entry Point:** Command-line arguments `train_data_paths` and `valid_data_paths` are defined in `/code/run.py`.
    ```python
    FLAGS.DEFINE_string('train_data_paths', '', 'train data paths.')
    FLAGS.DEFINE_string('valid_data_paths', '', 'validation data paths.')
    ```
    - **Data Provider Selection:** `run.py` passes these paths to `datasets_factory.data_provider`.
    ```python
    train_input_handle, test_input_handle = datasets_factory.data_provider(
        FLAGS.dataset_name,
        FLAGS.train_data_paths,
        FLAGS.valid_data_paths,
        FLAGS.batch_size * FLAGS.n_gpu,
        FLAGS.img_width,
        seq_length=FLAGS.total_length,
        is_training=True)
    ```
    - **Dataset Factory:** `datasets_factory.py` selects the `mnist.InputHandle` for the 'mnist' dataset.
    ```python
    if dataset_name == 'mnist':
        test_input_param = {
            'paths': valid_data_list,
            'minibatch_size': batch_size,
            'input_data_type': 'float32',
            'is_output_sequence': True,
            'name': dataset_name + 'test iterator'
        }
        test_input_handle = datasets_map[dataset_name].InputHandle(test_input_param)
        # ...
    ```
    - **Vulnerable File Loading in `mnist.py`:** `InputHandle` in `mnist.py` loads data using `np.load(self.paths[0])` and `np.load(self.paths[1])` without path validation.
    ```python
    class InputHandle(object):
        # ...
        def __init__(self, input_param):
            # ...
            self.paths = input_param['paths']
            # ...
            self.load()

        def load(self):
            """Load the data."""
            dat_1 = np.load(self.paths[0])  # Vulnerable line: no path validation
            # ...
            if self.num_paths == 2:
                dat_2 = np.load(self.paths[1]) # Vulnerable line: no path validation
                # ...
    ```
    - **Analysis:** The code directly uses the paths provided by the user without any validation, leading to a path traversal vulnerability. `np.load` attempts to open and process files based on these unsanitized paths.
- **Security Test Case:**
    1. **Prepare malicious data paths:** Create a dummy file `sensitive_data.npz` in `/tmp/` (not strictly needed but can be used for a valid path). Assume `/etc/passwd` exists and is readable by the user running the test.
    2. **Run the training script with path traversal payload:** Execute `run.py` with `--dataset_name mnist` and a malicious `train_data_paths` argument pointing to `/etc/passwd`. Use a valid path for `--valid_data_paths` (e.g., `/tmp/sensitive_data.npz`) to avoid errors unrelated to path traversal.
    ```bash
    python -u run.py \
        --is_training True \
        --dataset_name mnist \
        --train_data_paths /etc/passwd \
        --valid_data_paths /tmp/sensitive_data.npz \
        --save_dir checkpoints/_mnist_e3d_lstm_test \
        --gen_frm_dir results/_mnist_e3d_lstm_test \
        --model_name e3d_lstm \
        --max_iterations 1
    ```
    3. **Observe the output and errors:** Examine the script's output. While `np.load` will likely fail to load `/etc/passwd` as a valid `.npz` archive, error messages should indicate that the application attempted to open and process `/etc/passwd`. Error messages might reveal snippets of `/etc/passwd` content or error messages like "Invalid header", confirming the attempt to read the file due to path traversal.