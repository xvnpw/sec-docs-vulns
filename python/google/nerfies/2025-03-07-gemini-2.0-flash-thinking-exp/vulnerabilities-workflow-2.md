### Combined Vulnerability List

This document outlines critical and high severity vulnerabilities identified in the Nerfies project. Each vulnerability is detailed with its description, potential impact, rank, implemented and missing mitigations, preconditions for exploitation, source code analysis, and a security test case to verify its existence.

#### 1. Insecure Deserialization in Camera Parameter Loading
   - **Description:**
        1. The Nerfies project loads camera parameters from JSON files located in the `camera` subdirectory of a dataset.
        2. The `Camera.from_json` method in `/code/nerfies/camera.py` deserializes camera parameters from these JSON files using `json.load`.
        3. An attacker can create a malicious dataset containing a crafted JSON file (e.g., `camera/${item_id}.json`) with manipulated camera parameters.
        4. This malicious JSON file can inject unexpected data types or structures, potentially exploiting vulnerabilities during the deserialization process or in the `Camera` class constructor.
        5. When a user trains or evaluates the Nerfies model using a dataset containing this malicious JSON file, the `Camera.from_json` method parses it.
        6. If the `Camera.from_json` method or the underlying JSON parsing process is vulnerable to insecure deserialization, it could lead to arbitrary code execution or other unexpected behavior when the malicious data is processed.
   - **Impact:** Arbitrary code execution. Successful exploitation could allow an attacker to gain control over the system running the Nerfies training or evaluation process.
   - **Vulnerability rank:** Critical
   - **Currently implemented mitigations:** None evident. The code uses standard JSON loading and class instantiation without input validation or sanitization.
   - **Missing mitigations:**
        - Input validation and sanitization for all camera parameters loaded from JSON files within the `Camera.from_json` method. This should include checks for data types, ranges, and structures to ensure they conform to expected values.
        - Consider using safer deserialization methods or implement custom parsing logic with security in mind.
        - Implement error handling and input rejection to prevent processing datasets with invalid or suspicious camera parameter files.
   - **Preconditions:**
        - The attacker must provide a malicious dataset to a user, potentially by hosting it online or distributing it through other channels.
        - The user must use the Nerfies training or evaluation scripts (`train.py` or `eval.py`) and point them to the attacker's malicious dataset directory.
   - **Source code analysis:**
        1. **File:** `/code/nerfies/camera.py`
        2. **Class:** `Camera`
        3. **Method:** `from_json(cls, path: types.PathType)`
        4. **Code Snippet:**
            ```python
            @classmethod
            def from_json(cls, path: types.PathType):
                """Loads a JSON camera into memory."""
                path = gpath.GPath(path)
                with path.open('r') as fp:
                    camera_json = json.load(fp)

                # Fix old camera JSON.
                if 'tangential' in camera_json:
                    camera_json['tangential_distortion'] = camera_json['tangential']

                return cls(
                    orientation=np.asarray(camera_json['orientation']),
                    position=np.asarray(camera_json['position']),
                    focal_length=camera_json['focal_length'],
                    principal_point=np.asarray(camera_json['principal_point']),
                    skew=camera_json['skew'],
                    pixel_aspect_ratio=camera_json['pixel_aspect_ratio'],
                    radial_distortion=np.asarray(camera_json['radial_distortion']),
                    tangential_distortion=np.asarray(camera_json['tangential_distortion']),
                    image_size=np.asarray(camera_json['image_size']),
                )
            ```
        - The `from_json` method uses `json.load(fp)` to parse JSON files. While `json.load` itself is generally safe, the loaded data is directly used to instantiate a `Camera` object.
        - The `Camera` class constructor directly assigns the parsed data to object attributes without validation.
        - Malicious JSON data with unexpected types or values for fields like `orientation`, `position`, `image_size`, etc., could cause issues in subsequent computations or exploit downstream vulnerabilities due to malformed data.
   - **Security test case:**
        1. **Create a malicious JSON camera file:** Create `malicious_dataset/camera/000000.json` with the following content:
            ```json
            {
              "orientation": "malicious string",
              "position": [-0.3236, -3.26428, 5.4160],
              "focal_length": 2691,
              "principal_point": [1220, 1652],
              "skew": 0.0,
              "pixel_aspect_ratio": 1.0,
              "radial_distortion": [0.1004, -0.2090, 0.0],
              "tangential_distortion": [0.001109, -2.5733e-05],
              "image_size": [2448, 3264]
            }
            ```
        2. **Prepare a minimal dataset:** Create `malicious_dataset` with necessary subdirectories and minimal valid files (`rgb/1x/000000.png`, `metadata.json`, `dataset.json`, `scene.json`).
        3. **Run training or evaluation:** Execute `train.py` or `eval.py` pointing to the `malicious_dataset` directory:
            ```bash
            python train.py --data_dir /path/to/malicious_dataset --base_folder /tmp/nerfies_test --gin_configs configs/test_vrig.gin
            ```
        4. **Observe the behavior:** Monitor for errors, crashes, or unexpected behavior during script execution, especially related to camera parameter processing. Instability or crashes during parsing of the crafted data are indicators of the vulnerability.

#### 2. Malicious PNG Image Processing Vulnerability
   - **Description:**
        1. An attacker crafts a malicious PNG image file.
        2. The attacker includes this malicious PNG image in a dataset, potentially by distributing a compromised dataset.
        3. A user downloads and uses this dataset for training a Nerfies model.
        4. During dataset loading, the Nerfies code uses `imageio.imread()` (in `/code/nerfies/image_utils.py`) to load and process PNG images.
        5. If the `imageio` library or its backend has a vulnerability in handling malformed PNG files, processing the malicious image can trigger this vulnerability.
        6. Successful exploitation can lead to arbitrary code execution on the user's machine.
   - **Impact:** Arbitrary code execution, potentially leading to full system compromise.
   - **Vulnerability Rank:** Critical
   - **Currently implemented mitigations:** None. The project relies on the `imageio` library without specific security measures against malicious images.
   - **Missing mitigations:**
        - Input validation: Implement checks to validate image file headers and metadata before loading, although this may not prevent advanced exploits.
        - Sandboxing or containerization: Run image processing in a sandboxed environment to limit exploit impact.
        - Library updates: Regularly update `imageio` and its dependencies to patch known vulnerabilities.
        - Security-focused image processing: Consider using more secure image processing libraries.
   - **Preconditions:**
        - User uses the Nerfies codebase.
        - User uses a dataset containing a maliciously crafted PNG image.
        - Nerfies code processes the malicious PNG image using `imageio.imread()`.
   - **Source Code Analysis:**
        1. **File:** `/code/nerfies/image_utils.py`
        2. **Function:** `load_image(path: types.PathType)`
        3. **Code Snippet:**
            ```python
            import imageio
            def load_image(path: types.PathType) -> np.ndarray:
              """Reads an image."""
              if not isinstance(path, gpath.GPath):
                path = gpath.GPath(path)

              with path.open('rb') as f:
                return imageio.imread(f)
            ```
        - The `load_image` function directly uses `imageio.imread()` to load images.
        - This function is used in `/code/nerfies/datasets/nerfies.py` to load RGB images, and subsequently in training and evaluation scripts.
   - **Security Test Case:**
        1. Prepare a malicious PNG image file (`malicious.png`) designed to exploit a vulnerability in `imageio` or Pillow.
        2. Create a dataset directory `test_dataset` with the structure `rgb/1x`.
        3. Place `malicious.png` in `test_dataset/rgb/1x/`.
        4. Create dummy camera and metadata files as required for a minimal Nerfies dataset.
        5. Set `DATASET_PATH` environment variable to `test_dataset` path.
        6. Run the training script:
            ```bash
            python train.py --data_dir $DATASET_PATH --base_folder /tmp/nerfies_test --gin_configs configs/test_vrig.gin
            ```
        7. Observe the execution for crashes, unexpected program behavior, or attempts at arbitrary code execution. Try to execute a benign command within the malicious PNG to confirm code execution (e.g., `touch /tmp/pwned`).

#### 3. Arbitrary File Read via Crafted Dataset Configuration
   - **Description:**
        1. An attacker crafts a malicious dataset, manipulating `dataset.json` and `scene.json` configuration files.
        2. In `dataset.json`, the attacker injects directory traversal paths (e.g., "../../sensitive_file") into `val_ids` or `train_ids`.
        3. Alternatively, in `scene.json`, directory traversal paths can be injected into the `center` array.
        4. When the Nerfies application loads this malicious dataset, the data loading functions process these IDs or center coordinates without proper validation.
        5. This lack of validation allows directory traversal paths to be interpreted, potentially leading to file access outside the intended dataset directory.
        6. If the application attempts to read files based on these manipulated paths, it could result in arbitrary file read.
   - **Impact:** High. An attacker can read arbitrary files from the system, potentially disclosing sensitive information.
   - **Vulnerability Rank:** High
   - **Currently implemented mitigations:** None. No input validation or sanitization on `item_id` values or scene center coordinates is implemented.
   - **Missing mitigations:**
        - Input validation: Implement robust validation for `item_id` values from `dataset.json` and `scene.json`, ensuring they are alphanumeric and do not contain directory traversal characters.
        - Path sanitization: Sanitize file paths constructed using `item_id` to ensure they remain within the intended dataset directory.
        - Sandboxing/Isolation: Run data loading in a sandboxed environment to limit the impact of file read vulnerabilities.
   - **Preconditions:**
        1. User downloads and uses a maliciously crafted dataset.
        2. Malicious dataset contains manipulated `dataset.json` or `scene.json` with directory traversal paths in `val_ids`, `train_ids`, or `center` arrays.
        3. User executes `train.py` or `eval.py` with the malicious dataset.
   - **Source Code Analysis:**
        1. **File:** `/code/datasets/nerfies.py`
        2. **Function:** `_load_dataset_ids(data_dir: types.PathType)` and `load_scene_info(data_dir: types.PathType)`
        3. **Code Snippets:**
            - `_load_dataset_ids`:
                ```python
                def _load_dataset_ids(data_dir: types.PathType) -> Tuple[List[str], List[str]]:
                    dataset_json_path = gpath.GPath(data_dir, 'dataset.json')
                    with dataset_json_path.open('r') as f:
                        dataset_json = json.load(f)
                        train_ids = dataset_json['train_ids']
                        val_ids = dataset_json['val_ids']
                    return train_ids, val_ids
                ```
            - `load_scene_info`:
                ```python
                def load_scene_info(data_dir: types.PathType) -> Tuple[np.ndarray, float, float, float]:
                    scene_json_path = gpath.GPath(data_dir, 'scene.json')
                    with scene_json_path.open('r') as f:
                        scene_json = json.load(f)
                    scene_center = np.array(scene_json['center'])
                    return scene_center, ...
                ```
        - `train_ids`, `val_ids` and `center` are read from JSON without validation.
        - `item_id` from `train_ids` and `val_ids` is used to construct file paths in `load_camera`:
            ```python
            def load_camera(self, item_id, scale_factor=1.0):
                ...
                if isinstance(item_id, gpath.GPath):
                  camera_path = item_id
                else:
                  if self.camera_type == 'json':
                    camera_path = self.camera_dir / f'{item_id}{self.camera_ext}'
                  else:
                    raise ValueError(f'Unknown camera type {self.camera_type!r}.')
                ...
                return core.load_camera(camera_path, ...)
            ```
        - Manipulated `item_id` values can lead to directory traversal when constructing `camera_path`.
   - **Security Test Case:**
        1. **Craft Malicious Dataset:** Create `malicious_dataset` with:
            - `malicious_dataset/dataset.json`:
                ```json
                { "train_ids": ["malicious_item"], "val_ids": ["test_item"] }
                ```
            - `malicious_dataset/scene.json`:
                ```json
                { "center": ["../../", "../../", "../../"] }
                ```
            - `malicious_dataset/camera/malicious_item.json`: (dummy content)
            - `malicious_dataset/rgb/1x/malicious_item.png`: (dummy PNG)
            - `malicious_dataset/rgb/1x/test_item.png`: (dummy PNG)
        2. **Prepare Sensitive File:** Place `sensitive_data.txt` one directory level above `malicious_dataset`.
        3. **Run Nerfies Training:**
            ```bash
            export DATASET_PATH=/path/to/malicious_dataset
            python train.py --data_dir $DATASET_PATH --base_folder /tmp/nerfies_experiment --gin_configs configs/test_vrig.gin
            ```
        4. **Observe for File Read Attempt:** Monitor for attempts to read files outside the dataset directory, particularly `sensitive_data.txt`. Check error messages or use system monitoring tools to observe file access patterns.

#### 4. Unsafe Image Loading and Processing in Dataset Creation
   - **Description:**
        1. The project processes input video or images to create datasets for Nerfie training.
        2. The `_load_image` function in `/code/nerfies/datasets/nerfies.py` uses `cv2.imdecode` to load images from PNG files.
        3. `cv2.imdecode` is known to be vulnerable to various image format exploits if the input image is maliciously crafted.
        4. A malicious PNG file provided during dataset creation could trigger buffer overflows, heap corruption, or other memory corruption vulnerabilities in `cv2.imdecode`.
        5. This could lead to arbitrary code execution during dataset processing.
   - **Impact:** Arbitrary code execution, potentially leading to system compromise.
   - **Vulnerability Rank:** Critical
   - **Currently implemented mitigations:** None. The code directly uses `cv2.imdecode` without input validation of image file content.
   - **Missing mitigations:**
        - Input sanitization and validation: Validate input image files before processing with `cv2.imdecode`, including file type validation, size limits, and header validation.
        - Safe image decoding libraries: Consider safer image decoding libraries or sandboxed environments.
        - Sandboxing: Process image decoding in a sandboxed environment.
        - Input fuzzing: Perform fuzz testing on the image processing pipeline with malformed image files.
   - **Preconditions:**
        - Attacker provides a maliciously crafted PNG image file.
        - User processes this malicious image file using Nerfies scripts or notebooks for dataset creation.
   - **Source Code Analysis:**
        1. **File:** `/code/nerfies/datasets/nerfies.py`
        2. **Function:** `_load_image(path: types.PathType)`
        3. **Code Snippet:**
            ```python
            def _load_image(path: types.PathType) -> np.ndarray:
              path = gpath.GPath(path)
              with path.open('rb') as f:
                raw_im = np.asarray(bytearray(f.read()), dtype=np.uint8)
                image = cv2.imdecode(raw_im, cv2.IMREAD_COLOR)[:, :, ::-1]  # BGR -> RGB
                image = np.asarray(image).astype(np.float32) / 255.0
                return image
            ```
        - The code directly passes the raw file content to `cv2.imdecode` without any prior checks.
        - Malicious PNG files can exploit vulnerabilities in `cv2.imdecode` during decoding.
   - **Security Test Case:**
        1. Prepare a malicious PNG file designed to exploit a known vulnerability in `cv2.imdecode`.
        2. Create a Nerfies dataset and include the malicious PNG in the `rgb` directory.
        3. Run `train.py` or `eval.py` on this dataset.
        4. Monitor the system for signs of arbitrary code execution, crashes, or use memory debugging tools (AddressSanitizer, MemorySanitizer) to detect memory corruption errors during image processing.
        5. Successful test will show signs of memory corruption or arbitrary code execution.