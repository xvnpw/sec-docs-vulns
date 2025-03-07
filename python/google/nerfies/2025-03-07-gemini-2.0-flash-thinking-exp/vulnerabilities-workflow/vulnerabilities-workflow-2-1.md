* Vulnerability name: Insecure Deserialization in Camera Parameter Loading
* Description:
    1. The Nerfies project loads camera parameters from JSON files as described in the `README.md` within the `camera` subdirectory of a dataset.
    2. The `Camera.from_json` method in `/code/nerfies/camera.py` is used to deserialize camera parameters from these JSON files.
    3. An attacker can craft a malicious JSON file containing camera parameters (e.g., within `camera/${item_id}.json`).
    4. This malicious JSON file can inject unexpected data types or structures, or potentially exploit vulnerabilities in the JSON parsing library or the `Camera` class's constructor when processing these parameters.
    5. When a user trains or evaluates the Nerfies model using a dataset containing this malicious JSON file, the `Camera.from_json` method will parse the file.
    6. If the `Camera.from_json` method or the underlying JSON parsing process is vulnerable to insecure deserialization, it could lead to arbitrary code execution or other unexpected behavior when the malicious data is processed.
* Impact: Arbitrary code execution. An attacker could potentially gain control over the system running the Nerfies training or evaluation process if they can successfully inject malicious code through a crafted JSON camera parameter file.
* Vulnerability rank: Critical
* Currently implemented mitigations: None evident in the provided code. The code relies on standard JSON loading and class instantiation without explicit input validation or sanitization for security purposes.
* Missing mitigations:
    - Input validation and sanitization for all camera parameters loaded from JSON files within the `Camera.from_json` method. This should include checking data types, ranges, and structures to ensure they conform to expected values and prevent injection of malicious data.
    - Consider using a safer deserialization method if available or implement custom parsing logic with security in mind.
    - Implement error handling and input rejection to prevent processing of datasets with invalid or suspicious camera parameter files.
* Preconditions:
    - The attacker needs to be able to provide a malicious dataset to a user. This could be achieved by hosting the dataset online or distributing it through other channels, enticing users to download and use it for training or evaluation.
    - The user must then use the Nerfies training or evaluation scripts (`train.py` or `eval.py`) and point them to the attacker's malicious dataset directory.
* Source code analysis:
    1. **File:** `/code/nerfies/camera.py`
    2. **Class:** `Camera`
    3. **Method:** `from_json(cls, path: types.PathType)`
    4. **Code:**
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
        - The method `from_json` uses `json.load(fp)` to parse the JSON file. `json.load` in Python is generally safe from direct code execution vulnerabilities, but the *data* loaded is directly used to instantiate a `Camera` object.
        - The constructor `__init__` of the `Camera` class in the same file takes the parsed data and directly assigns it to the object's attributes without any explicit validation.
        - If a malicious JSON file contains unexpected data types or values for fields like `orientation`, `position`, `focal_length`, `principal_point`, `radial_distortion`, `tangential_distortion`, or `image_size`, it could potentially cause vulnerabilities when these parameters are used in subsequent computations within the Nerfies pipeline, or if there's a vulnerability in how numpy arrays are created with malicious data.
        - For example, if `image_size` is manipulated to be extremely large or negative, it could lead to issues in later image processing steps or memory allocation. While direct code execution via `json.load` is unlikely, unexpected behavior or exploitation of downstream vulnerabilities due to malformed data is possible.

* Security test case:
    1. **Create a malicious JSON camera file:** Create a file named `000000.json` inside a directory named `camera`. This JSON file will contain malicious data for camera parameters. For example, to test for unexpected data types, we can inject a string where a numerical array is expected, or inject extremely large numerical values.

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

    2. **Prepare a minimal dataset:** Create a minimal dataset directory with the following structure:

        ```
        malicious_dataset/
        ├── camera/
        │   └── 000000.json  (malicious file from step 1)
        ├── rgb/
        │   └── 1x/
        │       └── 000000.png (any valid PNG image)
        ├── metadata.json (minimal metadata)
        ├── dataset.json (minimal dataset split)
        └── scene.json (minimal scene info)
        ```
        Minimal content for `metadata.json`, `dataset.json`, and `scene.json` can be created based on the examples in `README.md`, ensuring they are valid JSON but minimal for testing purposes. For `rgb/1x/000000.png`, a small, valid PNG image needs to be placed.

    3. **Run training or evaluation:** Execute the `train.py` or `eval.py` script, pointing it to the `malicious_dataset` directory using the `--data_dir` flag.

        ```bash
        python train.py --data_dir /path/to/malicious_dataset --base_folder /tmp/nerfies_test --gin_configs configs/test_vrig.gin
        ```
        or
        ```bash
        python eval.py --data_dir /path/to/malicious_dataset --base_folder /tmp/nerfies_test --gin_configs configs/test_vrig.gin
        ```

    4. **Observe the behavior:** Monitor the execution of the script. Check for error messages, crashes, or unexpected behavior. Specifically, look for signs that the malicious JSON data is causing issues during parsing or later processing. If the application crashes or exhibits unexpected behavior related to camera parameter processing, it indicates a potential vulnerability. A successful exploit might be difficult to directly demonstrate without deeper code analysis to identify specific injection points, but instability or crashes during parsing of crafted data are strong indicators.