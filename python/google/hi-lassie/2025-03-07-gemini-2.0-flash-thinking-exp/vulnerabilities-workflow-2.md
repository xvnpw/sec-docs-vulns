## Combined Vulnerability List

### Path Traversal Vulnerability in Data Preprocessing Scripts

- **Vulnerability Name:** Path Traversal in Data Preprocessing Scripts
- **Description:**
    1. An attacker crafts a malicious dataset for LASSIE or Pascal-part datasets. This malicious dataset includes image filenames designed to exploit path traversal, such as filenames containing sequences like `../` to navigate out of expected directories.
    2. The user downloads and places this maliciously crafted dataset into the designated data directories as instructed in the `README.md` (e.g., `data/lassie/images/` or `data/pascal_part/JPEGImages/`).
    3. The user executes the data preprocessing scripts, `preprocess_lassie.py` or `preprocess_pascal.py`, for the corresponding animal class, as guided by the `README.md`.
    4. Within these scripts, the code constructs file paths using `os.path.join` by combining the base data directory (e.g., `cfg.lassie_img_dir`, `cfg.pascal_img_dir`) with filenames directly derived from the malicious dataset.
    5. Due to the lack of proper sanitization or validation of these filenames, the path traversal sequences (e.g., `../`) are processed by `os.path.join`. This allows the script to resolve file paths that are outside the intended data directories.
    6. Subsequently, when the preprocessing scripts attempt to perform file operations, such as reading images using `cv2.imread` or saving processed data, these operations are conducted based on the manipulated paths.
    7. Consequently, an attacker can achieve arbitrary file write by controlling the output path via malicious filenames, potentially overwriting sensitive files outside the intended data directories, depending on the subsequent operations performed by the preprocessing script with the traversed path. Additionally, an attacker can read arbitrary files from the server's filesystem, potentially including sensitive data, configuration files, or even source code, depending on the server's file permissions and the attacker's crafted paths.
- **Impact:**
    - Arbitrary File Write: A successful path traversal attack enables an attacker to write files to locations outside the intended data directories.
    - Potential Code Execution: If an attacker can overwrite critical system files or libraries, it could lead to arbitrary code execution on the system running the preprocessing scripts.
    - Data Corruption: Overwriting existing files, even within the project directory, can lead to data corruption and disrupt the functionality of the Hi-LASSIE project.
    - Arbitrary File Read: An attacker can read arbitrary files from the server's filesystem, potentially including sensitive data.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - None: The code does not implement any explicit sanitization or validation of filenames extracted from the datasets to prevent path traversal vulnerabilities.
- **Missing Mitigations:**
    - Path Sanitization: Implement robust path sanitization techniques in `preprocess_lassie.py` and `preprocess_pascal.py`. Before using any filename from the dataset to construct a file path, the code should validate and sanitize the filename to remove or neutralize any path traversal sequences (e.g., `../`, `./`, absolute paths).
    - Input Validation: Implement strict input validation to ensure that filenames from the dataset conform to expected patterns and do not contain malicious characters or sequences that could be exploited for path traversal. The `animal_class` argument and the 'id' values from the CSV should be strictly validated as well.
    - Secure File Path Construction: While `os.path.join` is used, it's not sufficient to prevent path traversal when filenames themselves are malicious. Consider using methods that canonicalize paths and verify that the resulting path stays within the intended directory, or use chroot-like environments for processing. Path normalization using `os.path.normpath` and checks to ensure the path resides within the intended base directory should be implemented.
    - Principle of Least Privilege: Ensure that the user running the preprocessing scripts operates with the minimum necessary privileges to reduce the potential damage from arbitrary file write vulnerabilities.
    - Sandboxing or restricted permissions: Running the preprocessing scripts in a sandboxed environment or with restricted file system permissions could limit the impact of a path traversal vulnerability.
- **Preconditions:**
    - The attacker must be able to create or modify a dataset (LASSIE or Pascal-part) to include malicious filenames or malicious content in annotation files. This could be achieved by compromising a source where these datasets are obtained or by tricking users into using a malicious dataset.
    - The user must download and use the compromised dataset and execute either `preprocess_lassie.py` or `preprocess_pascal.py` script, potentially with a maliciously crafted class name.
- **Source Code Analysis:**
    - **File: `/code/main/preprocess_lassie.py`**
        ```python
        with open(osp.join(cfg.lassie_ann_dir, '%s.csv'%cfg.animal_class), 'r') as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader):
                img_id = int(row['id'])
                img_file = osp.join(cfg.lassie_img_dir, '%s/input_%d.png'%(cfg.animal_class, img_id))
                img = cv2.imread(img_file)[:,:,2::-1]/255.
        ```
        - In `preprocess_lassie.py`, `img_file` is constructed using `osp.join(cfg.lassie_img_dir, '%s/input_%d.png'%(cfg.animal_class, img_id))`. The potential vulnerability lies in how `img_file` is used in `cv2.imread(img_file)`. If a malicious entry in the CSV file (or if the image files themselves are named maliciously) leads to `img_file` containing path traversal characters, `cv2.imread` will attempt to read from that potentially manipulated path. Also, the filename for the annotation file is built using `cfg.animal_class`, which if malicious, could also lead to path traversal when opening the annotation file itself.

    - **File: `/code/main/preprocess_pascal.py`**
        ```python
        img_list = osp.join(cfg.pascal_img_set_dir, '%s.txt'%cfg.animal_class)
        with open(img_list, 'r') as f:
            img_files = [img_file.replace('\n','') for img_file in f.readlines()]

        for i, img in enumerate(img_files):
            img_id = img.split('/')[-1].replace('.jpg','')
            ann_file = osp.join(cfg.pascal_ann_dir, img_id + '.mat')
            ann = loadmat(ann_file)
            obj = ann['anno'][0,0]['objects'][0,0]
            parts = obj["parts"]

            img = cv2.imread(osp.join(cfg.pascal_img_dir, img))[:,:,2::-1]/255.
        ```
        - In `preprocess_pascal.py`, `img_files` is a list of filenames read directly from `osp.join(cfg.pascal_img_set_dir, '%s.txt'%cfg.animal_class)`. The script iterates through `img_files` and directly passes each `img` filename to `cv2.imread(osp.join(cfg.pascal_img_dir, img))`. If the `img_files` list contains malicious filenames like `../../../evil.jpg`, `os.path.join` will construct the path, and `cv2.imread` will try to read from the attacker-specified path. Similar to `preprocess_lassie.py`, the filename for the image list is constructed using `cfg.animal_class`, posing a path traversal risk during file opening.

    - **Visualization:**
        Imagine `cfg.pascal_img_dir` is `/path/to/project/data/pascal_part/JPEGImages/` and a malicious `image_sets/horse.txt` contains a line `../../../evil.jpg`.
        When `preprocess_pascal.py` reads this line into `img`, `img` becomes `../../../evil.jpg`.
        Then, `cv2.imread(osp.join(cfg.pascal_img_dir, img))` becomes `cv2.imread('/path/to/project/data/pascal_part/JPEGImages/../../../evil.jpg')`.
        `os.path.join` simplifies this to `cv2.imread('/path/to/project/evil.jpg')`, effectively traversing out of the intended directory.

- **Security Test Case:**
    1. **Prepare a malicious Pascal-part dataset:**
        - Create a directory structure mimicking the Pascal-part dataset structure. You will need the `image_sets`, `JPEGImages` and `Annotations_Part` directories.
        - Inside `data/pascal_part/image_sets/`, create or modify the file `horse.txt`. Add a line containing a path traversal filename, for example: `../../../evil.jpg`.
        - Create a dummy file named `evil.txt` in the root directory of the project (e.g., `/path/to/Hi-LASSIE/evil.txt`).
    2. **Run the `preprocess_pascal.py` script:**
        - Execute the preprocessing script for the horse class:
          ```bash
          python main/preprocess_pascal.py --cls horse
          ```
    3. **Check for arbitrary file write:**
        - After running the script, check if a file named `evil_dino_feat.npy` has been created in the root directory of the project (e.g., `/path/to/Hi-LASSIE/`).
    Alternatively, for `preprocess_lassie.py` test:
    1. **Create malicious LASSIE dataset components**:
        - Create `data/lassie/annotations/test_exploit/test_exploit.csv` with:
            ```csv
            id,kps
            0,{"keypointlabels": [], "x": 0, "y": 0}
            ```
        - Create `data/lassie/images/test_exploit/` and a symlink inside:
            ```bash
            ln -s ../../../evil.txt data/lassie/images/test_exploit/input_0.png
            ```
    2. **Run `preprocess_lassie.py`**:
        ```bash
        python main/preprocess_lassie.py --cls test_exploit
        ```
    3. **Check for file access/errors**: Observe if the script attempts to access `evil.txt` or throws errors related to accessing files outside the expected directory.


### Image File Processing Vulnerability in Preprocessing Scripts

- **Vulnerability Name:** Image File Processing Vulnerability in Preprocessing Scripts
- **Description:**
    The `preprocess_lassie.py` and `preprocess_pascal.py` scripts utilize the `cv2.imread()` function from the OpenCV library to load and process image files. OpenCV is susceptible to vulnerabilities when handling maliciously crafted image files. By processing a specially crafted image, an attacker could potentially exploit vulnerabilities within OpenCV's image decoding or processing routines. This could lead to arbitrary code execution on the system running the preprocessing scripts.

    Step-by-step trigger:
    1. An attacker crafts a malicious image file (e.g., PNG, JPEG, etc.) designed to exploit a known or zero-day vulnerability in OpenCV's `imread` function.
    2. The attacker replaces a legitimate image file within the LASSIE dataset (`data/lassie/images/{animal_class}/`) or Pascal-part dataset (`data/pascal_part/JPEGImages/`) with the malicious image file.
    3. The attacker executes either the `preprocess_lassie.py` or `preprocess_pascal.py` script, targeting the animal class dataset where the malicious image has been placed.
    4. When the preprocessing script encounters the malicious image file and calls `cv2.imread()` to load it, the vulnerability in OpenCV is triggered.
    5. Depending on the nature of the vulnerability, this could lead to arbitrary code execution, potentially allowing the attacker to gain control of the system or perform other malicious actions.

- **Impact:**
    Arbitrary code execution. Successful exploitation of this vulnerability could allow an attacker to execute arbitrary code on the machine running the preprocessing script, leading to a complete system compromise.

- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    None. The code directly uses `cv2.imread()` to load image files without any explicit validation or sanitization of the image file content or format.

- **Missing Mitigations:**
    - Input validation: Implement checks to validate the image file format and, to the extent possible, the image content before processing.
    - Sandboxing: Execute the preprocessing scripts within a sandboxed environment to restrict permissions.
    - Dependency updates: Regularly update the OpenCV library to the latest version to incorporate security patches.
    - Alternative Image Processing Libraries: Consider using safer or hardened image processing libraries.

- **Preconditions:**
    - The attacker needs to be able to place a malicious image file in a dataset directory that will be processed by the scripts.
    - The preprocessing script must be executed on the dataset containing the malicious image.

- **Source Code Analysis:**
    ```python
    img_file = osp.join(cfg.lassie_img_dir, '%s/input_%d.png'%(cfg.animal_class, img_id)) # in preprocess_lassie.py
    img = cv2.imread(img_file)[:,:,2::-1]/255.
    ```
    or
    ```python
    img = cv2.imread(osp.join(cfg.pascal_img_dir, img))[:,:,2::-1]/255. # in preprocess_pascal.py
    ```
    - `cv2.imread(img_file)`: This function from OpenCV is used to read the image file. OpenCV's image decoding functionality has had vulnerabilities. A malicious image can exploit parsing flaws in `imread`.
    - No validation: No checks are performed on `img_file` or the loaded `img` object before processing.

    **Visualization:**

    ```
    [Malicious Image] -->  [Replaces legitimate image in dataset]
                                            |
    [Run preprocess_lassie.py or preprocess_pascal.py]
                                            |
    [Script constructs image path] --> img_file
                                            |
    [cv2.imread(img_file)] ---------> [OpenCV Vulnerability Triggered]
                                            |
    [Potential Arbitrary Code Execution]
    ```

- **Security Test Case:**
    1. **Malicious Image Creation**: Create a malicious PNG image file named `malicious.png` designed to trigger an OpenCV vulnerability.
    2. **Image Replacement**: Navigate to a dataset image directory (e.g., `data/lassie/images/zebra/`) and replace an existing image (e.g., `input_0.png`) with `malicious.png` (renamed to `input_0.png`).
    3. **Script Execution**: Run the preprocessing script:
       ```bash
       python preprocess_lassie.py --cls zebra
       ```
    4. **Vulnerability Observation**: Monitor for script crashes, errors during image loading, or unexpected behavior indicating a vulnerability in `cv2.imread()`. Check terminal output and error logs for exceptions. For a more advanced test, craft the image to execute a specific payload and observe for its execution in a controlled environment.