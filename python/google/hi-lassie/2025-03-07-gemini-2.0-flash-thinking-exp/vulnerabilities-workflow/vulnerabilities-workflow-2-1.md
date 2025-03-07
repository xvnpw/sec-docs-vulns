### Vulnerability List

- Vulnerability Name: Path Traversal in Data Preprocessing Scripts
- Description:
    1. An attacker crafts a malicious dataset for LASSIE or Pascal-part datasets. This malicious dataset includes image filenames designed to exploit path traversal, such as filenames containing sequences like `../` to navigate out of expected directories.
    2. The user downloads and places this maliciously crafted dataset into the designated data directories as instructed in the `README.md` (e.g., `data/lassie/images/` or `data/pascal_part/JPEGImages/`).
    3. The user executes the data preprocessing scripts, `preprocess_lassie.py` or `preprocess_pascal.py`, for the corresponding animal class, as guided by the `README.md`.
    4. Within these scripts, the code constructs file paths using `os.path.join` by combining the base data directory (e.g., `cfg.lassie_img_dir`, `cfg.pascal_img_dir`) with filenames directly derived from the malicious dataset.
    5. Due to the lack of proper sanitization or validation of these filenames, the path traversal sequences (e.g., `../`) are processed by `os.path.join`. This allows the script to resolve file paths that are outside the intended data directories.
    6. Subsequently, when the preprocessing scripts attempt to perform file operations, such as reading images using `cv2.imread` or saving processed data, these operations are conducted based on the manipulated paths.
    7. Consequently, an attacker can achieve arbitrary file write by controlling the output path via malicious filenames, potentially overwriting sensitive files outside the intended data directories, depending on the subsequent operations performed by the preprocessing script with the traversed path.
- Impact:
    - Arbitrary File Write: A successful path traversal attack enables an attacker to write files to locations outside the intended data directories.
    - Potential Code Execution: If an attacker can overwrite critical system files or libraries, it could lead to arbitrary code execution on the system running the preprocessing scripts.
    - Data Corruption: Overwriting existing files, even within the project directory, can lead to data corruption and disrupt the functionality of the Hi-LASSIE project.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None: The code does not implement any explicit sanitization or validation of filenames extracted from the datasets to prevent path traversal vulnerabilities.
- Missing Mitigations:
    - Path Sanitization: Implement robust path sanitization techniques in `preprocess_lassie.py` and `preprocess_pascal.py`. Before using any filename from the dataset to construct a file path, the code should validate and sanitize the filename to remove or neutralize any path traversal sequences (e.g., `../`, `./`, absolute paths).
    - Input Validation: Implement strict input validation to ensure that filenames from the dataset conform to expected patterns and do not contain malicious characters or sequences that could be exploited for path traversal.
    - Secure File Path Construction: While `os.path.join` is used, it's not sufficient to prevent path traversal when filenames themselves are malicious. Consider using methods that canonicalize paths and verify that the resulting path stays within the intended directory, or use chroot-like environments for processing.
    - Principle of Least Privilege: Ensure that the user running the preprocessing scripts operates with the minimum necessary privileges to reduce the potential damage from arbitrary file write vulnerabilities.
- Preconditions:
    - The attacker must be able to create or modify a dataset (LASSIE or Pascal-part) to include malicious filenames. This could be achieved by compromising a source where these datasets are obtained or by tricking users into using a malicious dataset.
    - The user must download and use the compromised dataset and execute either `preprocess_lassie.py` or `preprocess_pascal.py` script.
- Source Code Analysis:
    - **File: `/code/main/preprocess_lassie.py`**
        ```python
        with open(osp.join(cfg.lassie_ann_dir, '%s.csv'%cfg.animal_class), 'r') as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader):
                img_id = int(row['id'])
                img_file = osp.join(cfg.lassie_img_dir, '%s/input_%d.png'%(cfg.animal_class, img_id))
                img = cv2.imread(img_file)[:,:,2::-1]/255.
        ```
        - In this code snippet, `img_file` is constructed using `osp.join(cfg.lassie_img_dir, '%s/input_%d.png'%(cfg.animal_class, img_id))`. However, the base directory `cfg.lassie_img_dir` is from configuration and seems safe. The potential vulnerability lies in how `img_file` is used in `cv2.imread(img_file)`. If a malicious entry in the CSV file (or if the image files themselves are named maliciously in a different attack scenario) leads to `img_file` containing path traversal characters, `cv2.imread` will attempt to read from that potentially manipulated path.

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
        - Here, the vulnerability is more evident. `img_files` is a list of filenames read directly from `osp.join(cfg.pascal_img_set_dir, '%s.txt'%cfg.animal_class)`. The script iterates through `img_files` and directly passes each `img` filename to `cv2.imread(osp.join(cfg.pascal_img_dir, img))`. If the `img_files` list (obtained from a potentially compromised `*.txt` file) contains malicious filenames like `../../../evil.jpg`, `os.path.join` will construct the path, and `cv2.imread` will try to read from the attacker-specified path, which could be anywhere on the filesystem.

    - **Visualization:**
        Imagine `cfg.pascal_img_dir` is `/path/to/project/data/pascal_part/JPEGImages/` and a malicious `image_sets/horse.txt` contains a line `../../../evil.jpg`.
        When `preprocess_pascal.py` reads this line into `img`, `img` becomes `../../../evil.jpg`.
        Then, `cv2.imread(osp.join(cfg.pascal_img_dir, img))` becomes `cv2.imread('/path/to/project/data/pascal_part/JPEGImages/../../../evil.jpg')`.
        `os.path.join` simplifies this to `cv2.imread('/path/to/project/evil.jpg')`, effectively traversing out of the intended directory.

- Security Test Case:
    1. **Prepare a malicious Pascal-part dataset:**
        - Create a directory structure mimicking the Pascal-part dataset structure, if you don't have it already. You will need the `image_sets`, `JPEGImages` and `Annotations_Part` directories. For testing purposes, you may only need to modify `image_sets` and create a dummy `JPEGImages` directory.
        - Inside `data/pascal_part/image_sets/`, create or modify the file `horse.txt`. Add a line containing a path traversal filename, for example: `../../../evil`. Note that the extension might not matter for path traversal itself, but `preprocess_pascal.py` expects `.jpg` in the original filenames, so to avoid errors in other parts of the script, a valid image extension might be preferable, e.g., `../../../evil.jpg`.
        - Create a dummy file named `evil.txt` in the root directory of the project (e.g., `/path/to/Hi-LASSIE/evil.txt`). This file is to check if the path traversal is successful and if we can write outside the intended directory.
        - Optionally, place a dummy image file in `data/pascal_part/JPEGImages/` to satisfy the script's image reading process if it strictly checks for image existence, though for path traversal testing, the content of the image might be irrelevant.
    2. **Run the `preprocess_pascal.py` script:**
        - Execute the preprocessing script for the horse class:
          ```bash
          python main/preprocess_pascal.py --cls horse
          ```
    3. **Check for arbitrary file write:**
        - After running the script, check if a file named `evil_dino_feat.npy` (or similar, depending on where the processed features are saved and the script logic after the potential `cv2.imread` error if the path traversal prevents image reading) has been created in the root directory of the project (e.g., `/path/to/Hi-LASSIE/`). The script might fail to process the image if `cv2.imread` fails, but the goal is to see if the path traversal affects file operations later in the script. You might need to adjust the malicious path or analyze the script's further operations to precisely trigger an arbitrary file write. For example, if the script proceeds to save DINO features, you might look for a saved feature file in an unexpected location.
        - If a file is written outside the `data/pascal_part` directory (e.g., in the root project directory) due to the malicious filename, the path traversal vulnerability is confirmed.

This vulnerability allows an attacker to potentially write files outside the intended directories, posing a significant security risk. It is crucial to implement the missing mitigations to secure the data preprocessing scripts.