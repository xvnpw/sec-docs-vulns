- Vulnerability Name: Path Traversal in Image Loading
- Description:
  1. The application takes `--file_root` and `--img_root` command-line arguments to specify directories for pre-processed files and raw images.
  2. The `dataloader.py` scripts use these paths to load image file names from files within `--file_root` (e.g., `imgs_train.txt`, `imgs_test.txt`).
  3. When loading images, the code uses `os.path.join(img_root_path, path)` where `img_root_path` is from `--img_root` and `path` is read from files in `--file_root`.
  4. If an attacker can control the content of the files in `--file_root` (e.g., by providing a crafted `imgs_train.txt` file) and the application uses a user-provided or attacker-controlled `--file_root` and `--img_root` without validation, they can insert path traversal sequences (e.g., `../../`) into the image paths in `imgs_train.txt`.
  5. When the application attempts to load these images, `os.path.join` will resolve the path traversal sequences, potentially leading to access to files outside the intended `img_root_path`.
- Impact:
  An attacker can read arbitrary files from the server's filesystem if the application processes attacker-controlled file paths without validation. This could lead to information disclosure, including sensitive data, source code, or configuration files.
- Vulnerability Rank: High
- Currently Implemented Mitigations: None
- Missing Mitigations:
  - Input validation for `--file_root` and `--img_root` to ensure they are valid and safe paths.
  - Sanitization of image paths read from files within `--file_root` to remove or neutralize path traversal sequences before using them in `os.path.join`.
- Preconditions:
  - The attacker needs to be able to provide or influence the content of the files within the directory specified by `--file_root` (e.g., `imgs_train.txt`).
  - The application must be deployed in an environment where it processes user-provided or untrusted `--file_root` and `--img_root` without validation.
- Source Code Analysis:
  - In `/code/src/argument_parser.py`, `add_base_args` defines `--file_root` and `--img_root` using `parser.add_argument(...)`.
  - In `/code/src/dataloader.py`, classes `Data`, `DataQuery`, `DataTriplet` take `file_root` and `img_root_path` in their `__init__` methods.
  - In `/code/src/dataloader.py`, methods `_load_dataset` in these classes read image file names from files located in `file_root` (e.g., `os.path.join(self.file_root, "imgs_%s.txt" % self.mode))`).
  - For example, in `Data` class, `_load_dataset` method reads `imgs_train.txt` using `os.path.join(self.file_root, "imgs_%s.txt" % self.mode)`:
    ```python
    with open(os.path.join(self.file_root, "imgs_%s.txt" % self.mode)) as f:
        img_data = f.read().splitlines()
    ```
  - In `/code/src/dataloader.py`, methods `__getitem__` in these classes use `os.path.join(self.img_root_path, self.img_data[index])` to open images.
  - For example, in `Data` class, `__getitem__` method opens image using `os.path.join(self.img_root_path, self.img_data[index])`:
    ```python
    img = Image.open(os.path.join(self.img_root_path, self.img_data[index]))
    ```
  - No validation or sanitization is performed on `file_root`, `img_root_path`, or `self.img_data[index]` before using `os.path.join`.
- Security Test Case:
  1. Prepare a malicious `imgs_train.txt` file within a directory. This file should contain a path traversal string, for example: `../../../../../../../../etc/passwd`. Let's say this directory is `/tmp/malicious_files`.
  2. Create a dummy image file (e.g., `dummy.jpg`) and place it in a separate image directory, for example, `/tmp/images`.
  3. Run one of the training scripts (e.g., `train_attr_pred.py`) with the following command-line arguments:
     ```bash
     python src/train_attr_pred.py --file_root /tmp/malicious_files --img_root /tmp/images --dataset_name Shopping100k --ckpt_dir test_output
     ```
  4. Observe the output and logs. If the vulnerability is present, the application might attempt to open `/etc/passwd` (or fail with an error if permissions are insufficient). Check for error messages related to accessing `/etc/passwd` or other system files, which would indicate a path traversal attempt. For example, you might see an `IOError: [Errno 13] Permission denied: /etc/passwd` if run as a non-root user.