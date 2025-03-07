## Combined Vulnerability List

### Malicious Script Execution via Compromised Download Server

- **Vulnerability Name:** Malicious Script Execution via Compromised Download Server
- **Description:**
  1. A user downloads shell scripts (e.g., `dldata.sh`, `dlweights.sh`) from the repository, intending to download datasets and pretrained weights.
  2. Following project instructions, the user executes a downloaded script on their local machine.
  3. These scripts use `gsutil cp` or `gsutil -m cp` to fetch data from `gs://omnimatte/`. For instance, `dldata.sh` retrieves datasets from `gs://omnimatte/data/`, and `dlweights.sh` gets weights from `gs://omnimatte/models/`.
  4. The scripts directly download and automatically extract archives (e.g., `.tar.gz`, `.zip`) using `tar -xf` or `unzip`.
  5. If an attacker compromises the `gs://omnimatte/` Google Cloud Storage bucket, they can replace legitimate files with malicious ones of the same name.
  6. When a user runs the scripts, they unknowingly download these malicious files.
  7. Specifically, malicious archives at `gs://omnimatte/data/` or `gs://omnimatte/models/` will be downloaded and their embedded code executed upon extraction via `tar -xf` or `unzip`, leading to arbitrary code execution on the user's system.
- **Impact:**
  Critical. Exploitation allows arbitrary code execution on the user's machine, leading to:
    - Full system compromise.
    - Data theft.
    - Malware installation.
    - Denial of service.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:** None
- **Missing Mitigations:**
  - Implement integrity checks (checksum verification).
  - Use digital signatures for data and weight files.
  - Enforce HTTPS and warn users about download risks.
  - Educate users and warn about executing downloaded scripts.
  - Provide alternative, safer download methods with verification.
- **Preconditions:**
  - Attacker compromises `gs://omnimatte/` Google Cloud Storage bucket.
  - User downloads and executes scripts without inspection.
- **Source Code Analysis:**
  - **`/code/scripts/dldata.sh`**: Downloads and extracts `.tar.gz` archives using `tar -xf`.
    ```bash
    gsutil -m cp gs://omnimatte/data/kubric-shadows-v1-train.tar.gz data/
    ...
    cd data
    for x in *tar.gz; do
      tar -xf $x  # Vulnerable extraction
    done
    ```
  - **`/code/scripts/dlweights.sh`**: Downloads and extracts `weights.zip` using `unzip`.
    ```bash
    WEIGHTSDIR=pretrained_weights
    mkdir $WEIGHTSDIR
    gsutil cp gs://omnimatte/models/weights.zip $WEIGHTSDIR/
    unzip pretrained_weights/weights.zip -d $WEIGHTSDIR/ # Vulnerable extraction
    ```
- **Security Test Case:**
  1. Set up a malicious server mimicking `gs://omnimatte/`.
  2. Create a malicious `weights.zip` with embedded executable.
  3. Host `weights.zip` on the malicious server.
  4. Modify `dlweights.sh` to download from the malicious server (e.g., using `wget`).
  5. Run modified `dlweights.sh`.
  6. Verify if malicious code in `weights.zip` executes (e.g., check for file creation in `/tmp`).

### Path Traversal

- **Vulnerability Name:** Path Traversal
- **Description:**
  An attacker can read or write files outside the custom video directory by manipulating filenames in custom video data. The application constructs file paths by concatenating user-provided paths and filenames without sanitization. By crafting filenames with path traversal sequences (e.g., `../../../sensitive_file`), an attacker can access files outside the intended directory. For instance, a symbolic link named `../../../sensitive_file.png` in `<my_video>/rgb/` could lead to accessing `/etc/passwd` if processed.
- **Impact:**
  An attacker could read sensitive files (configuration, source code, user data) or potentially overwrite/delete files, leading to data corruption or system instability.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:** None
- **Missing Mitigations:**
  - Input validation and sanitization for file paths and filenames.
  - Validate custom video directory path.
  - Sanitize filenames (remove/escape `..`, `/`, `\`).
  - Use secure file path manipulation functions to prevent traversal.
- **Preconditions:**
  - User uses "Custom video" feature.
  - Application processes user-provided file paths for video frames, masks.
  - Lack of input validation for file paths and filenames.
- **Source Code Analysis:**
  - **`/code/src/dataset.py`**, `OmnimatteDataLoader.get_maskpath`: Unsafe path construction.
    ```python
    def get_maskpath(self, viddir, obj_id, fn):
        return f'{viddir}/mask/{obj_id}/{fn.split("/")[-1]}' # Vulnerable path construction
    ```
    - `viddir` from user input (`config.datadir`).
    - `fn` from user-provided directory content.
    - Direct concatenation without sanitization.
- **Security Test Case:**
  1. Setup:
     - Create `test_video/rgb` with symlink `../../../passwd.png` -> `/etc/passwd` and `frame1.png`.
     - Create `test_video/mask/01` with `frame1.png`.
     - Create `test_video/bg_est.png`.
  2. Execution: Run inference/training scripts with `--config.datadir=./test_video`.
  3. Verification: Check system logs or application logs (if modified to log file access in `read_image`) for attempts to access `/etc/passwd`.

### Potential JPEG processing vulnerability in `tf.io.decode_jpeg`

- **Vulnerability Name:** Potential JPEG processing vulnerability in `tf.io.decode_jpeg`
- **Description:**
  1. An attacker crafts a malicious JPEG file to exploit vulnerabilities in TensorFlow's `tf.io.decode_jpeg`.
  2. The attacker replaces RGB frames in a custom video dataset with the malicious JPEG.
  3. Finetuning is initiated using provided scripts with the malicious dataset.
  4. `read_crop_im` in `src/dataset.py` processes frames.
  5. `tf.io.decode_jpeg` decodes the malicious JPEG.
  6. Exploitation of `tf.io.decode_jpeg` vulnerability can lead to crash or arbitrary code execution.
- **Impact:** High. Arbitrary code execution on the server, potentially leading to system control, data theft, or malicious actions.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:** None
- **Missing Mitigations:**
  - Input sanitization for JPEG files.
  - Use safer image decoding library (if feasible).
  - Sandbox image processing operations.
- **Preconditions:**
  - Finetuning mode enabled (custom video data allowed).
  - Attacker can provide a custom video dataset with malicious JPEG.
  - Vulnerable TensorFlow version is used.
- **Source Code Analysis:**
  - **`/code/src/dataset.py`**, `read_crop_im`: Vulnerable JPEG decoding.
    ```python
    def read_crop_im(im, im_width, im_height, channels=3, order='CHW', crop=None):
        im = tf.io.decode_jpeg(im, channels=channels) # Vulnerable JPEG decoding
        ...
    ```
    - `im` comes from user-supplied video files.
    - Direct use of `tf.io.decode_jpeg` without validation.
- **Security Test Case:**
  1. Create a malicious JPEG file exploiting a known `tf.io.decode_jpeg` vulnerability (using tools or public exploits).
  2. Create a malicious video dataset: replace `.png` frames with the malicious JPEG (renamed to `.png` if needed).
  3. Run finetuning script with `--config.datadir` pointing to the malicious dataset.
  4. Monitor for crashes, errors, or unusual system behavior indicating exploitation during data loading.

### Potential Image processing vulnerability in `PIL.Image.open`

- **Vulnerability Name:** Potential Image processing vulnerability in `PIL.Image.open`
- **Description:**
  1. An attacker crafts a malicious image (PNG, GIF, etc.) to exploit vulnerabilities in Pillow's `PIL.Image.open`.
  2. The attacker replaces background images (`bg_est.png`) or mask images (`mask/01/*.png`) in custom or evaluation datasets with the malicious image.
  3. Finetuning or evaluation is initiated, processing the malicious image.
  4. `read_image` in `src/utils.py` is called to load images.
  5. `PIL.Image.open(filepath).convert(pil_format)` processes the malicious image.
  6. Exploitation of `PIL.Image.open` vulnerability can lead to crash, DoS, or arbitrary code execution.
- **Impact:** High. Arbitrary code execution, potentially leading to server compromise, data theft, or disruption.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:** None
- **Missing Mitigations:**
  - Input sanitization and validation for image files.
  - Consider safer image processing libraries.
  - Sandbox image processing operations.
- **Preconditions:**
  - Application processes user-supplied images (finetuning, evaluation).
  - Attacker can provide malicious image files as background or mask images.
  - Vulnerable Pillow version is used.
- **Source Code Analysis:**
  - **`/code/src/utils.py`**, `read_image`: Vulnerable image loading.
    ```python
    def read_image(filepath, width=None, height=None, pil_format='RGB'):
        im = Image.open(filepath).convert(pil_format) # Vulnerable image loading
        return im
    ```
    - `filepath` from user-provided data directories.
    - Direct use of `PIL.Image.open` without validation.
- **Security Test Case:**
  1. Craft a malicious image file exploiting a known Pillow vulnerability (using tools or public exploits for PNG, GIF, etc.).
  2. Prepare a malicious dataset:
     - Finetuning: replace `bg_est.png` or mask images in custom dataset.
     - Evaluation: replace `bg_128.png` or mask images in evaluation dataset.
  3. Execute finetuning or evaluation scripts, pointing to the malicious dataset.
  4. Monitor for crashes, errors, or unexpected behavior during image loading, indicating exploitation of `PIL.Image.open`.