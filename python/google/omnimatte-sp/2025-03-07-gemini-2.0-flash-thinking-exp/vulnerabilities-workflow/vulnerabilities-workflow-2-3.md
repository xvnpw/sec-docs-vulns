- Vulnerability Name: Path Traversal
- Description:
An attacker could potentially read or write files outside of the intended custom video directory by crafting malicious filenames within the custom video data provided for finetuning. The application, when processing a custom video, relies on user-provided file paths and filenames to locate video frames, masks, and background images. If the application does not properly sanitize or validate these paths and filenames, an attacker could manipulate them to access files in directories outside the designated custom video input directory. For example, if the application expects images in `<my_video>/rgb/*.png` and constructs paths by simply concatenating directory names and filenames, an attacker could create symbolic links or files with names like `../../../sensitive_file` within the `<my_video>/rgb/` directory. When the application processes these crafted filenames, it might resolve the path to locations outside the intended `<my_video>` directory, leading to unauthorized file access or manipulation.

Steps to trigger the vulnerability:
1. Prepare a custom video directory structure as described in the README, but include a malicious file or symbolic link within the rgb or mask subdirectories. For example, create a symbolic link named `../../../sensitive_file.png` inside `<my_video>/rgb/` that points to a sensitive file on the system, like `/etc/passwd`.
2. Run the training or inference scripts, providing the path to the malicious custom video directory `<my_video>` as input.
3. If the application is vulnerable, it will attempt to process the malicious filename, potentially leading to access or manipulation of the file pointed to by the crafted path (e.g., `/etc/passwd` in the symbolic link example).

- Impact:
An attacker could read sensitive files from the server's filesystem, potentially gaining access to configuration files, source code, or user data. In more severe scenarios, depending on the application's file handling capabilities and permissions, an attacker might also be able to overwrite or delete files outside the intended directory, leading to data corruption or system instability.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
None identified in the provided project files. The code appears to directly construct file paths based on user-provided directory and filenames without explicit sanitization or validation.
- Missing Mitigations:
Input validation and sanitization for all user-provided file paths and filenames are missing. The application should:
    - Validate that the provided custom video directory path is within expected boundaries.
    - Sanitize filenames to remove or escape characters like `..`, `/`, and `\` that could be used for path traversal.
    - Use secure file path manipulation functions that prevent traversal outside the intended directory (e.g., using functions that resolve paths relative to a safe base directory and prevent escaping this base).
- Preconditions:
    - The user must be instructed or intend to use the "Custom video" feature.
    - The application must process user-provided file paths and filenames to access video frames, masks, or background images within the custom video directory.
    - The application must lack proper input validation and sanitization for these file paths and filenames.
- Source Code Analysis:
In `src/dataset.py`, within the `OmnimatteDataLoader` class, the `get_maskpath` function constructs file paths like this:
```python
def get_maskpath(self, viddir, obj_id, fn):
    return f'{viddir}/mask/{obj_id}/{fn.split("/")[-1]}'
```
- `viddir` is derived from user input (`config.datadir`).
- `fn` (filename) is taken from the list of RGB frames, which, in the case of custom video, are located within the user-provided directory.
- The code uses f-strings to directly concatenate these components without any explicit sanitization or validation.
- If a malicious user crafts a filename within the `<my_video>/rgb/` directory (e.g., by creating a symbolic link with a path traversal sequence in its name), and if this filename is processed by `get_maskpath`, the resulting path could traverse outside the intended `<my_video>` directory.

For example, if `viddir` is `/path/to/my_video` and a malicious filename `../../../sensitive_file.png` exists in `<my_video>/rgb/`, and `fn` is constructed based on this malicious filename, then `fn.split("/")[-1]` would be `../../../sensitive_file.png`. The resulting `get_maskpath` would be `/path/to/my_video/mask/{obj_id}/../../../sensitive_file.png`, which, after path resolution, could point to `/path/to/sensitive_file.png` if `/path/to/my_video/mask/{obj_id}` does not exist or is ignored in path resolution.

- Security Test Case:
1. **Setup:**
    - Create a directory named `test_video`.
    - Inside `test_video`, create subdirectories `rgb` and `mask`.
    - Inside `test_video/rgb`, create a symbolic link named `../../../passwd.png` that points to `/etc/passwd` (or a similar sensitive file).
    - Create a dummy PNG file named `frame1.png` inside `test_video/rgb/`.
    - Inside `test_video/mask`, create a subdirectory `01`.
    - Inside `test_video/mask/01`, create a dummy PNG file named `frame1.png`.
    - Create a dummy `bg_est.png` inside `test_video`.
2. **Execution:**
    - Run the inference script: `./scripts/inference.sh` or training script: `./scripts/train-real.sh` or `./scripts/train-synth.sh`.
    - Modify the script command to use `--config.datadir=./test_video` to point to the malicious custom video directory.
    - Run the script.
3. **Verification:**
    - After the script execution, check if there are any attempts to read or access the `/etc/passwd` file. This might be observable through system logs or by monitoring file access.
    - Alternatively, modify the script or add logging to the `read_image` function in `src/utils.py` to log the file paths being accessed. Check if the log shows an attempt to access `/etc/passwd` or a path outside the `test_video` directory due to the malicious symbolic link.
4. **Expected Result:**
    - If the application is vulnerable, the logs or system monitoring should indicate an attempt to access `/etc/passwd` (or the target of the symbolic link), proving path traversal.
    - If mitigated, the application should either fail to process the malicious filename, throw an error, or only access files within the intended `test_video` directory, without attempting to access `/etc/passwd`.