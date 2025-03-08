- Vulnerability Name: Path Traversal in `--store_dir` argument

- Description:
  The `main.py` script uses the `--store_dir` command-line argument to specify the directory where experiment results and checkpoints are stored. This directory path, provided by the user, is directly used in file system operations without proper sanitization. A malicious user can craft a `--store_dir` argument containing path traversal sequences like `../` to manipulate the directory where files are written. For example, by providing `--store_dir /tmp/../../malicious_dir`, the application might write files into the `/malicious_dir` directory, outside the intended project directory.

  Steps to trigger the vulnerability:
  1. An attacker executes the `main.py` script.
  2. The attacker provides a crafted `--store_dir` argument that includes path traversal sequences, such as `../` or absolute paths pointing outside the intended storage directory. For example: `--store_dir /tmp/../../malicious_dir`.
  3. The `main.py` script uses this unsanitized path to construct file paths for storing checkpoints and experiment results using `os.path.join`.
  4. Due to path traversal sequences, files are written to a directory outside the intended storage location, as specified by the attacker in the crafted `--store_dir` argument.

- Impact:
  A successful path traversal attack can lead to arbitrary file write. An attacker could potentially:
    - Overwrite critical system files, leading to system instability or denial of service.
    - Write files to sensitive directories, potentially gaining unauthorized access or control.
    - Write malicious scripts or executables to startup directories or other locations where they might be executed, leading to further compromise of the system.
    - Expose sensitive information by writing experiment data to publicly accessible directories.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
  None. The code directly uses the user-supplied `--store_dir` argument without any validation or sanitization.

- Missing Mitigations:
  - **Path Sanitization:** Implement path sanitization to remove or neutralize path traversal sequences like `../` from the user-supplied `--store_dir` argument.
  - **Path Validation:** Validate the provided `--store_dir` argument to ensure it is within an expected base directory and does not contain malicious path traversal sequences. Consider using functions like `os.path.abspath` and checking if the resulting path is still within the intended base directory.
  - **Restrict Path Scope:**  Instead of allowing arbitrary paths, restrict the `--store_dir` to be a subdirectory within a predefined project results directory.

- Preconditions:
  - The user must be able to execute the `main.py` script and provide command-line arguments, specifically the `--store_dir` argument.
  - The application must have write permissions to the file system locations where the attacker intends to write files through path traversal.

- Source Code Analysis:
  1. **`wide_bnn_sampling/main.py`:**
     - The `store_dir` flag is defined:
       ```python
       flags.DEFINE_string(
           'store_dir', '~/wide_bnn_sampling', 'storage location')
       ```
     - The `store_dir` flag value is accessed as `FLAGS.store_dir` and passed to `measurements.Measurements`:
       ```python
       m = measurements.Measurements(FLAGS.store_dir, FLAGS.init_store_dir)
       ```
  2. **`wide_bnn_sampling/measurements.py`:**
     - In the `Measurements` class constructor, the `store_dir` argument is directly assigned to `self.save_dir`:
       ```python
       self.save_dir = store_dir
       ```
  3. **`wide_bnn_sampling/checkpoint.py`:**
     - The `_get_checkpoint_path` function uses `os.path.join` with `save_dir` to construct the checkpoint path:
       ```python
       def _get_checkpoint_path(save_dir, sid):
         path = os.path.join(save_dir, 'checkpoint')
         if sid is not None:
           path = os.path.join(path, str(sid))
         return path
       ```
     - The `save_checkpoint` function uses `_get_checkpoint_path` to determine the checkpoint directory and `os.makedirs` to create it:
       ```python
       path = _get_checkpoint_path(save_dir, sid)
       if not os.path.exists(path):
         os.makedirs(path)
       ```
     - No sanitization or validation is performed on the `save_dir` path before using it in `os.path.join` or `os.makedirs`.

  **Visualization:**

  ```
  main.py --> measurements.py (store_dir is passed) --> checkpoint.py (store_dir used in os.path.join & os.makedirs)
  FLAGS.store_dir -----------------> Measurements.save_dir ---------------------> _get_checkpoint_path/save_checkpoint
  (user input)                                                                    (vulnerable functions)
  ```

- Security Test Case:
  1. **Environment Setup:**
     - Set up a testing environment with Python and the project dependencies installed as described in the `README.md`.
     - Create a temporary directory, e.g., `/tmp/test_dir`, where you do *not* expect files to be written under normal operation.
  2. **Execute `main.py` with crafted `--store_dir`:**
     - Run the `main.py` script with a crafted `--store_dir` argument that attempts path traversal. For example:
       ```bash
       python3 wide_bnn_sampling/main.py --config wide_bnn_sampling/config.py --store_dir '/tmp/../../test_dir'
       ```
     - Replace `/tmp/../../test_dir` with a path that is outside the intended project directory but writable by the user running the script.
  3. **Verify File Creation in Unexpected Location:**
     - After the script execution completes (or after it has run for a short duration if it's a long-running process), check if a `checkpoint` directory and files within it have been created in the `/tmp/test_dir` directory.
       ```bash
       ls /tmp/test_dir/checkpoint
       ```
     - If files are found in `/tmp/test_dir/checkpoint`, it confirms the path traversal vulnerability, as the application wrote files to an unexpected location based on the crafted `--store_dir` argument.
  4. **Expected Outcome:**
     - If the vulnerability exists, you will find a `checkpoint` directory and files within it inside `/tmp/test_dir`, demonstrating that the path traversal was successful and the application wrote files outside the intended directory.
     - If the vulnerability is mitigated, no `checkpoint` directory or files should be found in `/tmp/test_dir`. The files should be written in the default or intended `store_dir`.