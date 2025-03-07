*   **Vulnerability Name:** Path Traversal in `run_experiment.py` via `--data_dir` and `--save_dir` flags
*   **Description:**
    1. The `run_experiment.py` script accepts user-controlled paths via the `--data_dir` and `--save_dir` command-line flags.
    2. The `--data_dir` flag is intended to specify the directory where datasets are stored, and `--save_dir` is for specifying where experiment results are saved.
    3. The script uses these paths in file system operations without proper sanitization or validation. Specifically, `utils.get_mldata(FLAGS.data_dir, FLAGS.dataset)` uses `--data_dir` to load datasets, and the script uses `FLAGS.save_dir` to create directories for saving results using `gfile.MkDir` and `pickle.dump`.
    4. An attacker can exploit this by providing malicious paths like `/../../sensitive_data` or similar path traversal sequences as values for `--data_dir` or `--save_dir`.
    5. When the script executes file operations using these manipulated paths, it can traverse the file system outside the intended directories, potentially accessing or creating files in unauthorized locations.
*   **Impact:**
    *   **Unauthorized File System Access:** An attacker could read files and directories outside the intended data and save directories. This could lead to the disclosure of sensitive information if the script's process has sufficient permissions.
    *   **Data Modification or Overwriting:** By manipulating the `--save_dir`, an attacker could potentially save experiment results to arbitrary locations, potentially overwriting existing files or directories, leading to data corruption or denial of service in certain scenarios if critical system files are targeted (though less likely in this application context).
*   **Vulnerability Rank:** High
*   **Currently Implemented Mitigations:**
    *   None. The code directly uses the user-provided paths from the command-line flags without any sanitization or validation.
*   **Missing Mitigations:**
    *   **Input Sanitization:** The project lacks input sanitization for the `--data_dir` and `--save_dir` flags in `run_experiment.py`.
    *   **Path Validation:**  There is no validation to ensure that the provided paths are within the expected directories or to prevent path traversal attempts.
    *   **Safe Path Handling:**  Using secure path handling mechanisms to prevent traversal, such as using functions that resolve paths to canonical forms and validate them against a whitelist or expected base directory.
*   **Preconditions:**
    *   The attacker needs to be able to execute the `run_experiment.py` script. This typically means the attacker has access to the command line or can otherwise influence the execution of the script with specific arguments.
*   **Source Code Analysis:**
    1. **Flag Definition:** In `run_experiment.py`, the flags `--data_dir` and `--save_dir` are defined using `absl.flags.DEFINE_string`:
        ```python
        flags.DEFINE_string("save_dir", "/tmp/toy_experiments", "Where to save outputs")
        flags.DEFINE_string("data_dir", "/tmp/data", "Directory with predownloaded and saved datasets.")
        ```
    2. **Path Usage:** These flags are directly used in the `main` function and passed to other utility functions:
        ```python
        save_dir = os.path.join(
            FLAGS.save_dir,
            FLAGS.dataset + "_" + FLAGS.sampling_method)
        ...
        X, y = utils.get_mldata(FLAGS.data_dir, FLAGS.dataset)
        ```
    3. **`utils.get_mldata` function (File: /code/utils/utils.py):**
        ```python
        def get_mldata(data_dir, name):
          ...
          filename = os.path.join(data_dir, dataname + ".pkl")
          if not gfile.Exists(filename):
            raise NameError("ERROR: dataset not available")
          data = pickle.load(gfile.GFile(filename, "r"))
          ...
        ```
        - This function uses `os.path.join(data_dir, dataname + ".pkl")` to construct the file path. If `data_dir` is manipulated to include path traversal sequences, the resulting `filename` will also be affected.
    4. **Saving Results:** The `save_dir` flag is used to create directories and save results:
        ```python
        if do_save:
          if not gfile.Exists(save_dir):
            try:
              gfile.MkDir(save_dir)
            except:
              ...
          filename = os.path.join(
              save_dir, "log-" + strftime("%Y-%m-%d-%H-%M-%S", gmtime()) + ".txt")
          sys.stdout = utils.Logger(filename)
          ...
          filename = os.path.join(save_dir,
                                  filename + "_" + str(1000+len(existing_files))[1:] + ".pkl")
          pickle.dump(all_results, gfile.GFile(filename, "w"))
        ```
        -  Here, `os.path.join(save_dir, ...)` is used to construct save paths. A manipulated `save_dir` will allow writing files to arbitrary locations.

    **Visualization:**

    ```
    run_experiment.py --data_dir [USER_INPUT_PATH] --save_dir [USER_INPUT_PATH] ...
        |
        V
    utils.get_mldata(FLAGS.data_dir, ...)  <-- Uses potentially malicious FLAGS.data_dir
        |
        V
    gfile.GFile(filename, "r")             <-- File operation with malicious path
        ...
    gfile.MkDir(save_dir)                   <-- Directory operation with malicious path
        |
        V
    gfile.GFile(filename, "w")             <-- File operation with malicious path
    ```

*   **Security Test Case:**
    1. **Setup:** Assume the attacker has access to a system where the `active-learning-playground` is installed and can execute `run_experiment.py`.
    2. **Execute with Malicious `--data_dir`:** Run the script with a `--data_dir` flag pointing to a sensitive directory outside the intended data directory, for example:
        ```bash
        python run_experiment.py --dataset mnist --sampling_method uniform --score_method logistic --data_dir /etc/passwd --save_dir /tmp/test_results
        ```
        *Expected Outcome:* While directly accessing `/etc/passwd` as a directory for datasets might cause the script to fail because it's not a valid dataset directory, a more targeted path traversal like `/../../../../etc/passwd` might lead to attempts to access files within `/etc/passwd` relative to the intended data directory, potentially revealing if the script attempts to open or list files in that directory.  Depending on file permissions, the script might throw errors or potentially even process parts of the sensitive file if it's incorrectly interpreted as a dataset.

    3. **Execute with Malicious `--save_dir`:** Run the script with a `--save_dir` flag pointing to a sensitive directory where the attacker wants to write files, for example (be cautious when running this, as it might create files in unexpected locations):
        ```bash
        python run_experiment.py --dataset mnist --sampling_method uniform --score_method logistic --data_dir /tmp/data --save_dir /tmp/../../test_results_traversal
        ```
        *Expected Outcome:*  The script should attempt to create directories and save results under `/tmp/test_results_traversal` which, due to the path traversal `../../`, might resolve to a location outside of `/tmp/toy_experiments`, demonstrating the ability to write files outside the intended save directory.

    4. **Verification:** After running the test cases, check the file system to see if the script attempted to access files or create directories in the locations specified via the malicious paths. Observe the script's output for any error messages or unusual behavior that might indicate path traversal attempts. For the `--save_dir` test, verify if files were created in `/tmp/test_results_traversal` or a location resolved from the traversal path, instead of within `/tmp/toy_experiments`.