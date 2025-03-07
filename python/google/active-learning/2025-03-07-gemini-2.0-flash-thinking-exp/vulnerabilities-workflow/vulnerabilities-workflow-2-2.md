- Vulnerability Name: Path Traversal in Dataset Loading
- Description:
    1. The `run_experiment.py` script utilizes the `--data_dir` and `--dataset` flags to determine the location and name of the dataset to load for experiments.
    2. The value of the `--data_dir` flag, provided by the user, is directly passed to the `utils.get_mldata` function in `utils/utils.py`.
    3. Inside `utils.get_mldata`, the filename is constructed by joining `data_dir` with the `dataset` name and ".pkl" extension using `os.path.join`.
    4. If the `data_dir` flag is not properly sanitized, a malicious user could provide a path that includes path traversal sequences (e.g., `..`) to access files outside of the intended data directory.
    5. For example, setting `--data_dir ../../../sensitive_directory/` could potentially allow the script to access files within `sensitive_directory`, assuming the user running the script has the necessary permissions.
    6. The `pickle.load` function in `utils.get_mldata` is then used to load the dataset from the constructed file path. If a malicious path is crafted, this could lead to reading arbitrary files on the system.
- Impact:
    - High. An attacker could potentially read arbitrary files on the file system of the user running the `run_experiment.py` script. This could lead to information disclosure of sensitive data if the user has access to such files and the script is executed with those privileges.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. There is no visible input sanitization or validation for the `data_dir` or `dataset` flags in `run_experiment.py` or `utils/utils.py` that would prevent path traversal. The code directly uses `os.path.join` which, while designed for path joining, does not inherently prevent traversal if `..` components are provided in the input strings.
- Missing Mitigations:
    - Input sanitization and validation for the `data_dir` and `dataset` flags in `run_experiment.py`.
    - Implement checks to ensure that the resolved file path stays within the intended data directory. This could involve:
        - Validating that the provided `data_dir` is an absolute path or resolving it to an absolute path.
        - Using `os.path.abspath` and `os.path.commonprefix` to verify that the constructed file path remains within the intended base directory.
        - Sanitizing the input to remove or replace path traversal characters like `..`.
- Preconditions:
    - The user must execute the `run_experiment.py` script.
    - The attacker needs to be able to influence the command-line arguments passed to `run_experiment.py`, specifically the `--data_dir` flag. This could be achieved by:
        - Social engineering to convince a user to run the script with a malicious `data_dir`.
        - Exploiting another vulnerability that allows command-line injection or modification of script arguments.
- Source Code Analysis:
    1. **`run_experiment.py`:**
        ```python
        flags.DEFINE_string("data_dir", "/tmp/data",
                            "Directory with predownloaded and saved datasets.")
        FLAGS = flags.FLAGS
        ...
        X, y = utils.get_mldata(FLAGS.data_dir, FLAGS.dataset)
        ```
        - The `data_dir` flag is defined and its value is directly accessed as `FLAGS.data_dir` and passed to `utils.get_mldata`. There is no sanitization or validation here.

    2. **`utils/utils.py`:**
        ```python
        def get_mldata(data_dir, name):
          ...
          filename = os.path.join(data_dir, dataname + ".pkl")
          if not gfile.Exists(filename):
            raise NameError("ERROR: dataset not available")
          data = pickle.load(gfile.GFile(filename, "r"))
          ...
        ```
        - `os.path.join(data_dir, dataname + ".pkl")` constructs the filename. If `data_dir` contains `..`, `os.path.join` will resolve the path, potentially leading outside the intended directory.
        - `pickle.load(gfile.GFile(filename, "r"))` opens and reads the file specified by the potentially attacker-controlled `filename`. If the path is manipulated, this could read arbitrary files.
- Security Test Case:
    1. Create a directory `/tmp/vuln_test_data`.
    2. Create a file `/tmp/vuln_test_data/test_dataset.pkl`. This file can contain dummy pickled data.
    3. Create a symbolic link or place a sensitive file (e.g., a dummy `sensitive.txt` file) in `/tmp/sensitive_directory/sensitive.txt`.
    4. Run `run_experiment.py` with the following arguments:
       ```bash
       python run_experiment.py --data_dir '../../../tmp/vuln_test_data' --dataset test_dataset --save_dir /tmp/test_results
       ```
    5. Observe if the script executes without errors and loads the dummy dataset from `/tmp/vuln_test_data/test_dataset.pkl`. This confirms basic functionality.
    6. Now, attempt path traversal to access a sensitive file.  For testing purposes, create a dummy file `/tmp/sensitive_file.txt`.
    7. Run `run_experiment.py` with a crafted `data_dir` to try and access `/tmp/sensitive_file.txt`:
       ```bash
       python run_experiment.py --data_dir '../../tmp/' --dataset sensitive_file --save_dir /tmp/test_results
       ```
    8. If the code attempts to open and potentially process `/tmp/sensitive_file.pkl` (or throws an error related to file access at that location), it indicates a path traversal vulnerability.
    9. **Expected vulnerable behavior:** The script might attempt to open a file named `sensitive_file.pkl` in the directory `../../tmp/` relative to the script's execution directory, which resolves to `/tmp/sensitive_file.pkl`. If this file exists (or if an attacker can place a malicious pickle file there), the script will try to load it. Even if it doesn't exist, the attempt to access a file outside the intended `/tmp/data` directory demonstrates path traversal.
    10. **To fully verify file read,** you would need to modify the `utils.get_mldata` function temporarily to print the `filename` right before `pickle.load`. Run the test again and check if the printed filename shows the traversed path (e.g., `/tmp/sensitive_file.pkl`).

This vulnerability allows for reading arbitrary files and could be further exploited if there were write operations or deserialization vulnerabilities involved.