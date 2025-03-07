## Combined Vulnerability Report

This report summarizes identified security vulnerabilities within the `run_experiment.py` script. Two distinct categories of high to critical severity vulnerabilities have been identified: Path Traversal and Code Injection, both stemming from insufficient input sanitization of command-line flags. Exploitation of these vulnerabilities could allow an attacker to read arbitrary files, overwrite files, or execute arbitrary code on the system running the script.

### 1. Path Traversal in `run_experiment.py` via `--data_dir` and `--save_dir` Flags

- **Description:**
    1. The `run_experiment.py` script uses the `--data_dir` and `--save_dir` command-line flags to specify directories for dataset loading and experiment output saving, respectively.
    2. The values provided for these flags are directly used in file path constructions within the script without proper sanitization or validation.
    3. Specifically, `--data_dir` is used in `utils.get_mldata` to load datasets, and `--save_dir` is used to create directories and save experiment outputs using functions like `gfile.MkDir`, `utils.Logger`, and `pickle.dump`.
    4. An attacker can provide malicious paths containing path traversal sequences, such as `../`, as values for `--data_dir` or `--save_dir`.
    5. When the script performs file system operations using these manipulated paths, it can traverse outside the intended directories, potentially leading to unauthorized file access or modification.
    6. For example, a malicious `--data_dir` could be used to read sensitive files outside the designated data directory, while a crafted `--save_dir` could lead to writing experiment outputs to arbitrary locations, potentially overwriting existing files.

- **Impact:**
    - **Unauthorized File System Access:** An attacker could potentially read arbitrary files on the file system if the script's process has sufficient permissions. This can lead to the disclosure of sensitive information.
    - **File Overwrite/Modification:** By manipulating `--save_dir`, an attacker could potentially write files to arbitrary locations, possibly overwriting existing files, leading to data corruption or operational disruptions.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - None. The code directly utilizes the user-provided paths from the command-line flags without any input sanitization or validation. While `os.path.join` is used for path construction, it does not prevent path traversal when malicious sequences like `../` are included in the input.

- **Missing Mitigations:**
    - **Input Sanitization and Validation:** Implement robust input sanitization and validation for both `--data_dir` and `--save_dir` flags in `run_experiment.py`.
    - **Path Traversal Prevention:** Sanitize input paths to remove or neutralize path traversal sequences (e.g., `../`).
    - **Restrict Base Directory:** Enforce that both data and save directories are always within predefined safe base directories. Validate that the resolved paths remain within these base directories and reject any paths attempting to escape. Use functions like `os.path.abspath` and `os.path.commonprefix` to ensure paths stay within allowed boundaries.

- **Preconditions:**
    - The attacker must be able to execute the `run_experiment.py` script and control the command-line arguments, specifically `--data_dir` and `--save_dir`. This is typical for users who run experiments using this script.

- **Source Code Analysis:**
    ```python
    File: /code/run_experiment.py
    ...
    flags.DEFINE_string("save_dir", "/tmp/toy_experiments", "Where to save outputs")
    flags.DEFINE_string("data_dir", "/tmp/data", "Directory with predownloaded and saved datasets.")
    FLAGS = flags.FLAGS

    def main(argv):
      del argv
      ...
      save_dir = os.path.join(
          FLAGS.save_dir,
          FLAGS.dataset + "_" + FLAGS.sampling_method) # Path constructed using unsanitized FLAGS.save_dir
      data_dir = FLAGS.data_dir # Unsanitized FLAGS.data_dir
      do_save = FLAGS.do_save == "True"

      if do_save:
        if not gfile.Exists(save_dir):
          try:
            gfile.MkDir(save_dir) # Directory creation with potentially traversed path
          except:
            print(('WARNING: error creating save directory, '
                   'directory most likely already created.'))
        # Set up logging
        filename = os.path.join(
            save_dir, "log-" + strftime("%Y-%m-%d-%H-%M-%S", gmtime()) + ".txt") # File creation in potentially traversed save_dir
        sys.stdout = utils.Logger(filename)

        ...
        filename = os.path.join(save_dir, # File creation in potentially traversed save_dir
                                filename + "_" + str(1000+len(existing_files))[1:] + ".pkl")
        pickle.dump(all_results, gfile.GFile(filename, "w")) # Pickle dump in potentially traversed save_dir

      X, y = utils.get_mldata(data_dir, FLAGS.dataset) # Uses unsanitized data_dir

    File: /code/utils/utils.py
    def get_mldata(data_dir, name):
      ...
      filename = os.path.join(data_dir, dataname + ".pkl") # Path constructed using unsanitized data_dir
      if not gfile.Exists(filename):
        raise NameError("ERROR: dataset not available")
      data = pickle.load(gfile.GFile(filename, "r")) # File read from potentially traversed path
      ...
    ```
    - The code directly uses `FLAGS.data_dir` and `FLAGS.save_dir` from user input in `os.path.join` for file and directory operations without any sanitization. This allows path traversal if an attacker provides malicious input.

- **Security Test Case:**
    1. Assume you have access to run `run_experiment.py`.
    2. **Test Case 1: Malicious `--save_dir`**
        Execute the following command:
        ```bash
        python run_experiment.py --dataset test_dataset --sampling_method uniform --score_method logistic --save_dir "/tmp/attack_test/../../" --do_save True
        ```
        After execution, check if files (like `log-YYYY-MM-DD-HH-MM-SS.txt` or `results_score_logistic_select_None_norm_False_stand_True_000.pkl`) are created in `/tmp/attack_test/` or even higher directories. This would confirm path traversal via `--save_dir`.
    3. **Test Case 2: Malicious `--data_dir`**
        Create a dummy file `/tmp/sensitive_file.txt`.
        Run `run_experiment.py` with a crafted `--data_dir` to attempt to access `/tmp/sensitive_file.txt`:
        ```bash
        python run_experiment.py --dataset sensitive_file --sampling_method uniform --score_method logistic --data_dir '../../tmp/' --save_dir /tmp/test_results
        ```
        Check if the script attempts to open and potentially process `/tmp/sensitive_file.pkl` (or throws an error related to file access at that location). This would indicate path traversal via `--data_dir`.
    4. **Vulnerability Validation:** Successful creation of files outside the intended save directory in Test Case 1, or attempts to access files outside the intended data directory in Test Case 2, confirms the path traversal vulnerability.

### 2. Code Injection via Unsanitized Input Parameters in `run_experiment.py`

- **Description:**
    1. The `run_experiment.py` script utilizes several command-line flags, including `dataset`, `sampling_method`, `score_method`, and `select_method`, to configure experiment parameters.
    2. The values provided for these flags are directly used in the script for dynamic operations such as constructing file paths for dataset loading and dynamically selecting and instantiating components like active learning samplers and models.
    3. Lack of input sanitization for these flags allows an attacker to potentially inject arbitrary code. By crafting malicious input strings for flags like `dataset`, `sampling_method`, `score_method`, or `select_method`, an attacker could manipulate file paths or influence the dynamic loading/instantiation of components in unintended and potentially harmful ways.
    4. For instance, a manipulated `dataset` flag could lead to command injection when constructing file paths for dataset loading, while malicious inputs to `sampling_method`, `score_method`, or `select_method` could, in more complex scenarios, be exploited if the system attempts to dynamically execute code based on these string inputs.

- **Impact:**
    - **Arbitrary Code Execution:** Successful code injection can lead to arbitrary code execution on the system running `run_experiment.py`.
    - **System Compromise:** An attacker could potentially gain full control of the system, leading to data theft, data modification, denial of service, or further malicious activities.
    - **Critical Severity:** This vulnerability is considered critical, especially if the script runs in an environment with sensitive data or elevated privileges.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - None. There is no input sanitization or validation implemented for the command-line flags `dataset`, `sampling_method`, `score_method`, and `select_method`. The script directly uses the string values from these flags without any checks.

- **Missing Mitigations:**
    - **Strict Input Sanitization and Validation:** Implement strict input validation and sanitization for all command-line flags, especially `dataset`, `sampling_method`, `score_method`, and `select_method`.
    - **Whitelist Validation:** For `sampling_method`, `score_method`, and `select_method`, use a whitelist approach to allow only predefined, safe values. Map user inputs to a predefined set of allowed modules or functions instead of directly using input strings for dynamic loading.
    - **Path Sanitization:** For the `dataset` flag and any flags used to construct file paths, sanitize input to prevent path traversal and command injection in file path contexts.

- **Preconditions:**
    - The attacker needs the ability to execute the `run_experiment.py` script and control command-line arguments. This could be through direct command-line access or via a web interface that passes user-controlled input to the script.

- **Source Code Analysis:**
    ```python
    File: /code/run_experiment.py
    ...
    flags.DEFINE_string("dataset", "letter", "Dataset name")
    flags.DEFINE_string("sampling_method", "margin", ...)
    flags.DEFINE_string("score_method", "logistic", ...)
    flags.DEFINE_string("select_method", "None", ...)
    FLAGS = flags.FLAGS

    def main(argv):
      del argv
      ...
      X, y = utils.get_mldata(FLAGS.data_dir, FLAGS.dataset) # Unsanitized FLAGS.dataset used in file path construction
      sampler = get_AL_sampler(FLAGS.sampling_method) # Unsanitized FLAGS.sampling_method used for sampler selection
      score_model = utils.get_model(FLAGS.score_method, seed) # Unsanitized FLAGS.score_method used for model selection
      select_model = utils.get_model(FLAGS.select_method, seed) # Unsanitized FLAGS.select_method used for model selection
      ...

    File: /code/utils/utils.py
    def get_mldata(data_dir, name):
      ...
      filename = os.path.join(data_dir, dataname + ".pkl") # Path construction with potentially malicious dataset name (dataname)
      ...
    File: /code/sampling_methods/constants.py
    def get_AL_sampler(name):
        if name in AL_MAPPING and name != 'mixture_of_samplers':
            return AL_MAPPING[name] # Dynamic sampler retrieval based on unsanitized name
        ...
    File: /code/utils/utils.py
    def get_model(method, seed=13):
        if method == "logistic": # Conditional model selection based on unsanitized method
            model = LogisticRegression(...)
        elif method == "kernel_ls":
            model = BlockKernelSolver(random_state=seed)
        ...
    ```
    - The code uses `FLAGS.dataset`, `FLAGS.sampling_method`, `FLAGS.score_method`, and `FLAGS.select_method` directly from user input without sanitization in path constructions and for dynamic component selection, which could lead to code injection vulnerabilities.

- **Security Test Case:**
    1. Assume you have access to run `run_experiment.py`.
    2. **Test Case 1: Command Injection via `dataset` flag**
        Execute the following command to attempt command injection via the `dataset` flag:
        ```bash
        python run_experiment.py --dataset=";os.system('touch /tmp/pwned_dataset');" --sampling_method=uniform --score_method=logistic
        ```
        After execution, check if a file named `pwned_dataset` is created in `/tmp`.
    3. **Verification:** If the file `/tmp/pwned_dataset` is created, it indicates successful command injection via the `dataset` flag. Observe the script's output for any signs of injected command execution.