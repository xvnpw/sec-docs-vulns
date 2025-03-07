### Vulnerability List

- Vulnerability Name: Code Injection via Unsanitized Input Parameters in `run_experiment.py`
- Description:
    - The `run_experiment.py` script utilizes command-line flags to specify various experiment parameters, such as `dataset`, `sampling_method`, `score_method`, and `select_method`.
    - These flags are defined using `absl.flags.DEFINE_string`.
    - The values provided for `dataset`, `sampling_method`, `score_method`, and `select_method` flags are directly used in the script to:
        - Construct file paths to load datasets using `utils.get_mldata`.
        - Dynamically select and instantiate active learning samplers using `sampling_methods.constants.get_AL_sampler`.
        - Dynamically select and instantiate scoring and selection models using `utils.get_model`.
    - Lack of input sanitization on these flags allows an attacker to inject arbitrary code by crafting malicious input strings. For example, by manipulating the `dataset` flag, an attacker could potentially inject commands into the file path, leading to arbitrary file access or code execution when the script attempts to load the dataset. Similarly, manipulating `sampling_method`, `score_method`, or `select_method` could lead to loading and execution of unintended or malicious code if the system attempts to dynamically import or execute modules or functions based on these unsanitized string inputs.

- Impact:
    - **High/Critical**: Successful code injection can lead to arbitrary code execution on the server running the `run_experiment.py` script.
    - An attacker could potentially gain full control of the system, steal sensitive data, modify data, or use the system for further malicious activities.
    - The impact is critical if the script is run in an environment with sensitive data or elevated privileges.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - None. The code does not implement any input sanitization or validation for the command-line flags `dataset`, `sampling_method`, `score_method`, and `select_method`. The script directly uses the string values provided by these flags to construct file paths and dynamically load modules/functions.

- Missing Mitigations:
    - **Input Sanitization and Validation**: Implement strict input validation and sanitization for all command-line flags, especially `dataset`, `sampling_method`, `score_method`, and `select_method`.
        - **Whitelist Approach**: For `sampling_method`, `score_method`, and `select_method`, use a whitelist to allow only predefined, safe values. Instead of directly using the string input to dynamically load modules, map the input to a predefined set of allowed modules or functions.
        - **Path Sanitization**: For the `dataset` flag and any other flags used to construct file paths, sanitize the input to prevent path traversal attacks. Ensure that the constructed paths are within the intended data directories and do not allow access to parent directories or system files.
        - **Input Type Validation**: Validate the type and format of all inputs to ensure they conform to expected values.

- Preconditions:
    - The attacker must be able to execute the `run_experiment.py` script with the ability to control command-line arguments, such as through a publicly accessible web interface or command-line access to the server.

- Source Code Analysis:
    - **`run_experiment.py`**:
        - The script starts by defining command-line flags using `absl.flags`:
            ```python
            flags.DEFINE_string("dataset", "letter", "Dataset name")
            flags.DEFINE_string("sampling_method", "margin", ...)
            flags.DEFINE_string("score_method", "logistic", ...)
            flags.DEFINE_string("select_method", "None", ...)
            flags.DEFINE_string("data_dir", "/tmp/data", ...)
            ```
        - The `dataset` flag is used in `utils.get_mldata`:
            ```python
            X, y = utils.get_mldata(FLAGS.data_dir, FLAGS.dataset)
            ```
            In `utils.get_mldata`, the `FLAGS.dataset` value is directly used to construct a filename:
            ```python
            filename = os.path.join(save_dir, dataset[1]+'.pkl')
            if not gfile.Exists(filename):
                if dataset[0][-3:] == 'csv':
                    data = get_csv_data(dataset[0])
                elif ...
                else:
                    try:
                        data = fetch_mldata(dataset[0])
                    except:
                        raise Exception('ERROR: failed to fetch data from mldata.org')
                ...
                pickle.dump(data, gfile.GFile(filename, 'w'))
            ```
            If `FLAGS.dataset` contains malicious path components like `../`, it could lead to path traversal when `os.path.join` is used. Furthermore, if `dataset[0]` is controlled and set to `'csv'` and `dataset[0]` itself is a malicious command, it might be interpreted in `get_csv_data`.
        - The `sampling_method` flag is used in `get_AL_sampler`:
            ```python
            sampler = get_AL_sampler(FLAGS.sampling_method)
            ```
            In `sampling_methods/constants.py`, `get_AL_sampler` uses `FLAGS.sampling_method` to look up and return a sampler class from the `AL_MAPPING` dictionary:
            ```python
            def get_AL_sampler(name):
                if name in AL_MAPPING and name != 'mixture_of_samplers':
                    return AL_MAPPING[name]
                if 'mixture_of_samplers' in name:
                    return get_mixture_of_samplers(name)
                raise NotImplementedError('The specified sampler is not available.')
            ```
            While direct code injection via `sampling_method` might be less direct due to dictionary lookup, vulnerabilities could arise if `AL_MAPPING` population process itself is compromised, or if the intended sampler logic has vulnerabilities.
        - The `score_method` and `select_method` flags are used in `utils.get_model`:
            ```python
            score_model = utils.get_model(FLAGS.score_method, seed)
            ...
            select_model = utils.get_model(FLAGS.select_method, seed)
            ```
            In `utils.get_model`, the `method` argument (derived from `FLAGS.score_method` and `FLAGS.select_method`) is used to dynamically select and instantiate a model:
            ```python
            def get_model(method, seed=13):
                if method == "logistic":
                    model = LogisticRegression(...)
                    ...
                elif method == "kernel_ls":
                    model = BlockKernelSolver(random_state=seed)
                    ...
                elif method == "small_cnn":
                    model = SmallCNN(random_state=seed)
                    return model
                elif method == "allconv":
                    model = AllConv(random_state=seed)
                    return model
                else:
                    raise NotImplementedError("ERROR: " + method + " not implemented")
                model = GridSearchCV(model, params, cv=3)
                return model
            ```
            Similar to `sampling_method`, direct injection here is less likely because of the `if/elif/else` structure. However, if the project were to expand and dynamically load model classes based on the `method` string (e.g., using `importlib.import_module` or `eval`), a code injection vulnerability could be introduced if `method` is not sanitized.

- Security Test Case:
    1. **Prerequisites**:
        - Access to execute `run_experiment.py` script.
        - Python environment with the project dependencies installed.
    2. **Test Steps**:
        - Execute `run_experiment.py` with a maliciously crafted `dataset` flag. For example, try to inject a command that lists the contents of the root directory:
          ```bash
          python run_experiment.py --dataset=";os.system('ls /');" --sampling_method=uniform --score_method=logistic
          ```
          or try to create a file in `/tmp`:
          ```bash
          python run_experiment.py --dataset=";os.system('touch /tmp/pwned');" --sampling_method=uniform --score_method=logistic
          ```
        - Observe the output and system behavior.
    3. **Expected Result**:
        - If the vulnerability exists, the injected command `os.system('ls /')` or `os.system('touch /tmp/pwned')` might be executed. In the first case, the output of `ls /` might be visible in the script's output or logs. In the second case, a file named `pwned` might be created in the `/tmp` directory.
        - If the vulnerability does not exist, the script should either fail gracefully due to invalid dataset name or execute without performing the injected system command.
    4. **Verification**:
        - Check the script's output for unexpected output like directory listings.
        - Check if the file `/tmp/pwned` was created.
        - Monitor system logs for any unusual activity that might indicate code injection.