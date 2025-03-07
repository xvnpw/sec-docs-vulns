### Vulnerability List

- Vulnerability Name: Path Traversal in Data Loading via `train_data_paths` and `valid_data_paths`

- Description:
    The application is vulnerable to path traversal. By manipulating the `train_data_paths` or `valid_data_paths` command-line arguments, an attacker can specify arbitrary file paths on the system. When the training script `run.py` is executed, these paths are passed to the data loading mechanism in `src/data_provider/mnist.py` (when `--dataset_name mnist` is used). Specifically, the `InputHandle` class in `mnist.py` uses `numpy.load()` to load data from the provided paths without proper validation. An attacker can provide a path to a sensitive file (e.g., `/etc/passwd`) instead of a legitimate dataset file. Although `numpy.load()` is intended for `.npy`, `.npz` or pickled files, it might still attempt to open and read arbitrary files. This could lead to unauthorized read access to local files if the application attempts to process the content or if error messages expose file existence or content snippets.

- Impact:
    An attacker can potentially read arbitrary files from the server's filesystem that the user running the script has access to. This could lead to information disclosure, including sensitive data, configuration files, or even application source code if it's accessible.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    No mitigations are currently implemented in the project to prevent path traversal. The code directly uses the user-provided paths with `np.load` without any sanitization or validation.

- Missing Mitigations:
    Input validation and sanitization are missing. The application should validate that the provided paths for `train_data_paths` and `valid_data_paths`:
    - Are within an expected directory or set of directories.
    - Conform to the expected file type (e.g., `.npz`, `.npy`).
    - Do not contain path traversal sequences like `../` or absolute paths pointing outside the allowed data directories.

- Preconditions:
    - The attacker needs to be able to influence the command-line arguments passed to `run.py`. In a typical scenario, this would be a user running the training script based on instructions that could be manipulated or if the script is integrated into a system where command-line arguments can be indirectly controlled.
    - The user running the script must have read permissions to the files the attacker is trying to access.

- Source Code Analysis:
    1. **Entry Point:** The vulnerability starts with the command-line arguments `train_data_paths` and `valid_data_paths` defined in `/code/run.py` using `tf.app.flags.FLAGS`.
    ```python
    FLAGS.DEFINE_string('train_data_paths', '', 'train data paths.')
    FLAGS.DEFINE_string('valid_data_paths', '', 'validation data paths.')
    ```
    2. **Data Provider Selection:** In `/code/run.py`, the `main` function calls `datasets_factory.data_provider` with these paths.
    ```python
    train_input_handle, test_input_handle = datasets_factory.data_provider(
        FLAGS.dataset_name,
        FLAGS.train_data_paths,
        FLAGS.valid_data_paths,
        FLAGS.batch_size * FLAGS.n_gpu,
        FLAGS.img_width,
        seq_length=FLAGS.total_length,
        is_training=True)
    ```
    3. **Dataset Factory:** In `/code/src/data_provider/datasets_factory.py`, the `data_provider` function selects the data handler based on `dataset_name`. For `mnist`, it instantiates `mnist.InputHandle`.
    ```python
    if dataset_name == 'mnist':
        test_input_param = {
            'paths': valid_data_list,
            'minibatch_size': batch_size,
            'input_data_type': 'float32',
            'is_output_sequence': True,
            'name': dataset_name + 'test iterator'
        }
        test_input_handle = datasets_map[dataset_name].InputHandle(test_input_param)
        # ... (rest of mnist dataset handling)
    ```
    4. **Vulnerable File Loading in `mnist.py`:** In `/code/src/data_provider/mnist.py`, the `InputHandle` class's `__init__` method takes the `paths` and directly loads data using `np.load(self.paths[0])` and potentially `np.load(self.paths[1])`.
    ```python
    class InputHandle(object):
        # ...
        def __init__(self, input_param):
            # ...
            self.paths = input_param['paths']
            # ...
            self.load()

        def load(self):
            """Load the data."""
            dat_1 = np.load(self.paths[0]) # Vulnerable line - no path validation
            for key in dat_1.keys():
                self.data[key] = dat_1[key]
            if self.num_paths == 2:
                dat_2 = np.load(self.paths[1]) # Vulnerable line - no path validation
                # ... (rest of data loading)
    ```
    **Visualization of Vulnerability Flow:**

    ```
    User Input (command-line arguments: --train_data_paths, --valid_data_paths)
        --> /code/run.py (passes paths to datasets_factory.data_provider)
            --> /code/src/data_provider/datasets_factory.py (selects mnist data provider)
                --> /code/src/data_provider/mnist.py (InputHandle class)
                    --> InputHandle.__init__()
                        --> InputHandle.load()
                            --> np.load(self.paths[0])  <-- Vulnerable call: direct file loading without validation
                            --> np.load(self.paths[1])  <-- Vulnerable call: direct file loading without validation
    ```

- Security Test Case:
    1. **Prepare malicious data paths:** Create a file named `sensitive_data.npz` in `/tmp/` directory (or any accessible directory). This file is not actually needed to trigger the read vulnerability but can be used as a dummy valid data path if needed. Also assume there is a sensitive file readable by the user, e.g. `/etc/passwd`.
    2. **Run the training script with path traversal payload:** Execute the `run.py` script with `--dataset_name mnist` and maliciously crafted `train_data_paths` argument pointing to `/etc/passwd`. For `valid_data_paths`, provide a valid path like `/tmp/sensitive_data.npz` or any other valid mnist data path to avoid errors in other parts of the script.
    ```bash
    python -u run.py \
        --is_training True \
        --dataset_name mnist \
        --train_data_paths /etc/passwd \
        --valid_data_paths /tmp/sensitive_data.npz \
        --save_dir checkpoints/_mnist_e3d_lstm_test \
        --gen_frm_dir results/_mnist_e3d_lstm_test \
        --model_name e3d_lstm \
        --max_iterations 1
    ```
    3. **Observe the output and errors:** Examine the output and error messages. While `np.load` might fail to load `/etc/passwd` as a valid numpy archive, the error messages might reveal that the script attempted to open and process `/etc/passwd`. Depending on the system and file content, you might observe different errors, but the key is to confirm that the application attempted to access `/etc/passwd` based on the provided command-line argument. For example, error messages might include snippets of `/etc/passwd` content if `np.load` tries to parse it. Even if it throws an error like "Invalid header", it confirms the attempt to read the file.

    **Expected Outcome:** Running the test case will demonstrate that the application attempts to load and process the file specified in `--train_data_paths` without validation, confirming the path traversal vulnerability. Error messages in the console output should indicate that the system tried to read or process `/etc/passwd`.