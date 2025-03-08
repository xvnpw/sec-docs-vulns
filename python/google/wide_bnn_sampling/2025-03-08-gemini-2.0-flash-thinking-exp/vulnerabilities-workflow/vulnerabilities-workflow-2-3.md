- Vulnerability Name: Path Traversal in Dataset Loading
- Description:
  1. The `wide_bnn_sampling` library uses `tensorflow_datasets` to load datasets.
  2. The `datasets.get_dataset` function in `/code/wide_bnn_sampling/datasets.py` uses `tfds.load` and takes `data_dir` as an argument to specify the dataset directory.
  3. The `data_dir` is configurable via the `config.py` file and command line flag `--config` in `/code/wide_bnn_sampling/main.py`.
  4. The `/code/wide_bnn_sampling/main.py` script reads the `data_dir` from the configuration and passes it directly to the `datasets.cifar10_tfds` function, which then calls `datasets.get_dataset`.
  5. The `datasets.get_dataset` function directly passes the user-controlled `data_dir` to `tfds.load` without sufficient validation or sanitization.
  6. While `tfds.load` is intended for datasets, a malicious user could potentially provide a path that, while not directly leading to arbitrary file read, could cause `tfds.load` to interact with unintended directories or datasets if not properly validated. This could lead to unexpected behavior, errors, or potentially be leveraged in more complex attacks if combined with other vulnerabilities or misconfigurations in the environment where this library is used. The risk is that by manipulating the `data_dir`, an attacker can influence the data loading process to access or attempt to access locations outside of the intended dataset storage, which is a form of path traversal.
- Impact:
  - By controlling the `data_dir`, an attacker can influence the dataset loading to access or attempt to access locations outside the intended dataset storage. This could lead to unexpected program behavior, errors, or potentially be a stepping stone for more serious attacks depending on the broader application context where this library is used. While not direct arbitrary file read, it represents a path traversal issue in how dataset locations are handled.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations: None
- Missing Mitigations:
  - Sanitize and validate the `data_dir` input to ensure it is a safe path and restrict access to only the intended dataset directories.
  - Implement checks to prevent path traversal characters like `..` in `data_dir`.
  - Consider using a whitelist of allowed dataset directories or more robust path validation for `data_dir`.
- Preconditions:
  - The user must run the `/code/wide_bnn_sampling/main.py` script.
  - The attacker must be able to control the configuration file or command line arguments, specifically the `data_dir` parameter.
- Source Code Analysis:
  - File: `/code/wide_bnn_sampling/datasets.py`
    ```python
    def get_dataset(
        name,
        data_dir=None,  # User-controlled data_dir
        input_key='image'):
      ...
      ds_train, ds_test = tfds.as_numpy(
          tfds.load(
              name + (':3.*.*' if name != 'imdb_reviews' else ''),
              split=['train' + ('[:%d]' % n_train if n_train is not None else ''),
                     'test' + ('[:%d]' % n_test if n_train is not None else '')],
              batch_size=-1,
              as_dataset_kwargs={'shuffle_files': False},
              data_dir=data_dir)) # data_dir passed directly to tfds.load
      ...
    ```
  - File: `/code/wide_bnn_sampling/main.py`
    ```python
    config_flags.DEFINE_config_file(
        name='config',
        default=None,
        help_string='training configuration')
    ...
    def run_experiment(C: config_dict.ConfigDict, m: measurements.Measurements):
      ...
      ds = datasets.cifar10_tfds(
          data_dir=C.data_dir) # data_dir from config
      ...
    ```
  - File: `/code/wide_bnn_sampling/config.py`
    ```python
    def get_config():
      ...
      C.data_dir = '' # Default value, can be overridden by config file or command line
      ...
      return C
    ```
- Security Test Case:
  1. Create a malicious configuration file `malicious_config.py` with the following content:
     ```python
     from ml_collections import config_dict

     def get_config():
       C = config_dict.ConfigDict()
       C.data_dir = '/tmp' # Malicious data_dir, point to tmp
       C.n_train = 1
       C.n_test = 1
       C.architecture = 'fcn'
       C.reparam_type = 'identity'
       C.step_count = 1
       C.burn_in = 0
       C.thin = 1
       C.save_stats = False
       return C
     ```
  2. Run the `/code/wide_bnn_sampling/main.py` script with the malicious configuration file:
     ```bash
     python3 wide_bnn_sampling/main.py --config malicious_config.py --store_dir test_results
     ```
  3. Observe the program's execution and any error messages. Check if the program attempts to load datasets from `/tmp`. Because `/tmp` is a common directory but not intended for datasets, if the program proceeds without error or tries to access datasets within `/tmp`, it indicates that the `data_dir` is being used without proper validation, confirming the path traversal risk.
  4. Examine the logs or output for any unusual behavior related to dataset loading or file access in `/tmp`. Successful execution without errors when pointing `data_dir` to `/tmp` (a non-dataset directory) would indicate a lack of proper validation and the presence of a path traversal risk.