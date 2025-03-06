### Vulnerability List

- Vulnerability Name: Path Traversal via Configuration File Manipulation
- Description:
    - The application uses a YAML configuration file, specified via the `--para` command-line argument, to define various parameters including file paths for data directories, output directories, and cache locations.
    - An attacker can supply a malicious YAML file path through the `--para` argument.
    - By crafting a malicious YAML file containing path traversal sequences (e.g., `../`) in parameters like `data_dir`, `output_dir`, or `cached_feature_dir`, the attacker can manipulate the file paths used by the application.
    - When the application constructs file paths using `os.path.join()` with these manipulated parameters, it may attempt to access or create files outside of the intended directories.
    - For example, by setting `data_dir: "../../"`, an attacker could potentially cause the application to read training data from directories outside the project's intended `data` directory, or write output files to unexpected locations.
- Impact:
    - Information Disclosure: An attacker could potentially read sensitive files if path traversal allows access to files outside the intended data directories.
    - Data Manipulation: An attacker might be able to write to arbitrary file system locations, potentially overwriting important files or injecting malicious data, depending on how the manipulated paths are used in subsequent file operations (e.g., logging, caching, saving results).
- Vulnerability Rank: Medium
- Currently Implemented Mitigations:
    - None. The application does not perform any validation or sanitization of file paths read from the configuration file.
- Missing Mitigations:
    - Input validation: Implement validation for all file path parameters read from the YAML configuration file.
        - Check if the provided paths are within expected base directories.
        - Sanitize paths to remove or neutralize path traversal sequences like `../`.
    - Use absolute paths: For critical file system operations, consider using absolute paths defined within the application code instead of relying on user-provided relative paths from the configuration file.
- Preconditions:
    - The attacker must be able to provide a malicious YAML configuration file path to the application, typically via the `--para` command-line argument when running `main.py` or `inference.py`.
- Source Code Analysis:
    - File: `/code/code/main.py` and `/code/code/inference.py`
    - In `main.py` and `inference.py`, the `get_args()` function parses the `--para` argument:
    ```python
    parser.add_argument('--para', type=str, default='para.yml',
                            help="the path to the parameter file, has to be a yaml file")
    args = parser.parse_args()
    with open(args.para) as fin:
        paras = yaml.safe_load(fin)
    ```
    - The `yaml.safe_load()` function loads the YAML content from the file specified by `--para`.
    - The loaded parameters in `paras` are used to construct file paths throughout the code, for example in `main.py`:
    ```python
    paras['log_dir'] = os.path.join(paras['output_dir'], current_time)
    paras['result_dir'] = os.path.join(paras['output_dir'], current_time, paras['result_dir'])
    paras['cache_dir'] = os.path.join(paras['output_dir'], current_time, paras['cache_dir'])
    paras['cached_feature_dir'] = os.path.join(paras['cached_feature_dir'], paras['dataset'])
    train_file = os.path.join(paras['data_dir'], paras['dataset'], 'split', 'train.json')
    taxonomy_file = os.path.join(paras['data_dir'], paras['dataset'], 'split', 'taxonomy.json')
    seen_label_file = os.path.join(paras['data_dir'], paras['dataset'], 'split', 'seen_labels.txt')
    cached_file = os.path.join(paras['cached_feature_dir'], '{}_cached_examples_for_training.pt'.format(paras['mode']))
    taxonomy_cached_file = os.path.join(paras['cached_feature_dir'], '{}_cached_taxonomy.json'.format(paras['mode']))
    utils.make_all_dirs(paras) # creates directories based on paras
    ```
    - If a malicious `para.yml` is provided with manipulated path parameters, the `os.path.join()` and `utils.make_all_dirs()` functions will operate with these attacker-controlled paths, potentially leading to path traversal.
- Security Test Case:
    1. Create a malicious YAML configuration file named `malicious_para.yml` with the following content:
    ```yaml
    data_dir: "../../"
    output_dir: "output/"
    result_dir: "result/"
    cache_dir: "cache/"
    rl_result_dir: "rl_result/"
    rl_cache_dir: "rl_cache/"
    cached_feature_dir: "cached_input/"
    model_config: bert-base-uncased
    model_path: null
    ```
    2. Run the `main.py` script, providing the malicious configuration file via the `--para` argument and choosing a dataset (e.g., yelp) and mode (e.g., bert):
    ```bash
    python code/main.py --mode bert --model_config bert-base-uncased --para malicious_para.yml --dataset yelp
    ```
    3. Observe the application's behavior. Check the output logs and file system activity to see if the application attempts to access files or directories outside the intended project structure. For instance, monitor if it tries to read files from the parent directories due to the `data_dir: "../../"` setting.
    4. Expected outcome: The application will likely attempt to load data files from a path constructed using the manipulated `data_dir`, such as `../../yelp/split/train.json`, which is outside the intended `data` directory and demonstrates path traversal. Depending on file permissions and the existence of such files, this could lead to errors or information disclosure if sensitive files were located in the traversed paths.