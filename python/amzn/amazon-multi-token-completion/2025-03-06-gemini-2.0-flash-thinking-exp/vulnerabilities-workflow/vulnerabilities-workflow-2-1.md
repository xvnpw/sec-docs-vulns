### Vulnerability List

- Vulnerability Name: Path Traversal in Dataset Loading
- Description:
  1. The `test.py`, `matrix_plugin.py`, and `mtc_model.py` scripts load datasets using user-provided paths via command-line arguments `--dataset_path` and `--input_path`.
  2. Specifically, in `test.py`, if the `--dataset_path` argument is provided, the script directly uses it in `datasets.load_from_disk()`. Similarly, `matrix_plugin.py` uses `--input_path` and `mtc_model.py` uses `--input_path` (constructed from arguments) in `datasets.load_from_disk()` without any sanitization.
  3. An attacker can provide a malicious path like `../../../../../../../../etc/passwd` as the `--dataset_path` or `--input_path` argument.
  4. The `datasets.load_from_disk()` function will attempt to load the dataset from the attacker-controlled path, leading to a path traversal vulnerability.
- Impact:
  - High. An attacker can read arbitrary files from the server's file system that the Python process has permissions to access. This can include sensitive configuration files, source code, or data.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
  - None. The code directly uses user-provided paths without any validation or sanitization.
- Missing Mitigations:
  - Path sanitization: Implement checks to ensure that the provided dataset path is within the expected directory or restrict allowed characters to prevent traversal.
  - Input validation: Validate the format and content of the dataset path to ensure it is a valid directory for datasets.
- Preconditions:
  - The user must be able to execute `test.py`, `matrix_plugin.py`, or `mtc_model.py` and provide command-line arguments, specifically `--dataset_path` or `--input_path`.
- Source Code Analysis:
  - **test.py:**
    ```python
    if args.dataset_path is None:
        dataset = datasets.load_from_disk(f'{HOME_DIR}/MultiTokenCompletionData/input_data_{args.case}')
    else:
        dataset = datasets.load_from_disk(args.dataset_path) # Vulnerable line - user controlled path
    ```
    The `datasets.load_from_disk(args.dataset_path)` line directly uses the user-provided `args.dataset_path` without any checks.

  - **matrix_plugin.py:**
    ```python
    if args.force or not os.path.exists(model_path) or not os.path.exists(dataset_path):
        if args.input_path is not None:
            input_path = args.input_path # Vulnerable line - user controlled path
        elif 'roberta' in model_name:
            input_path = f'{HOME_DIR}/MultiTokenCompletionData/input_data_{model_name}{dataset_suffix}'
        elif 'spanbert' in model_name:
            input_path = f'input_data_{model_name}'
        else:
            input_path = f'{HOME_DIR}/MultiTokenCompletionData/input_data_cased'

        dataset = datasets.load_from_disk(input_path) # Vulnerable line - uses user controlled path
        ...
    else:
        seen_dataset = datasets.load_from_disk(dataset_path)
    ```
    The `datasets.load_from_disk(input_path)` line is vulnerable when `input_path` is derived from `args.input_path`.

  - **mtc_model.py:**
    ```python
    if not os.path.exists(input_path):
        print(f"PATH {input_path} wasn't found, creating data")
        parse_data(dataset_name, dataset_suffix)

    if not args.data_only:
        fs = S3FileSystem() if input_path.startswith('s3://') else None
        input_features = datasets.load_from_disk(input_path, fs=fs) # Vulnerable line - uses potentially user controlled path
    ```
    The `datasets.load_from_disk(input_path, fs=fs)` line is vulnerable when `input_path` is derived or directly taken from user input via arguments.

- Security Test Case:
  1. Open a terminal and navigate to the `/code` directory of the project.
  2. Run the `test.py` script with the following command, attempting to access the `/etc/passwd` file using path traversal:
     ```bash
     python test.py --dataset_path "../../../../../../../../../etc"
     ```
  3. Observe the output and errors. If the script attempts to load files from `/etc/passwd` or its parent directory, and you see errors related to dataset format or file reading from unexpected locations (e.g., errors trying to read CSV from `/etc`), this confirms the path traversal vulnerability.
  4. To further confirm, you can create a dummy dataset directory, for example, `/tmp/dummy_dataset`. Inside `/tmp/dummy_dataset`, create an empty file named `test_set.csv`.
  5. Now, run `test.py` again, trying to traverse out of the dummy dataset directory to read `/etc/passwd`:
     ```bash
     python test.py --dataset_path "/tmp/dummy_dataset/../../../../../../etc"
     ```
  6. Check the output for errors indicating attempts to read files from `/etc` or dataset loading failures from unexpected paths, which would further validate the path traversal.

- Vulnerability Name: Path Traversal in Checkpoint Loading
- Description:
  1. The `test.py`, `matrix_plugin.py`, `predict.py`, and `benchmark.py` scripts load model checkpoints using user-provided paths via command-line argument `--ckpt` or `--version`.
  2. In `test.py`, `matrix_plugin.py`, and `benchmark.py`, the `--ckpt` argument is directly passed to `Generation.load_from_checkpoint()`. In `predict.py`, it's either `--ckpt` or the result of `get_latest_ckpt()` that's used.
  3. An attacker can provide a malicious path like `../../../../../../../../etc/passwd` as the `--ckpt` argument.
  4. The `Generation.load_from_checkpoint()` function will attempt to load the checkpoint from the attacker-controlled path, leading to a path traversal vulnerability.
- Impact:
  - High. An attacker can attempt to load arbitrary files as checkpoints. While loading `/etc/passwd` as a checkpoint will likely fail due to format incompatibility, this vulnerability can be exploited to check for the existence of files or attempt to load other accessible files, potentially revealing information about the file system structure. In a more sophisticated scenario, if an attacker can upload a specially crafted file to a known location on the server, they might be able to trick the application into loading and executing malicious code disguised as a checkpoint if the checkpoint loading process is not sufficiently robust and performs deserialization without proper safeguards.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations:
  - None. The code directly uses user-provided paths without any validation or sanitization.
- Missing Mitigations:
  - Path sanitization: Implement checks to ensure that the provided checkpoint path is within the expected checkpoint directory or restrict allowed characters to prevent traversal.
  - Input validation: Validate the format and expected file extensions of the checkpoint path.
- Preconditions:
  - The user must be able to execute `test.py`, `matrix_plugin.py`, `predict.py`, or `benchmark.py` and provide command-line arguments, specifically `--ckpt` or `--version`.
- Source Code Analysis:
  - **test.py:**
    ```python
    ckpt = args.ckpt # User controlled path
    print('ckpt:', ckpt)
    if ckpt is None:
        if args.version is not None:
            ckpt = get_ckpt_version(args.version)
            print(f'using {ckpt}')
        else:
            ckpt = get_latest_ckpt()
            print(f'No checkpoint provided taking the latest: {ckpt}')

    model = Generation.load_from_checkpoint(ckpt).cuda() # Vulnerable line - user controlled path
    ```
    The `Generation.load_from_checkpoint(ckpt)` line directly uses the user-provided `args.ckpt` without checks.

  - **matrix_plugin.py:**
    ```python
    if args.test:
        ...
        ckpt = args.ckpt # User controlled path
        if ckpt is None:
            from glob import glob
            ckpt = sorted(glob(f'matrix_plugin_results/{args.version}/checkpoints/*.ckpt'))[-1]
        print(ckpt)
        test(matrix, seen_dataset, mapping, tok, ckpt, args.log)
    ```
    The `ckpt = args.ckpt` assignment makes `ckpt` user-controlled and vulnerable when used in checkpoint loading.

  - **predict.py:**
    ```python
    if model is None:
        model = Generation.load_from_checkpoint(ckpt or get_latest_ckpt()).cuda() # Vulnerable line - user controlled path
    ```
    `Generation.load_from_checkpoint()` is called with `ckpt` argument, which can be user-controlled.

  - **benchmark.py:**
    ```python
    ckpt = args.ckpt # User controlled path
    print('ckpt:', ckpt)
    if ckpt is None:
        if args.version is not None:
            ckpt = get_ckpt_version(args.version)
            print(f'using {ckpt}')
        else:
            ckpt = get_latest_ckpt()
            print(f'No checkpoint provided taking the latest: {ckpt}')

    # Loading model
    model = Generation.load_from_checkpoint(ckpt).cuda().eval() # Vulnerable line - user controlled path
    ```
    `Generation.load_from_checkpoint(ckpt)` uses `ckpt` which is user-provided via `args.ckpt`.

- Security Test Case:
  1. Open a terminal and navigate to the `/code` directory of the project.
  2. Run the `test.py` script with the following command, attempting to access the `/etc/passwd` file as a checkpoint using path traversal:
     ```bash
     python test.py --ckpt "../../../../../../../../../etc/passwd"
     ```
  3. Observe the output and errors. If the script attempts to load `/etc/passwd` as a checkpoint and you see errors related to checkpoint format or file reading from unexpected locations (e.g., errors indicating that `/etc/passwd` is not a valid checkpoint file), this confirms the path traversal vulnerability in checkpoint loading.
  4. Similar to the dataset test, you can create a dummy checkpoint file in a known location and then attempt to traverse out of that location to load `/etc/passwd` to further verify the vulnerability.