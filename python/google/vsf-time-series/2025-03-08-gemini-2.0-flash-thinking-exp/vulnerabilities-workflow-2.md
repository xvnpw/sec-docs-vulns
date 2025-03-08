## Vulnerability Report

### Path Traversal in `--data` Argument of `train_multi_step.py`

- **Vulnerability Name:** Path Traversal in `--data` Argument
- **Description:**
    The `train_multi_step.py` script uses the `--data` command-line argument to specify the directory for loading datasets. This argument's value is passed to the `load_dataset` function in `util.py` without sufficient sanitization or validation. Inside `load_dataset`, the provided path is directly used with `os.path.join` to construct file paths for loading data files (train.npz, val.npz, test.npz). An attacker can exploit this by providing a crafted path containing path traversal sequences like `../../../../etc` as the `--data` argument. This will cause `os.path.join` to resolve to paths outside the intended `data` directory, such as `../../../../etc/train.npz`. Consequently, the application attempts to load data files from these manipulated paths, potentially accessing sensitive files or directories elsewhere on the system.

- **Impact:**
    An attacker can read arbitrary files from the system by providing a malicious path to the `--data` argument. This could allow access to sensitive information such as configuration files, application code, credentials, or other data that the application user has access to. Depending on the file system permissions of the application process, an attacker could potentially read any file on the server. Exposure of such information can lead to further system compromise.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    None. The code directly uses the provided path from the `--data` argument without any validation or sanitization.

- **Missing Mitigations:**
    - **Input Path Sanitization and Validation:** Implement robust input sanitization on the `--data` argument in `train_multi_step.py`. Prevent path traversal sequences like `../` and ensure the path is restricted to the intended data directory.
    - **Path Validation:** Validate that the provided path is within the expected data directory and does not contain any malicious components. Implement checks to ensure that the resolved path is within the allowed data directory and does not contain path traversal sequences. Consider using secure path handling functions that prevent path traversal vulnerabilities.
    - **Principle of Least Privilege:** Ensure the application runs with the minimum necessary file system permissions to limit the impact of a successful path traversal attack.

- **Preconditions:**
    - The attacker must be able to execute the `train_multi_step.py` script.
    - The attacker must be able to control the command-line arguments, specifically the `--data` argument. This could be through direct shell access or a vulnerable interface that allows passing arguments to the script.

- **Source Code Analysis:**
    1. **File: `/code/train_multi_step.py`**
        ```python
        import argparse
        # ...
        parser = argparse.ArgumentParser()
        parser.add_argument('--data',type=str,default='data/METR-LA',help='data path')
        args = parser.parse_args()
        # ...
        dataloader = load_dataset(args, args.data, args.batch_size, args.batch_size, args.batch_size)
        ```
        - The `argparse` module is used to parse command-line arguments.
        - The `--data` argument is defined and its value is retrieved into `args.data`.
        - `args.data` is directly passed to the `load_dataset` function.

    2. **File: `/code/util.py`**
        ```python
        import os
        import numpy as np
        # ...
        def load_dataset(args, dataset_dir, batch_size, valid_batch_size= None, test_batch_size=None):
            # ...
            for category in ['train', 'val', 'test']:
                cat_data = np.load(os.path.join(dataset_dir, category + '.npz'))
                # ...
        ```
        - The `load_dataset` function receives `dataset_dir` (which is the value of `args.data`).
        - `os.path.join(dataset_dir, category + '.npz')` constructs the file path by joining `dataset_dir` with filenames.
        - `np.load()` then attempts to load data from this potentially attacker-controlled path without any sanitization of `dataset_dir`.

    3. **Visualization:**
        ```mermaid
        graph LR
            A[User Input: --data argument] --> B(train_multi_step.py: argparse.parse_args());
            B --> C{train_multi_step.py: args.data};
            C --> D(util.py: load_dataset dataset_dir);
            D --> E(util.py: os.path.join);
            E --> F(util.py: np.load());
            F --> G[File System Access (Potentially Traversal)];
        ```

- **Security Test Case:**
    1. Open a terminal in a publicly accessible instance of the project.
    2. Navigate to the `/code` directory.
    3. Run the training script with a path traversal payload for the `--data` argument to attempt to access the `/etc` directory:
       ```bash
       python train_multi_step.py --data '../../../../etc'
       ```
    4. Observe the error messages. If the output includes an error like `FileNotFoundError` and the path in the error message starts with or contains `../../../../etc`, it indicates that the script is attempting to access files outside the intended `data` directory, confirming the path traversal vulnerability. For example, an error message like: `FileNotFoundError: [Errno 2] No such file or directory: '../../../../etc/train.npz'` would be a clear indicator.
    5. To further verify, try to access a known file like `/etc/passwd`:
       ```bash
       python train_multi_step.py --data '../../../../etc/passwd'
       ```
    6. Check the error output again. If the script attempts to load `passwd.npz` from within the `/etc/passwd` directory (which is not a directory), or if you observe file system access attempts to locations outside the project's `data` directory via system monitoring tools, it confirms the path traversal vulnerability.


### Data Poisoning via Compromised External Data Sources

- **Vulnerability Name:** Data Poisoning via Compromised External Data Sources
- **Description:**
    The project's `README.md` file directs users to download datasets from external, third-party websites and services, including GitHub, Google Drive, Baidu Yun, and a time series classification website. These external sources are not under the project's direct control. An attacker could compromise these external data sources by gaining unauthorized access to accounts, compromising servers, or performing man-in-the-middle attacks if links are not secure (HTTPS). Once compromised, the attacker could replace the legitimate datasets with poisoned datasets containing manipulated time-series data. Users following the `README.md` instructions would download and use these poisoned datasets to train the models, leading to models trained on corrupted information.

- **Impact:**
    Training models with poisoned datasets can lead to a range of negative impacts:
    - Degraded forecasting accuracy, rendering models unreliable.
    - Skewed or biased predictions, leading to incorrect decisions in applications.
    - Potentially manipulated predictions causing harm in critical applications like traffic control, energy management, or healthcare if these models are deployed in such systems.
    - Loss of trust in the model and the research project's integrity.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    None. The project entirely relies on the security of external websites and services for data integrity. There are no mechanisms in place to verify the downloaded datasets' authenticity or integrity.

- **Missing Mitigations:**
    - **Integrity Checks:** Implement checksum verification for datasets. Provide SHA256 or similar checksums for each dataset in the `README.md`, allowing users to verify downloaded files using tools like `sha256sum`.
    - **Secure Hosting:** Host datasets within the project's repository (using Git LFS) or on project-controlled secure cloud storage (AWS S3, Azure Blob Storage) with access controls. This reduces reliance on external, potentially less secure, third-party platforms.
    - **Data Source Verification Instructions:** Add clear instructions in `README.md` on how users can independently verify data sources' authenticity and integrity, even if external links are used, linking to official dataset websites or publications.
    - **Data Sanitization and Anomaly Detection:** Implement basic data sanitization and anomaly detection checks within the `generate_training_data.py` script to identify potential data corruption or manipulation, such as checking for out-of-range values or statistical anomalies.

- **Preconditions:**
    - An attacker must successfully compromise one or more of the external data sources linked in the `README.md`.
    - Users must follow the instructions in the `README.md` and download datasets from these compromised external sources.
    - Users must execute the `generate_training_data.py` script and subsequently train models using the downloaded (potentially poisoned) datasets.

- **Source Code Analysis:**
    1. **File: `/code/README.md`**: This file contains the vulnerable links to external data sources without integrity verification mechanisms.
    2. **File: `/code/generate_training_data.py`**:
        ```python
        import pandas as pd
        # ...
        def generate_train_val_test(args):
            if args.ds_name == "metr-la":
                df = pd.read_hdf(args.dataset_filename) # Reads HDF5 file without integrity checks
            else:
                df = pd.read_csv(args.dataset_filename, delimiter = ",", header=None) # Reads CSV file without integrity checks
            # ...
        ```
        - The script uses `pandas.read_hdf` and `pandas.read_csv` to read data files specified by `--dataset_filename` without any integrity checks.

- **Security Test Case:**
    1. **Attacker Compromises External Data Source (Simulated):** Simulate compromising the METR-LA dataset on the Google Drive link by creating a modified `metr-la.h5` dataset (poisoned) with subtly altered traffic data values to introduce bias.
    2. **Victim Downloads Poisoned Dataset:** The victim user downloads the (simulated) compromised METR-LA dataset from the Google Drive link as `data/metr-la.h5` following `README.md` instructions.
    3. **Victim Generates Training Data:** Run `generate_training_data.py` to process the poisoned dataset:
       ```bash
       python generate_training_data.py --ds_name metr-la --output_dir data/METR-LA --dataset_filename data/metr-la.h5
       ```
    4. **Victim Trains Model:** Train the MTGNN model using the generated data:
       ```bash
       python train_multi_step.py --data ./data/METR-LA --model_name mtgnn --device cuda:0 --expid 1 --epochs 2 --batch_size 64 --runs 1 --random_node_idx_split_runs 1 --lower_limit_random_node_selections 100 --upper_limit_random_node_selections 100 --step_size1 2500 --mask_remaining false
       ```
    5. **Victim Evaluates Model:** Evaluate the trained model and compare metrics and predictions to a model trained on a clean dataset to observe the impact of data poisoning (e.g., skewed predictions, different evaluation metrics).


### Path Traversal in `--dataset_filename` Argument of `generate_training_data.py`

- **Vulnerability Name:** Path Traversal in Dataset Filename
- **Description:**
    The `generate_training_data.py` script uses the `--dataset_filename` argument to specify the path to the raw dataset file. This argument is directly passed to pandas `read_hdf` or `read_csv` functions without any sanitization or validation. An attacker can provide a malicious path as the `--dataset_filename` argument, such as "../../sensitive_file.txt", to read files outside the intended data directory. When `generate_training_data.py` is executed with this malicious argument, the pandas library will attempt to read the file from the attacker-specified path, potentially leading to arbitrary file read.

- **Impact:**
    An attacker can read arbitrary files from the server's filesystem that the Python process has permissions to access. This could include sensitive data, configuration files, or even source code, depending on the server setup and file permissions. The severity is high as it allows unauthorized access to potentially sensitive information.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    None. The code directly uses the user-provided filename without any checks or sanitization.

- **Missing Mitigations:**
    - **Input Validation:** Sanitize and validate the `dataset_filename` argument to ensure it only points to files within the intended data directory. This can be achieved by:
        - Using `os.path.abspath` and `os.path.commonprefix` to verify if the resolved path is within an allowed data directory.
        - Implementing a whitelist of allowed data directories and checking if the provided path starts with one of them.
        - Stripping path traversal characters like ".." from the input filename before using it.

- **Preconditions:**
    - The attacker needs to be able to execute the `generate_training_data.py` script and control the command-line arguments, specifically `--dataset_filename`. This could be possible if the script is exposed through a web interface or if the attacker has compromised a system where the script is run.

- **Source Code Analysis:**
    1. **File: `/code/generate_training_data.py`**
    2. **Argument Parsing (Lines 131-134):**
        ```python
        parser = argparse.ArgumentParser()
        # ...
        parser.add_argument(
            "--dataset_filename",
            type=str,
            default="data/metr-la.h5",
            help="Raw dataset readings.",
        )
        args = parser.parse_args()
        ```
        - The `--dataset_filename` argument is defined to accept a string input without any validation within the argument parser itself.

    3. **File Reading (Lines 141 & 143):**
        ```python
        if args.ds_name == "metr-la":
            df = pd.read_hdf(args.dataset_filename)
        else:
            df = pd.read_csv(args.dataset_filename, delimiter = ",", header=None)
        ```
        - The `dataset_filename` argument, directly obtained from user input via `args.dataset_filename`, is used in `pd.read_hdf` or `pd.read_csv` without any prior validation or sanitization. This directly leads to file system access based on user-controlled input.

    4. **Visualization:**
        ```mermaid
        graph LR
            A[User Input: --dataset_filename] --> B(generate_training_data.py: argparse.parse_args());
            B --> C{generate_training_data.py: args.dataset_filename};
            C --> D[pandas.read_hdf/read_csv];
            D --> E[File System Access (Potentially Traversal)];
        ```

- **Security Test Case:**
    1. **Precondition:** Ensure the project code is cloned and the environment is set up.
    2. **Step 1:** Navigate to the `/code` directory in a terminal.
    3. **Step 2:** Execute `generate_training_data.py` with a malicious `dataset_filename` to read `/etc/passwd`:
       ```bash
       python generate_training_data.py --ds_name metr-la --output_dir data/METR-LA --dataset_filename ../../../../../etc/passwd
       ```
    4. **Step 3:** Check output/errors. If the script attempts to process or read `/etc/passwd`, it confirms path traversal. Due to permissions, reading `/etc/passwd` might fail, but the attempt is key evidence.
    5. **Step 4 (Improved Test):** Create `/tmp/test_file.txt` with "This is a test file":
       ```bash
       echo "This is a test file" > /tmp/test_file.txt
       ```
    6. **Step 5:** Run `generate_training_data.py` to read `/tmp/test_file.txt`:
       ```bash
       python generate_training_data.py --ds_name metr-la --output_dir data/METR-LA --dataset_filename ../../../../../tmp/test_file.txt
       ```
    7. **Step 6:** Examine output/logs. If the script runs without path errors and attempts to process "This is a test file" as dataset, it confirms the path traversal vulnerability. The script's behavior depends on how it handles `/tmp/test_file.txt` content, but no path errors and script execution indicate success.