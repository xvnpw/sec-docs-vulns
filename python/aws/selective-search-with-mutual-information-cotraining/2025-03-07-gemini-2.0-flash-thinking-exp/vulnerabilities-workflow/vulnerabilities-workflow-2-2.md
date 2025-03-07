- Vulnerability Name: Path Traversal in Dataset Paths
- Description:
    1. The application accepts `train_folder_path` and `test_folder_path` as command-line arguments to specify the directories containing training and testing datasets.
    2. These paths are directly passed to the `QueryDocumentsPair` class in `mico/dataloader/query_doc_pair.py` without any sanitization or validation.
    3. Inside the `QueryDocumentsPair` class, the application uses `os.listdir()` with the provided paths to list files within these directories.
    4. Subsequently, it constructs file paths by simply concatenating the provided folder path with the filenames obtained from `os.listdir()`.
    5. Due to the lack of path validation, an attacker can manipulate the `train_folder_path` or `test_folder_path` parameters to include path traversal sequences like `../`.
    6. By providing a malicious path such as `../`, the `os.listdir()` function will list files in the parent directory, and the application will attempt to access files outside of the intended data directories.

- Impact:
    - Information Disclosure: A successful path traversal attack could allow an attacker to read sensitive files and directories on the server. If the application is deployed in an environment where an attacker can control the `train_folder_path` or `test_folder_path` parameters (e.g., through a web interface or API, or by gaining command-line access), they could potentially access configuration files, application code, or other sensitive data located outside the intended data directories.
    - In the context of this specific application, while the immediate code only reads files, the vulnerability creates a broader security risk. In other applications with path traversal flaws, attackers could potentially achieve command execution or data modification if write operations or other functionalities were exposed through similar vulnerabilities.

- Vulnerability Rank: High
- Currently Implemented Mitigations: None
- Missing Mitigations:
    - Path Sanitization and Validation: The application should implement robust path sanitization and validation checks for `train_folder_path` and `test_folder_path`. This should include:
        - Validating that the provided paths are absolute paths or resolving relative paths to absolute paths using `os.path.abspath()`.
        - Checking if the resolved paths are within an allowed data directory using `os.path.commonprefix()` to compare the resolved path with a predefined allowed base path.
        - Rejecting paths that contain path traversal sequences like `../` or symbolic links that point outside the allowed directories.
    - Principle of Least Privilege: The application should be run with minimal necessary privileges to limit the impact of a successful path traversal attack.

- Preconditions:
    - The application must be deployed in an environment where an attacker can control the command-line arguments, specifically `train_folder_path` and `test_folder_path`. This could occur in scenarios where:
        - The application is exposed through a web interface or API that allows users to specify these paths as input parameters.
        - An attacker has gained unauthorized access to the system's command line or configuration files and can modify the execution parameters of the application.

- Source Code Analysis:
    - File: `/code/mico/dataloader/query_doc_pair.py`
    - Code Snippet:
      ```python
      def __init__(self, train_folder_path=None, test_folder_path=None, is_csv_header=True, val_ratio=0.1, is_get_all_info=False):
          ...
          train_files = list(map(lambda x : train_folder_path + '/' + x, (filter(lambda x : x.endswith("csv"), sorted(os.listdir(train_folder_path))))))
          train_dataset_list = []
          val_dataset_list = []
          for csv_file in train_files:
              train_dataset = LazyTextDataset(csv_file, val_ratio=val_ratio, is_csv_header=self._is_csv_header, is_get_all_info=is_get_all_info)
              train_dataset_list.append(train_dataset)
              val_dataset = LazyTextDataset(csv_file, val_indices=train_dataset.val_indices, is_csv_header=self._is_csv_header, is_get_all_info=is_get_all_info)
              val_dataset_list.append(val_dataset)
          self.train_dataset = ConcatDataset(train_dataset_list)
          logging.info('train_dataset sample size: %d' % self.train_dataset.__len__())
          self.val_dataset = ConcatDataset(val_dataset_list)
          logging.info('val_dataset sample size: %d' % self.val_dataset.__len__())

          test_files = list(map(lambda x : test_folder_path + '/' + x, (filter(lambda x : x.endswith("csv"), sorted(os.listdir(test_folder_path))))))
          test_dataset_list = list(map(lambda x : LazyTextDataset(x, is_csv_header=self._is_csv_header, is_get_all_info=is_get_all_info), test_files))
          self.test_dataset = ConcatDataset(test_dataset_list)
          logging.info('test_dataset sample size: %d' % self.test_dataset.__len__())
      ```
    - Visualization:
      ```
      User Input (train_folder_path, test_folder_path) --> QueryDocumentsPair.__init__
                                                        --> os.listdir(train_folder_path) --> Lists files in provided path (potentially malicious)
                                                        --> path concatenation (train_folder_path + '/' + filename) --> Malicious path constructed
                                                        --> LazyTextDataset(malicious_csv_file_path) --> File operations on potentially sensitive files
      ```
    - Step-by-step analysis:
        1. The `QueryDocumentsPair` class constructor receives `train_folder_path` and `test_folder_path` directly from command-line arguments.
        2. `os.listdir(train_folder_path)` is called. If `train_folder_path` is set to `../`, this will list files in the parent directory of the intended data directory.
        3. The code iterates through the listed filenames and constructs file paths using simple string concatenation: `train_folder_path + '/' + x`. If `train_folder_path` is `../` and `x` is `sensitive.txt`, the constructed path becomes `../sensitive.txt`, leading to path traversal.
        4. `LazyTextDataset` is initialized with these potentially malicious paths, and file operations within `LazyTextDataset` (like opening and reading CSV files) will then operate on files outside the intended data directory, based on the attacker-controlled path.

- Security Test Case:
    1. **Setup:**
        - Deploy the MICO application in a test environment.
        - Navigate to the `/code/example/data/` directory.
        - Create a new directory named `sensitive_data`.
        - Inside `sensitive_data`, create a file named `sensitive.txt` with some sensitive content (e.g., "This is a sensitive file.").
        - Move the directory `sensitive_data` to the parent directory of `/code/example/data/`, so that `sensitive_data` is at the same level as `example` directory. The path to `sensitive.txt` will be now `<parent_dir_of_code>/sensitive_data/sensitive.txt`.

    2. **Attack:**
        - Modify the `run_mico.sh` script located in `/code/example/scripts/`.
        - Change the `train_folder_path` and `test_folder_path` variables to point to the parent directory using `../` and target the `sensitive_data` directory to attempt to access `sensitive.txt`. For example:
          ```bash
          dataset_name=example
          train_folder_path=../sensitive_data/
          test_folder_path=../sensitive_data/
          ```
        - Run the modified `run_mico.sh` script from the `/code/example/scripts/` directory: `bash run_mico.sh`.

    3. **Observe:**
        - Check the application's output and logs in the `./results/` directory, specifically the training log file (`train.*.log`).
        - Look for error messages or exceptions related to file processing or path issues. In this case, you may see errors because the application is expecting CSV files but is now trying to process `sensitive.txt` or other files in `sensitive_data` directory which are not CSV files, or not in the expected CSV format.

    4. **Verify Information Disclosure (Indirect):**
        - While this specific test case might not directly demonstrate reading the content of `sensitive.txt` due to the application's CSV processing logic, the errors observed in step 3 confirm that the application is indeed attempting to access files within the `../sensitive_data/` directory as instructed by the attacker-controlled `train_folder_path` and `test_folder_path`.
        - This demonstrates the path traversal vulnerability because `os.listdir` and subsequent file path construction are successfully operating outside of the intended `./example/data/` directory and within the attacker-specified `../sensitive_data/` directory. In a more general scenario where the application might directly display or process file contents, this vulnerability could directly lead to information disclosure.

This test case proves that an attacker can control the paths used by the application to list and access files, thus confirming the path traversal vulnerability.