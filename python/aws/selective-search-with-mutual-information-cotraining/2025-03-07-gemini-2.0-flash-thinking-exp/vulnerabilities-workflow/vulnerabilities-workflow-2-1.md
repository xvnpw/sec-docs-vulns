### Vulnerability List

*   **Vulnerability Name:** Path Traversal in Data Folder Paths

*   **Description:**
    1.  The MICO application accepts command-line arguments `--train_folder_path` and `--test_folder_path` to specify the directories containing training and testing data in CSV format.
    2.  These paths are directly used by the `QueryDocumentsPair` class in `mico/dataloader/query_doc_pair.py` to construct file paths to CSV files.
    3.  The application iterates through files within these directories using `os.listdir()` and constructs full file paths by concatenating the base folder path with the file names.
    4.  If a user provides a maliciously crafted path like `../`, the application will traverse up the directory structure.
    5.  By providing paths like `--train_folder_path=../` or `--test_folder_path=../`, an attacker can potentially access files and directories outside of the intended data directories, leading to information disclosure. For example, an attacker could read system files or application files by crafting a path that points to them.

*   **Impact:**
    *   **Information Disclosure:** An attacker can read arbitrary files on the server's file system that the application process has read permissions to. This could include sensitive data, configuration files, or even parts of the application's source code.

*   **Vulnerability Rank:** High

*   **Currently Implemented Mitigations:**
    *   None. The code directly uses the provided paths without any sanitization or validation.

*   **Missing Mitigations:**
    *   **Input Validation and Sanitization:** Implement proper input validation to sanitize the `--train_folder_path` and `--test_folder_path` arguments. This should include:
        *   **Path Canonicalization:** Convert the provided paths to their canonical form to resolve symbolic links and remove redundant path components like `.` and `..`.
        *   **Path Traversal Prevention:** Validate that the resolved paths are within the intended data directory or a set of allowed directories. Reject paths that attempt to traverse outside these allowed boundaries.
        *   **Allowed Characters:** Restrict the allowed characters in the path to prevent injection of special characters that could be used in exploits.

*   **Preconditions:**
    *   The attacker needs to be able to execute the `main.py` script or `run_mico.sh` script and control the command-line arguments, specifically `--train_folder_path` and `--test_folder_path`. In a real-world scenario, this might be possible if the application is exposed through a web interface or API that allows users to specify these paths, or if an attacker gains access to the server and can run the scripts directly.

*   **Source Code Analysis:**
    1.  **`main.py`**:
        *   The script uses `argparser = get_model_specific_argparser()` to parse command-line arguments.
        *   `hparams = argparser.parse_args()` stores the parsed arguments, including `--train_folder_path` and `--test_folder_path`, in the `hparams` object.
        *   The `hparams` object is then passed to `QueryDocumentsPair` in `mico/dataloader/query_doc_pair.py`.

    2.  **`mico/utils/utils.py`**:
        *   `get_model_specific_argparser()` defines the command-line arguments.
        *   It defines `--train_folder_path` and `--test_folder_path` as `type=str`, but there is no validation or sanitization applied here.

    3.  **`mico/dataloader/query_doc_pair.py`**:
        *   In the `QueryDocumentsPair.__init__` method:
            ```python
            train_files = list(map(lambda x : train_folder_path + '/' + x, (filter(lambda x : x.endswith("csv"), sorted(os.listdir(train_folder_path))))))
            test_files = list(map(lambda x : test_folder_path + '/' + x, (filter(lambda x : x.endswith("csv"), sorted(os.listdir(test_folder_path))))))
            ```
            *   `train_folder_path` and `test_folder_path` from `hparams` are directly used to construct file paths.
            *   `os.listdir(train_folder_path)` and `os.listdir(test_folder_path)` list files in the provided directories.
            *   The code iterates through the results of `os.listdir()` and concatenates `train_folder_path + '/' + x` and `test_folder_path + '/' + x` to create full file paths.
            *   **No path sanitization or validation is performed before using these paths.** This allows path traversal if `train_folder_path` or `test_folder_path` contains `../` or similar path traversal sequences.

    **Visualization:**

    ```
    main.py --> get_model_specific_argparser() --> argparse.ArgumentParser (defines --train_folder_path, --test_folder_path)
          |
          v
    main.py --> hparams = argparser.parse_args() (parses arguments)
          |
          v
    main.py --> QueryDocumentsPair(train_folder_path=hparams.train_folder_path, test_folder_path=hparams.test_folder_path, ...)
          |
          v
    mico/dataloader/query_doc_pair.py --> QueryDocumentsPair.__init__(train_folder_path, test_folder_path, ...)
          |
          v
    mico/dataloader/query_doc_pair.py --> os.listdir(train_folder_path) / os.listdir(test_folder_path) (lists files in provided paths - VULNERABILITY)
          |
          v
    mico/dataloader/query_doc_pair.py --> path concatenation (train_folder_path + '/' + filename) / (test_folder_path + '/' + filename) (constructs file paths - VULNERABILITY)
          |
          v
    mico/dataloader/query_doc_pair.py --> LazyTextDataset(filepath, ...) (opens and reads files using constructed paths - VULNERABILITY)
    ```

*   **Security Test Case:**
    1.  **Prerequisites:**
        *   Have the MICO project code set up and runnable.
        *   Assume the attacker has access to run `run_mico.sh` or `main.py` with modified arguments.

    2.  **Steps:**
        a.  Navigate to the `example/scripts` directory in the project.
        b.  Modify the `run_mico.sh` script. Change the `train_folder_path` and `test_folder_path` variables to point to a sensitive file outside the intended data directories using path traversal. For example, to attempt to read the `/etc/passwd` file (on Linux-like systems), set:
            ```bash
            train_folder_path=../../../etc/
            test_folder_path=../../../etc/
            ```
            And modify the `train_files` and `test_files` lines in `mico/dataloader/query_doc_pair.py` to look for `passwd` file instead of `csv` to avoid errors if no csv is found in `/etc/`.
            ```python
            train_files = list(map(lambda x : train_folder_path + '/' + x, (filter(lambda x : x.endswith("passwd"), sorted(os.listdir(train_folder_path))))))
            test_files = list(map(lambda x : test_folder_path + '/' + x, (filter(lambda x : x.endswith("passwd"), sorted(os.listdir(test_folder_path))))))
            ```
            Alternatively, to read a file relative to the project root, assuming the script is run from `example/scripts`, you can use:
            ```bash
            train_folder_path=../../../code/README.md
            test_folder_path=../../../code/README.md
            ```
            And in `mico/dataloader/query_doc_pair.py`, modify the filters to look for `README.md` files.
             ```python
            train_files = list(map(lambda x : train_folder_path + '/' + x, (filter(lambda x : x.endswith("README.md"), sorted(os.listdir(train_folder_path))))))
            test_files = list(map(lambda x : test_folder_path + '/' + x, (filter(lambda x : x.endswith("README.md"), sorted(os.listdir(test_folder_path))))))
            ```
        c.  Run the modified `run_mico.sh` script:
            ```bash
            ./run_mico.sh
            ```
        d.  **Observe the output:** If the path traversal is successful, the application may attempt to process the files from the specified path. Depending on the file content and the application's behavior, you might see errors related to file format if it's not a CSV file, or in case of reading README.md, the program might proceed further but with unexpected data. If you modify the code to print the filenames being processed, you will observe that files from `/etc/` or project root are being accessed, confirming the path traversal vulnerability.

    3.  **Expected Result:** The application attempts to read files from the path specified in the modified `train_folder_path` and `test_folder_path` arguments, demonstrating that it is possible to traverse directories outside of the intended data directory. This confirms the path traversal vulnerability.