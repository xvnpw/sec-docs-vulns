## Combined Vulnerability List

The following vulnerabilities have been identified in the provided lists.

### 1. Unsafe Deserialization via `eval()` in Data Loading

- **Description:**
    1. The `load_data` function in `/code/src/utils.py` uses the `eval()` function to parse input text and act sequences from data files.
    2. Specifically, the lines `input_text = eval(items[0])` and `act_seq = eval(items[1])` in the `load_data` function interpret strings from the input data files as Python code and execute them.
    3. This allows for arbitrary code execution if a malicious user provides crafted data files. An attacker could inject malicious Python code into the data files (e.g., `train_<data>.txt`, `valid_<data>.txt`, `test_<data>.txt`).
    4. When the `load_data` function processes these files during training or testing, the `eval()` function will execute the attacker's injected code.

- **Impact:**
    Arbitrary code execution on the machine running the training or testing scripts. Successful exploitation can lead to complete system compromise, including data theft, malware installation, and denial of service.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    None. The code directly uses `eval()` without any input sanitization or validation.

- **Missing Mitigations:**
    - Replace `eval()` with a safe and appropriate deserialization method. If the data is intended to be in JSON format, use `json.loads()`. If it's meant to be Python literals (like lists, dictionaries, strings, numbers, booleans), use `ast.literal_eval()`. For plain text dialogue turns, directly read the text without using `eval()`.
    - Implement robust input validation and sanitization to ensure that the data files conform to the expected format and do not contain any executable code.

- **Preconditions:**
    - The user must train or test the model using a dataset that has been maliciously modified by an attacker.
    - The attacker needs to have a way to influence the data files that are read by the `load_data` function. This could be achieved by compromising the data source, or by convincing a user to use a malicious dataset.

- **Source Code Analysis:**
    1. **File:** `/code/src/utils.py`
    2. **Function:** `load_data(args, tokenizer)`
    3. **Vulnerable Code Block:**
    ```python
    with open(os.path.join(dirname, f'{set_name}_{args.data}.txt'), 'r', encoding='utf-8') as infile:
        for line in infile:
            items = line.strip('\n').split('\t')
            input_text = eval(items[0]) # Vulnerability: Unsafe use of eval()
            act_seq = eval(items[1])    # Vulnerability: Unsafe use of eval()
            sat = int(items[2])
            # ... rest of the code
    ```
    4. **Explanation:** The code reads data files line by line. Each line is split into items based on tab delimiters. The first and second items (`items[0]` and `items[1]`) are then passed to the `eval()` function. `eval()` in Python executes a string as a Python expression. If the content of `items[0]` or `items[1]` is maliciously crafted, it can contain arbitrary Python commands that will be executed with the privileges of the user running the script.

- **Security Test Case:**
    1. **Prepare Malicious Data File:** Create a new file named `test_sgd_malicious.txt` in the directory `dataset/sgd/`. Add the following line to this file:
        ```
        ["__import__('os').system('touch /tmp/pwned')"]	[""]	0
        ```
        This line is crafted so that when `eval(items[0])` is executed, it will run the Python command `os.system('touch /tmp/pwned')`, which creates an empty file named `pwned` in the `/tmp/` directory.
    2. **Modify `main.py` to use malicious data file:** Temporarily modify the `load_data` function in `/code/src/utils.py` to load the malicious data file. Change the line:
        ```python
        with open(os.path.join(dirname, f'{set_name}_{args.data}.txt'), 'r', encoding='utf-8') as infile:
        ```
        to:
        ```python
        with open(os.path.join(dirname, f'{set_name}_sgd_malicious.txt'), 'r', encoding='utf-8') as infile:
        ```
        This change ensures that the `load_data` function will read from `test_sgd_malicious.txt` instead of the original data file when processing the 'test' set.
    3. **Run the Test Script:** Execute the test script using the command: `./test.sh`. This will run the evaluation process, which includes loading the data using the modified `load_data` function and the malicious data file.
    4. **Verify Vulnerability:** After running the test script, check if the file `/tmp/pwned` has been created. You can use the command `ls /tmp/pwned` in your terminal. If the file `pwned` exists in the `/tmp/` directory, it confirms that the malicious code injected into the data file was successfully executed by the `eval()` function, demonstrating arbitrary code execution.

### 2. Deserialization of Untrusted Data via Pickle

- **Description:**
    1. An attacker modifies the preprocessed data file (e.g., `mwoz_64.pkl`) located in the `dataset/{args.data}/tokenized/` directory. This file is created by `utils.py` and contains pickled Python objects.
    2. The user downloads and runs `train.sh` or `test.sh`.
    3. `main.py` is executed, which in turn calls `utils.load_data(args, tokenizer)`.
    4. `utils.load_data` checks for the existence of the pickled data file. If it exists and `args.rewrite_data` is not set, it loads the data using `pickle.read_pkl`, which calls `pickle.load`.
    5. If the attacker has injected malicious code into the pickled data, `pickle.load` will execute this code during deserialization.

- **Impact:** Arbitrary code execution. The attacker can gain full control over the user's machine.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:** None. The code directly uses `pickle.load` without any safety measures.

- **Missing Mitigations:**
    - Avoid using pickle for loading data from potentially untrusted sources.
    - Use safer serialization formats like JSON or CSV if possible, or formats that are designed to be safe for deserialization.
    - If pickle is necessary, implement integrity checks (e.g., digital signatures) to ensure the data has not been tampered with.
    - Provide clear warnings to users about the security risks of running code from untrusted sources and advise them to only use original, unmodified scripts and data.

- **Preconditions:**
    - The attacker needs to be able to replace the preprocessed data files in the `dataset/{args.data}/tokenized/` directory before the user runs the training or testing scripts. This is feasible in a social engineering attack scenario where the attacker distributes a modified version of the repository.
    - The user must execute `train.sh` or `test.sh` (or directly `main.py`) without the `--rewrite_data` flag, so that the existing pickle file is loaded.

- **Source Code Analysis:**
    1. In `/code/src/utils.py`, the function `read_pkl(filename)` is defined:
       ```python
       def read_pkl(filename):
           with open(filename, 'rb') as f:
               return pickle.load(f)
       ```
       This function uses `pickle.load` to deserialize data from a file. `pickle.load` is known to be vulnerable to arbitrary code execution if the data source is untrusted.
    2. This function is called by `load_data(args, tokenizer)` in `/code/src/utils.py`:
       ```python
       if os.path.exists(f'{dirname}/tokenized/{args.data}_{args.max_seq_len}.pkl') and not args.rewrite_data:
           return read_pkl(f'{dirname}/tokenized/{args.data}_{args.max_seq_len}.pkl')
       ```
       The `load_data` function checks if a pre-tokenized data file exists. If it does and the `rewrite_data` flag is not set, it loads the data from the pickle file using `read_pkl`.
    3. `load_data` is called in `/code/src/main.py` in both training and evaluation modes.
    4. `train.sh` and `test.sh` scripts execute `main.py` without `--rewrite_data`, making the code vulnerable by default if malicious pickle files are present.

- **Security Test Case:**
    1. Prepare malicious pickle file:
       - Create a malicious Python object that executes code when unpickled. For example, create a file named `malicious_pickle_gen.py` with the following content:
         ```python
         import pickle
         import os

         class Malicious(object):
             def __reduce__(self):
                 return (os.system, ('touch /tmp/pwned',))

         malicious_data = {'train': {'input_ids': [], 'input_text': [], 'act_seq': [], 'sat': [], 'schema_ids': [], 'schema_text': [Malicious()]}, 'valid': {'input_ids': [], 'input_text': [], 'act_seq': [], 'sat': [], 'schema_ids': [], 'schema_text': []}, 'test': {'input_ids': [], 'input_text': [], 'act_seq': [], 'sat': [], 'schema_ids': [], 'schema_text': []}, 'act_list': {}}

         with open('/tmp/malicious_mwoz_64.pkl', 'wb') as f:
             pickle.dump(malicious_data, f)
         ```
       - Run `python malicious_pickle_gen.py` to generate the malicious pickle file `/tmp/malicious_mwoz_64.pkl`.
    2. Replace legitimate data file:
       - Assume the user is using `mwoz` dataset and `max_seq_len=64`.
       - Replace the file `/code/dataset/mwoz/tokenized/mwoz_64.pkl` with `/tmp/malicious_mwoz_64.pkl`. Use the command: `cp /tmp/malicious_mwoz_64.pkl /code/dataset/mwoz/tokenized/mwoz_64.pkl`
    3. Run training script:
       - Navigate to the `/code` directory: `cd /code`
       - Execute the training script: `./train.sh`
    4. Check for execution:
       - After running the script, check if the file `/tmp/pwned` exists. Use the command: `ls /tmp/pwned`. If this command shows the file `/tmp/pwned`, it confirms that the malicious code from the pickle file was executed, demonstrating the vulnerability.