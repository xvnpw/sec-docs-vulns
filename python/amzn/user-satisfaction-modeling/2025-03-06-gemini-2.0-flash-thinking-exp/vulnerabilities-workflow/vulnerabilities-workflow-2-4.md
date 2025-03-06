### Vulnerability List

- **Vulnerability Name:** Unsafe Deserialization via `eval()` in Data Loading
- **Description:**
    The `load_data` function in `/code/src/utils.py` uses the `eval()` function to parse input text and act sequences from data files. Specifically, the lines `input_text = eval(items[0])` and `act_seq = eval(items[1])` in the `load_data` function interpret strings from the input data files as Python code and execute them. This allows for arbitrary code execution if a malicious user provides crafted data files. An attacker could inject malicious Python code into the data files (e.g., `train_<data>.txt`, `valid_<data>.txt`, `test_<data>.txt`). When the `load_data` function processes these files during training or testing, the `eval()` function will execute the attacker's injected code.
- **Impact:**
    Arbitrary code execution on the machine running the training or testing scripts. Successful exploitation can lead to complete system compromise, including data theft, malware installation, and denial of service.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    None. The code directly uses `eval()` without any input sanitization or validation.
- **Missing Mitigations:**
    - Replace `eval()` with a safe and appropriate deserialization method. If the data is intended to be in JSON format, use `json.loads()`. If it's meant to be Python literals (like lists, dictionaries, strings, numbers, booleans), use `ast.literal_eval()`.
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
    5. **Clean Up:**
        - Delete the created file: `rm /tmp/pwned`
        - Revert the changes made to `/code/src/utils.py` to ensure that the code loads the original data files.
        - Optionally, delete the malicious data file `dataset/sgd/test_sgd_malicious.txt` if it's no longer needed.