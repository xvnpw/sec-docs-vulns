### Vulnerability List

- Vulnerability Name: Pickle Deserialization Vulnerability
- Description: The `load_adj` function in `/code/code/Model/utils.py` uses `np.load(file_adj, allow_pickle=True)` to load adjacency data from pickle files. This function is called by `load_data` to load `adjs.pickle`. Using `allow_pickle=True` when loading data from untrusted sources is insecure because it allows for arbitrary code execution during deserialization. An attacker can craft a malicious pickle file that executes arbitrary Python code when loaded.
- Impact: Remote Code Execution (RCE). Successful exploitation allows an attacker to execute arbitrary Python code on the machine running the training script. This can lead to complete system compromise, data theft, or denial of service.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations: None. The code directly loads pickle files with `allow_pickle=True` without any input validation or sanitization.
- Missing Mitigations:
    - Replace `np.load(file_adj, allow_pickle=True)` with safer alternatives for loading adjacency data. Consider using formats like `.npy` without `allow_pickle=True` if possible, or safer serialization libraries if pickle is necessary.
    - If pickle is unavoidable, implement input validation to sanitize the loaded data and ensure it conforms to the expected structure before deserialization. Explore using `pickle.load` with restricted globals to limit the scope of potential code execution.
    - Implement integrity checks for data files to ensure they haven't been tampered with.
- Preconditions:
    - The application must be configured to load data from a directory accessible to the attacker, or an attacker must find a way to inject a malicious `adjs.pickle` file into the expected data directory before the training script is executed.
    - The `train.py` script must be executed, which triggers the data loading process.
- Source Code Analysis:
    - File: `/code/code/Model/utils.py`
        ```python
        def load_adj(file_adj):
            # file_adj stores a list of [{"num_nodes", "rows", "cols", "weights" (optional)} for i in range(time_step)]
            # return: adj_read: a list of sp.csr_matrix

            adj_d = np.load(file_adj, allow_pickle=True) # [CRITICAL VULNERABILITY] - Loading pickle with allow_pickle=True
            adj_read = []
            for item in adj_d:
                num_nodes = item["num_nodes"]
                indptr = item['indptr']
                indices = item['indices']
                weights = item['weights']
                assert num_nodes == len(indptr) - 1
                adj = sp.csr_matrix((weights, indices, indptr), shape=[num_nodes, num_nodes])
                adj_read.append(adj)
            # return adj_read, num_nodes
            return adj_read
        ```
        The `load_adj` function uses `np.load(file_adj, allow_pickle=True)`, which is vulnerable to pickle deserialization attacks if `file_adj` points to an untrusted pickle file. This function is called within `load_data`.

    - File: `/code/code/Model/utils.py`
        ```python
        def load_data(dataDir):
            files = [dataDir + item for item in ["/adjs.npy", "/feats.npy", "/nodes.npy",
                        "/user.npy", "/query.npy", "/asin.npy", "/query_gt.npy", "/asin_gt.npy", "/kg.npy"]]
            [file_adj, file_feat, file_node, file_user, file_query, file_asin, file_query_gt, file_asin_gt, file_kg] = files
            adj = load_adj(file_adj) # Calls the vulnerable load_adj function
            # ...
        ```
        The `load_data` function calls `load_adj` to load adjacency data, making it vulnerable to pickle deserialization if `adjs.pickle` is compromised.

    - File: `/code/code/train.py`
        ```python
        data = load_data(args.data_dir + args.data_name) # Data loading initiated in train.py
        ```
        The `train.py` script initiates the data loading process by calling `load_data`, which transitively calls the vulnerable `load_adj` function.

- Security Test Case:
    1. **Prepare Malicious Pickle File:** Create a file named `adjs.pickle` with the following Python code to create a malicious payload:
        ```python
        import pickle
        import numpy as np
        import os

        class EvilPickle(object):
            def __reduce__(self):
                return (os.system, ('touch /tmp/evil_rete_vuln.txt',)) # Malicious command

        data_to_pickle = [{"num_nodes": 10, "rows": [], "cols": [], "weights": [], '__reduce__': EvilPickle().__reduce__ }]
        with open('adjs.pickle', 'wb') as f:
            pickle.dump(data_to_pickle, f)
        ```
    2. **Set Up Data Directory:** Create the data directory structure as expected by the script (e.g., `../PreProcess/elec/`) and place the malicious `adjs.pickle` file in the `elec` directory. Ensure other required data files (even dummy files) are present to avoid other loading errors and to ensure the script reaches the vulnerable code.
    3. **Run the Training Script:** Execute the `train.py` script, pointing it to the data directory containing the malicious `adjs.pickle` file.
        ```bash
        python code/train.py --data_name elec --data_dir ../PreProcess/
        ```
    4. **Verify Exploitation:** After the script execution, check if the file `/tmp/evil_rete_vuln.txt` has been created. If the file exists, it confirms that the malicious code embedded in the pickle file was executed, demonstrating the Pickle Deserialization Vulnerability.

- Vulnerability Name: Path Traversal in Data Loading
- Description: The `load_data` function in `/code/code/Model/utils.py` constructs file paths by directly concatenating the `dataDir` argument with filenames. This approach is vulnerable to path traversal attacks. If an attacker can control the `dataDir` argument (e.g., via command-line arguments), they can inject path traversal sequences like `../` to access files outside the intended data directory.
- Impact: Information Disclosure. An attacker could potentially read arbitrary files from the server's filesystem that the Python process has access to. This could include sensitive configuration files, source code, or other data.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations: None. The code performs no validation or sanitization of the `dataDir` input before using it to construct file paths.
- Missing Mitigations:
    - Implement robust input validation for the `dataDir` and `data_name` arguments. Sanitize these inputs to remove or escape path traversal characters.
    - Use secure path manipulation functions (e.g., `os.path.join` and `os.path.abspath` in Python) to construct file paths safely and ensure that all accessed files are within the intended data directory.
    - Restrict file system permissions of the user running the training script to limit the impact of potential path traversal vulnerabilities.
- Preconditions:
    - The attacker needs to be able to control or influence the `data_dir` or `data_name` arguments passed to the `train.py` script. This is typically achievable via command-line arguments when running the script.
    - The `train.py` script must be executed with the attacker-controlled `data_dir` argument.
- Source Code Analysis:
    - File: `/code/code/Model/utils.py`
        ```python
        def load_data(dataDir):
            files = [dataDir + item for item in ["/adjs.npy", "/feats.npy", "/nodes.npy", # [PATH TRAVERSAL VULNERABILITY] - Direct string concatenation for path construction
                        "/user.npy", "/query.npy", "/asin.npy", "/query_gt.npy", "/asin_gt.npy", "/kg.npy"]]
            [file_adj, file_feat, file_node, file_user, file_query, file_asin, file_query_gt, file_asin_gt, file_kg] = files
            adj = load_adj(file_adj)
            feat = load_feat(file_feat)
            node = load_node(file_node)
            # ...
        ```
        The code uses simple string concatenation (`dataDir + item`) to create file paths, which is vulnerable to path traversal if `dataDir` contains malicious sequences.

    - File: `/code/code/train.py`
        ```python
        args = parse_args()
        data = load_data(args.data_dir + args.data_name) # Uses user-provided args.data_dir and args.data_name
        ```
        The `train.py` script takes `data_dir` and `data_name` from command-line arguments and passes them directly to the `load_data` function.

    - File: `/code/code/Model/arg_parser.py`
        ```python
        parser.add_argument('--data_name', nargs='?', default='elec',
                            help='Choose a dataset from {elec, music, book, beauty, book_large}')
        parser.add_argument('--data_dir', nargs='?', default='../PreProcess/',
                            help='Input data path.') # Arguments are taken from command line without sanitization
        ```
        The `arg_parser.py` defines command-line arguments `--data_name` and `--data_dir` without any input validation, allowing users to provide potentially malicious paths.

- Security Test Case:
    1. **Prepare Malicious Data Directory Argument:** Construct a command-line argument for `train.py` that uses path traversal to attempt to access a sensitive file outside the intended data directory, such as `/etc/passwd`.
        ```bash
        python code/train.py --data_name "../../../../../etc" --data_dir .
        ```
        This command attempts to set `data_name` to traverse up several directories and then into `/etc`, while `data_dir` is set to the current directory.
    2. **Run the Training Script:** Execute the `train.py` script with the crafted arguments.
        ```bash
        python code/train.py --data_name "../../../../../etc" --data_dir .
        ```
    3. **Observe Error Messages/Output:** Observe the output and error messages generated by the script. If the script attempts to read files like `./../../../../../etc/adjs.npy`, `./../../../../../etc/feats.npy`, etc., and if error messages indicate "No such file or directory" for paths starting with `/etc/`, it suggests the script is indeed attempting to access files under `/etc` based on the provided `data_name`. While direct reading of `/etc/passwd` might be prevented by file permissions or other checks within the loading functions, the attempt itself validates the path traversal vulnerability. For a more definitive test, one could place a controlled file within a higher directory and verify if it can be read using path traversal in `data_name`.