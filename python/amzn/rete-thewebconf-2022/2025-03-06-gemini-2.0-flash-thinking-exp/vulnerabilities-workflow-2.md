## Combined Vulnerability List

The following vulnerabilities have been identified in the provided lists.

### 1. Pickle Deserialization Vulnerability

- **Vulnerability Name:** Pickle Deserialization Vulnerability
- **Description:** The `load_adj` function in `/code/code/Model/utils.py` uses `np.load(file_adj, allow_pickle=True)` to load adjacency data from pickle files. This function is called by `load_data` to load `adjs.pickle`. Using `allow_pickle=True` when loading data from untrusted sources is insecure because it allows for arbitrary code execution during deserialization. An attacker can craft a malicious pickle file that executes arbitrary Python code when loaded.
- **Impact:** Remote Code Execution (RCE). Successful exploitation allows an attacker to execute arbitrary Python code on the machine running the training script. This can lead to complete system compromise, data theft, or denial of service.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:** None. The code directly loads pickle files with `allow_pickle=True` without any input validation or sanitization.
- **Missing Mitigations:**
    - Replace `np.load(file_adj, allow_pickle=True)` with safer alternatives for loading adjacency data. Consider using formats like `.npy` without `allow_pickle=True` if possible, or safer serialization libraries if pickle is necessary.
    - If pickle is unavoidable, implement input validation to sanitize the loaded data and ensure it conforms to the expected structure before deserialization. Explore using `pickle.load` with restricted globals to limit the scope of potential code execution.
    - Implement integrity checks for data files to ensure they haven't been tampered with.
- **Preconditions:**
    - The application must be configured to load data from a directory accessible to the attacker, or an attacker must find a way to inject a malicious `adjs.pickle` file into the expected data directory before the training script is executed.
    - The `train.py` script must be executed, which triggers the data loading process.
- **Source Code Analysis:**
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
- **Security Test Case:**
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

### 2. Unverified Dependency Installation in `install.sh`

- **Vulnerability Name:** Unverified Dependency Installation in `install.sh`
- **Description:**
    1. The `install.sh` script, provided in the project, automates the installation process.
    2. As part of this process, the script downloads the PyBind11 library directly from the official GitHub repository using the command `git clone https://github.com/pybind/pybind11.git`.
    3. The script then uses this downloaded copy of PyBind11 to build and install the `para_samplers` package.
    4. If the GitHub repository `https://github.com/pybind/pybind11.git` is compromised at any point (e.g., through a man-in-the-middle attack, DNS spoofing, or GitHub account compromise), the `git clone` command could fetch a malicious version of the PyBind11 library.
    5. This malicious PyBind11 library could contain arbitrary code that gets executed during the `pip install ./para_samplers` step, potentially leading to full system compromise.
    6. An attacker could compromise the build process and inject malicious code into the user's environment.
- **Impact:**
    - Successful exploitation of this vulnerability could allow an attacker to execute arbitrary commands on the user's system.
    - This can lead to a complete compromise of the user's local machine, including data theft, malware installation, and unauthorized access.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    - None. The script directly fetches code from an external source without any verification.
- **Missing Mitigations:**
    - **Dependency Verification**: Implement verification of the downloaded PyBind11 library by pinning a specific known-good commit hash of the PyBind11 repository and verifying it in the script.
    - **Using Package Managers for PyBind11**: Rely on trusted package managers like `conda` or `pip` to install PyBind11 instead of cloning from Git.
- **Preconditions:**
    - The user must execute the provided `install.sh` script.
    - An attacker must have compromised the GitHub repository `https://github.com/pybind/pybind11.git` or be able to perform a man-in-the-middle attack during the `git clone` operation.
- **Source Code Analysis:**
    ```bash
    File: /code/code/install.sh
    Content:
    cd Model/para_samplers/
    rm -rf pybind11
    git clone https://github.com/pybind/pybind11.git  <-- Vulnerable line
    cd ..
    conda install -c anaconda cmake
    conda install -c conda-forge ninja
    pip install pybind11                      <-- Redundant and ineffective mitigation
    cd ..
    pip install ./para_samplers             <-- Build process uses potentially compromised pybind11
    ```
    - The vulnerability lies in the `git clone https://github.com/pybind/pybind11.git` command within the `install.sh` script.
    - This command directly downloads the source code of PyBind11 from GitHub without any integrity checks.
    - The subsequent `pip install ./para_samplers` command then uses this potentially compromised local copy of PyBind11 for building the C++ components.
    - Any malicious code injected into the PyBind11 repository could be executed during the compilation and installation process of `para_samplers`.
- **Security Test Case:**
    1. **Set up a malicious PyBind11 repository**:
        - Create a fork of the official PyBind11 repository on GitHub.
        - In the forked repository, introduce a malicious payload in the `setup.py` or `CMakeLists.txt` file that will execute arbitrary commands when PyBind11 is installed. For example, in `setup.py`, you could add code to execute `os.system('touch /tmp/pwned')` upon installation.
        - Commit and push these changes to your forked repository.
    2. **Modify `install.sh` to use the malicious repository**:
        - In a local copy of the RETE project, modify the `install.sh` script to clone your malicious PyBind11 fork instead of the official one. Change the line to: `git clone <URL_OF_YOUR_MALICIOUS_PYBIND11_FORK> pybind11`.
    3. **Run the modified `install.sh`**:
        - Execute the modified `install.sh` script in a clean environment (e.g., a virtual environment).
    4. **Verify the malicious payload execution**:
        - After the script completes, check if the malicious payload was executed. In the example payload `touch /tmp/pwned`, verify if the file `/tmp/pwned` exists.
        - Successful creation of `/tmp/pwned` (or any other intended malicious action) confirms the vulnerability.