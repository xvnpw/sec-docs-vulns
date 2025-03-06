- vulnerability name: Deserialization of Untrusted Data via `np.load` in Multiple Data Loading Functions
- description:
    1. An attacker crafts a malicious pickle file and renames it to one of the expected data files: `adjs.npy`, `query_gt.npy`, or `asin_gt.npy`. The attacker places this file in the data directory expected by the application (e.g., `../PreProcess/elec/`).
    2. The user runs the `train.py` script, which calls the `load_data` function in `/code/code/Model/utils.py`.
    3. The `load_data` function calls `load_adj` (for `adjs.npy`) and `load_gt` (for `query_gt.npy` and `asin_gt.npy`), both of which use `np.load(file_..., allow_pickle=True)`.
    4. `np.load` deserializes the malicious pickle file, and if the pickle file contains malicious code (e.g., `os.system('malicious_command')`), it will be executed on the server running the training script.
- impact: Arbitrary code execution. An attacker can execute arbitrary Python code on the system running the RETE training script by providing a malicious pickle file as input data. This could lead to data breach, system compromise, or other malicious activities.
- vulnerability rank: critical
- currently implemented mitigations: None. The code uses `allow_pickle=True` in `np.load` for `load_adj` and `load_gt`, which explicitly enables pickle loading and the associated risks.
- missing mitigations:
    - Avoid using pickle for data serialization. Use safer formats like JSON, CSV, or NumPy's native `.npy` format without pickle dependency where possible.
    - If pickle is absolutely necessary, implement strong integrity checks and source verification for the data to be loaded. However, this is generally not a sufficient mitigation for pickle vulnerabilities.
    - Sanitize input file paths (though less relevant in this case).
    - Warn users about the security risks of loading data from untrusted sources, especially pickle files.
- preconditions:
    - The attacker needs to be able to replace one of the data files (`adjs.npy`, `query_gt.npy`, `asin_gt.npy`) in the expected data directory with a malicious pickle file.
    - The `train.py` script must be executed by a user.
- source code analysis:
    1. File: `/code/code/Model/utils.py`
    2. Functions: `load_adj(file_adj)` and `load_gt(file_gt)`
    3. Lines:
        - `load_adj`: `adj_d = np.load(file_adj, allow_pickle=True)`
        - `load_gt`: `gt = np.load(file_gt, allow_pickle = True)`
        - `np.load` is called with `allow_pickle=True` in both functions, enabling pickle loading.
        - These functions are called within `load_data`, which processes files based on command-line arguments `data_dir` and `data_name`.
- security test case:
    1. Create a malicious pickle file named `query_gt.npy` (or `asin_gt.npy` or `adjs.npy`) with the following Python code:
    ```python
    import numpy as np
    import pickle
    import os

    class MaliciousPickle(object):
        def __reduce__(self):
            return (os.system, ('touch /tmp/pwned_gt',)) # Different touch file to distinguish
    malicious_data = [[(1,2)], [(3,4)]] # Example data structure, adjust if needed for gt files
    malicious_data_pickled = pickle.dumps(malicious_data)
    np.save('query_gt.npy', np.frombuffer(malicious_data_pickled, dtype=np.uint8))
    ```
    2. Place this `query_gt.npy` file in the data directory.
    3. Run the `train.py` script.
    4. Check if the file `/tmp/pwned_gt` (or `/tmp/pwned` if testing with `adjs.npy`) is created. If it is, the vulnerability is confirmed.