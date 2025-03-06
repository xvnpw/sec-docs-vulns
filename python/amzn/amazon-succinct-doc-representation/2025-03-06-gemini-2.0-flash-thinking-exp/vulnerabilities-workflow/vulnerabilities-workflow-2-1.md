### Vulnerability List

*   **Vulnerability Name:** Deserialization Vulnerability via Pickle Load in Embedding Files

*   **Description:**
    The project uses `pickle.load` to load pre-computed document and query embeddings from files (e.g., in `/code/src/late_interaction_baseline/precompute_embeddings.py` and `/code/src/auto_encoder/ae_modeling_training.py`). If an attacker can replace these pickle files with maliciously crafted ones, they could inject arbitrary Python code that will be executed when the `pickle.load` function is called. This is a standard deserialization vulnerability.

    Step-by-step trigger:
    1.  Attacker gains write access to the file system where the embedding files are stored (e.g., if `ARTIFACTS_PATH` or `CACHED_EMBDS_PATH` points to a user-writable directory or a shared storage with weak permissions).
    2.  Attacker creates a malicious pickle file that, when loaded, executes arbitrary Python code. This can be achieved using standard Python pickle payload generation techniques.
    3.  Attacker replaces one of the legitimate embedding pickle files (e.g., `doc_embeddings.pkl`, `query_embeddings.pkl`, or files specified by `get_embeddings_path` function) with the malicious pickle file.
    4.  When the application runs and attempts to load embeddings using functions like `read_embeddings` in `/code/src/late_interaction_baseline/precompute_embeddings.py` or during training/evaluation processes that rely on these embeddings, the malicious pickle file will be loaded.
    5.  The malicious code embedded in the pickle file gets executed by the Python interpreter.

*   **Impact:**
    *   **Code Execution:** Successful exploitation allows the attacker to execute arbitrary Python code on the server or machine running the re-ranking system. This can lead to complete compromise of the system.
    *   **Information Disclosure:** The attacker could use code execution to access sensitive data, environment variables, API keys, or internal configurations.
    *   **Data Modification/Integrity Breach:** Attacker can modify data, configurations, or even the model itself, leading to system malfunction or serving manipulated search results.
    *   **Lateral Movement:** If the compromised system has network access to other internal systems, the attacker might use it as a pivot point for further attacks.

*   **Vulnerability Rank:** High

*   **Currently Implemented Mitigations:**
    *   **None in Code:** The provided code does not include any explicit mitigations against pickle deserialization vulnerabilities. The code directly uses `pickle.load` without any security checks or input sanitization on the loaded files.
    *   **Implicit Mitigation - File System Permissions (Assumed):** It is implicitly assumed that the directories where embedding files are stored (defined by `ARTIFACTS_PATH` and `CACHED_EMBDS_PATH` in `config.py`) are properly secured with appropriate file system permissions, preventing unauthorized write access from external attackers. However, this is an infrastructure-level mitigation and not a code-level mitigation.

*   **Missing Mitigations:**
    *   **Avoid Deserialization of Untrusted Data:** The most robust mitigation is to avoid using `pickle.load` to load data from potentially untrusted sources. If possible, consider using safer serialization formats like JSON or Protocol Buffers for storing embeddings, especially if there's a risk of file replacement by an attacker.
    *   **Input Validation and Integrity Checks:** If pickle is necessary, implement integrity checks for the loaded files. This could involve:
        *   **Digital Signatures:** Sign the embedding files after generation. Before loading, verify the signature to ensure the file has not been tampered with.
        *   **Checksums/Hashes:** Calculate and store checksums (e.g., SHA256) of the embedding files. Before loading, recalculate the checksum and compare it to the stored value.
    *   **Restrict File System Permissions:** Ensure that the directories where embedding files are stored are properly secured with strict file system permissions, limiting write access only to authorized users and processes. Regularly review and enforce these permissions.
    *   **Sandboxing/Isolation:** Run the embedding loading and re-ranking processes in a sandboxed or isolated environment with limited privileges. This can restrict the impact of code execution if a deserialization vulnerability is exploited.

*   **Preconditions:**
    *   **Write Access to Embedding File Storage:** The attacker needs to gain write access to the directory where the embedding pickle files are stored. This could be through various means, such as exploiting other vulnerabilities in the system, social engineering, or misconfiguration of file system permissions.
    *   **Application Loads Pickle Files:** The re-ranking application must be configured to load embeddings from the file system using `pickle.load`. This is the case in the provided code.

*   **Source Code Analysis:**
    *   **File: `/code/src/late_interaction_baseline/precompute_embeddings.py`**
        ```python
        import pickle
        # ...
        def get_embeddings_path(embd_type: str, prefix: str):
            return f"{CACHED_EMBDS_PATH}/{prefix}_{embd_type}_embeddings.pkl"

        def read_embeddings(embd_type: str, prefix: str):
            handle = open(get_embeddings_path(embd_type, prefix), 'rb') # [highlight] File path constructed using CACHED_EMBDS_PATH
            # ...
            def next_batch():
                try:
                    b = [torch.from_numpy(_) for _ in pickle.load(handle)] # [highlight] pickle.load used to deserialize data from file
                    # ...
                except EOFError:
                    handle.close()
                    return
                return b
            # ...
        ```
        The `read_embeddings` function opens a file using a path constructed with `CACHED_EMBDS_PATH` and then uses `pickle.load` to deserialize data from this file. If an attacker can replace the file at this path with a malicious pickle file, the `pickle.load` call will execute the malicious code.

    *   **File: `/code/src/auto_encoder/ae_modeling_training.py`**
        ```python
        import pickle
        # ...
        def read_doc_embeddings(pkl_file=f"{ARTIFACTS_PATH}/msmarco/doc_embeddings.pkl"): # [highlight] File path constructed using ARTIFACTS_PATH
            dfiter = pd.read_csv(f"{ARTIFACTS_PATH}/msmarco/sample_collection.csv", chunksize=32)
            try:
                with open(pkl_file, "rb") as handle: # [highlight] File opened for reading pickle data
                    for df in dfiter:
                        vectors = pickle.load(handle)  # list of vectors, each of shape (num_words, 768) # [highlight] pickle.load used to deserialize data from file
                        yield list(zip(vectors, df.docid, df.doc))
            except EOFError:  # pickle file ends, simply finish
                pass
        ```
        Similarly, `read_doc_embeddings` function in `ae_modeling_training.py` uses `pickle.load` to load document embeddings from a file path constructed using `ARTIFACTS_PATH`. This is another potential point of exploitation if the pickle file can be replaced.

    *   **Visualization:**

        ```mermaid
        graph LR
            A[Attacker] --> B{File System Write Access}
            B --> C{Replace Embedding File with Malicious Pickle}
            D[Re-ranking Application Start/Run] --> E{read_embeddings/read_doc_embeddings}
            E --> F{pickle.load(Malicious File)}
            F --> G{Code Execution}
            G --> H[System Compromise]

        style B fill:#f9f,stroke:#333,stroke-width:2px
        style C fill:#f9f,stroke:#333,stroke-width:2px
        style F fill:#f9f,stroke:#333,stroke-width:2px
        style G fill:#faa,stroke:#333,stroke-width:2px
        style H fill:#faa,stroke:#333,stroke-width:2px
        ```

*   **Security Test Case:**
    1.  **Setup:**
        *   Identify the location where embedding files are stored based on `config.py` settings (`ARTIFACTS_PATH` or `CACHED_EMBDS_PATH`). For this test case, assume it's a directory named `test_embeddings` within the project directory and modify `config.py` accordingly for testing purposes only.
        *   Create a subdirectory `test_embeddings` in the project root.
        *   Identify one of the pickle files being loaded, for example, assume it's `test_embeddings/dev_top25_kd_128_doc_embeddings.pkl` (based on `get_embeddings_path` usage and `saved_embds_prefix` in `experiments/run_experiment.py`).

    2.  **Create Malicious Pickle File:**
        *   Create a Python script (e.g., `malicious_pickle_gen.py`) to generate a malicious pickle file. This script should contain code to be executed upon deserialization. For example, to create a file named `pwned.txt` in the `/tmp` directory:

            ```python
            import pickle
            import os

            class MaliciousClass:
                def __reduce__(self):
                    return (os.system, ('touch /tmp/pwned.txt',))

            payload = MaliciousClass()
            pickle.dump(payload, open("malicious_embeddings.pkl", "wb"))
            ```

        *   Run `malicious_pickle_gen.py` to create `malicious_embeddings.pkl`.

    3.  **Replace Legitimate File with Malicious File:**
        *   Rename the generated `malicious_embeddings.pkl` to `dev_top25_kd_128_doc_embeddings.pkl` (or the actual name of the file you are targeting).
        *   Replace the legitimate embedding file in the `test_embeddings` directory with this malicious file. For example, copy `malicious_embeddings.pkl` to `test_embeddings/dev_top25_kd_128_doc_embeddings.pkl`.

    4.  **Run the Application:**
        *   Execute a part of the application that loads the embeddings, for example, run the evaluation script or any script that triggers `read_embeddings` or `read_doc_embeddings` to load the replaced pickle file. For instance, run `python -m src.experiments.run_experiment`.

    5.  **Verify Exploitation:**
        *   After running the application, check if the malicious code was executed. In this example, check if the file `/tmp/pwned.txt` was created. If the file exists, it confirms that the malicious pickle file was successfully deserialized and the embedded code was executed, demonstrating the deserialization vulnerability.

    6.  **Cleanup:**
        *   Remove the `/tmp/pwned.txt` file (if created).
        *   Replace the malicious pickle file with the original legitimate embedding file to restore the system to its original state.
        *   Revert any changes made to `config.py` during setup.

This test case demonstrates how an attacker, given write access to the embedding file storage, can exploit the pickle deserialization vulnerability to achieve code execution. Note that the success of this test case depends on the ability to replace the embedding file, highlighting the importance of file system security as a precondition and mitigation consideration.