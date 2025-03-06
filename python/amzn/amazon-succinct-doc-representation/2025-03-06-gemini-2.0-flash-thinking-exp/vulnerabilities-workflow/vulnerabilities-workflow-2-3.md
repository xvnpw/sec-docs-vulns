- Vulnerability Name: Pickle Deserialization Vulnerability in Embedding Loading
  - Description: The `read_embeddings` function in `/code/src/late_interaction_baseline/precompute_embeddings.py` uses `pickle.load` to deserialize embedding vectors from files. If an attacker can control the embedding files (e.g., by providing a malicious `prefix` that points to a writable location, and then somehow injects malicious pickle file), they can execute arbitrary code on the server when the `read_embeddings` function is called.
  - Impact: Arbitrary Code Execution. An attacker can execute arbitrary code on the system running the application, potentially leading to full system compromise, data theft, or further malicious activities.
  - Vulnerability Rank: Critical
  - Currently Implemented Mitigations: None. The code directly uses `pickle.load` without any input validation or security checks on the embedding files.
  - Missing Mitigations:
    - Replace `pickle.load` with a safer serialization format like JSON or `torch.load` with `pickle_module=None` setting to prevent arbitrary code execution during deserialization.
    - Implement integrity checks on the embedding files to ensure they haven't been tampered with. This could involve using cryptographic signatures to verify the authenticity and integrity of the files before loading them.
    - If pickle is absolutely necessary, ensure that the files are loaded from a trusted source and implement strict input validation and sanitization for any parameters that influence the file path.
  - Preconditions:
    - The application must call the `read_embeddings` function.
    - An attacker must be able to either:
        - Control the `prefix` parameter in `read_embeddings` to point to a malicious pickle file they have placed in a writable location.
        - Replace the legitimate embedding files at the expected location with malicious pickle files.
  - Source Code Analysis:
    - Go to `/code/src/late_interaction_baseline/precompute_embeddings.py`.
    - Locate the `read_embeddings` function.
    - Observe that the function opens a file using `get_embeddings_path` based on the provided `embd_type` and `prefix`.
    - Inside the `next_batch` inner function, the code uses `pickle.load(handle)` to deserialize data from the opened file handle.
    - `pickle.load` is known to be vulnerable because it can deserialize arbitrary Python objects, including those that, when constructed, execute system commands or other malicious operations.
    - If the file opened by `read_embeddings` contains malicious pickled data, `pickle.load` will execute this malicious code during deserialization.

    ```python
    def read_embeddings(embd_type: str, prefix: str):
        handle = open(get_embeddings_path(embd_type, prefix), 'rb')
        def next_batch():
            try:
                b = [torch.from_numpy(_) for _ in pickle.load(handle)] # Vulnerable line
                if is_pad:
                    b = torch.nn.functional.pad(b, (0, 0, 0, max_length - b.shape[1]))
            except EOFError:
                handle.close()
                return
            return b
        return SavedBatchesReader(next_batch, lambda: handle.close())
    ```
  - Security Test Case:
    1. Create a malicious pickle file named `malicious_embeddings.pkl`. This file should contain Python code that will be executed when `pickle.load` is called. For example, it could execute `os.system('touch /tmp/pwned')` to create a file in the `/tmp` directory as a proof of concept.
    2. Place this `malicious_embeddings.pkl` file in a location where the application can access it, for example, within the `<CACHED_EMBDS_PATH>` directory, and name it according to the expected naming convention (e.g., if `embd_type` is 'doc' and `prefix` is 'test', name it `<CACHED_EMBDS_PATH>/test_doc_embeddings.pkl`). You might need to adjust the `<CACHED_EMBDS_PATH>` in `src/config.py` to a writable directory for testing purposes.
    3. Modify the code or configuration to call `read_embeddings` with `prefix='test'` and `embd_type='doc'` (or whatever names you used). For example, you might need to run an experiment that uses these embeddings.
    4. Run the application.
    5. Check if the command injected in `malicious_embeddings.pkl` was executed. In this example, check if the file `/tmp/pwned` was created. If it was, the vulnerability is confirmed.

- Vulnerability Name: Path Traversal in Embedding File Path Construction
  - Description: The `get_embeddings_path` function in `/code/src/late_interaction_baseline/precompute_embeddings.py` constructs file paths for embedding files by directly concatenating `CACHED_EMBDS_PATH`, a `prefix` parameter, and a fixed suffix. If the `prefix` is not properly validated, an attacker could supply a malicious prefix containing path traversal sequences (like `../`) to manipulate the resulting file path. This could allow them to read files outside the intended `<CACHED_EMBDS_PATH>` directory, potentially accessing sensitive information.
  - Impact: Arbitrary File Read. An attacker could potentially read sensitive files from the server's file system that the application process has access to, such as configuration files, application code, or other data.
  - Vulnerability Rank: Medium
  - Currently Implemented Mitigations: None. The code directly concatenates the path components without any sanitization or validation of the `prefix`.
  - Missing Mitigations:
    - Implement input validation and sanitization for the `prefix` parameter in `get_embeddings_path`. Sanitize the prefix to remove or escape any path traversal sequences (e.g., `../`, `..\\`).
    - Use secure path manipulation functions provided by the operating system or libraries (like `os.path.join` in Python) to construct file paths safely. `os.path.join` helps to correctly handle path separators and can prevent simple path traversal attempts, but it's not a complete solution against malicious prefixes. More robust sanitization is needed.
    - Consider restricting the possible values of `prefix` to a predefined whitelist or using UUIDs or hashes for file naming instead of user-provided prefixes.
  - Preconditions:
    - The application must call the `get_embeddings_path` function and use the resulting path to read a file.
    - An attacker must be able to control or influence the `prefix` parameter that is passed to `get_embeddings_path`.
  - Source Code Analysis:
    - Go to `/code/src/late_interaction_baseline/precompute_embeddings.py`.
    - Locate the `get_embeddings_path` function.
    - Observe that the function constructs the file path using an f-string by concatenating `CACHED_EMBDS_PATH`, `prefix`, `_`, `embd_type`, and `_embeddings.pkl`.
    - There is no validation or sanitization of the `prefix` before it is used in the path concatenation.
    - If an attacker provides a `prefix` like `"../../../../etc/passwd"`, the resulting path could become `<CACHED_EMBDS_PATH>/../../../../etc/passwd_doc_embeddings.pkl`, effectively traversing up the directory structure and potentially accessing `/etc/passwd` if `<CACHED_EMBDS_PATH>` is configured such that going up four levels reaches the root directory.

    ```python
    def get_embeddings_path(embd_type: str, prefix: str):
        return f"{CACHED_EMBDS_PATH}/{prefix}_{embd_type}_embeddings.pkl" # Path concatenation without sanitization
    ```
  - Security Test Case:
    1. Identify a code path in the application that calls `get_embeddings_path` and allows you to control the `prefix` parameter. This might be through command-line arguments, configuration files, or API calls if the project were exposed as a service. For a local test, you might need to modify the `run_experiment.py` or similar script to accept a malicious prefix.
    2. Set the `prefix` parameter to a path traversal string, such as `"../../../../etc/passwd"` (for Linux-like systems) or a similar path to a known file outside the intended embeddings directory for your testing environment.
    3. Run the application with this malicious `prefix`.
    4. Observe the application's behavior. In a real exploit, if successful, the attacker could read the content of `/etc/passwd` (or the file you targeted). For testing, you might need to modify the code temporarily to print the file path being accessed or check for error messages indicating file access attempts outside the intended directory. If you can confirm that the application attempts to open a file path that includes your path traversal sequence and points to a file outside the intended directory, the vulnerability is confirmed. For example, you might see an error like "FileNotFoundError: [Errno 2] No such file or directory: '<CACHED_EMBDS_PATH>/../../../../etc/passwd_doc_embeddings.pkl'" which indicates the path traversal attempt.