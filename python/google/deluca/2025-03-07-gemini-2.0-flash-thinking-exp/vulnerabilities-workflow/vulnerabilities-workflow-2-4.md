### Vulnerability 1: Unsafe Deserialization via Pickle in `deluca.core.load`

- Description:
    1. The `deluca.core.load` function in `/code/deluca/core.py` uses `pickle.load` to deserialize Python objects from files.
    2. An attacker can craft a malicious pickled file.
    3. When a user or application using `deluca` calls `deluca.core.load` on this malicious file, `pickle.load` will execute arbitrary code embedded in the file during deserialization.
    4. This can lead to arbitrary code execution on the machine running the `deluca` application.

- Impact:
    - Critical. Arbitrary code execution. An attacker can completely compromise the system running the `deluca` library. They could steal sensitive data, install malware, or pivot to other systems on the network.

- Vulnerability Rank:
    - Critical

- Currently Implemented Mitigations:
    - None. The code directly uses `pickle.load` without any input validation or security considerations.

- Missing Mitigations:
    - **Avoid using `pickle` for deserialization of untrusted data.**  Use safer serialization formats like JSON, MessagePack, or Protocol Buffers if possible, and ensure no code execution is involved in deserialization.
    - **Input validation and sanitization.** If `pickle` must be used (which is strongly discouraged for untrusted inputs), implement rigorous input validation to check the source and integrity of the pickled data. However, even with validation, `pickle` remains inherently risky.
    - **Principle of least privilege.** Ensure that the application using `deluca` and loading potentially pickled files runs with the minimum necessary privileges to limit the impact of successful exploitation.

- Preconditions:
    - An attacker needs to be able to supply a malicious file to be loaded by a `deluca` application using `deluca.core.load`. This could be achieved through various means, such as:
        - Social engineering to trick a user into loading the file.
        - Exploiting another vulnerability in the application that allows file uploads or file path manipulation.
        - If the application processes configuration files or policy data from external sources (e.g., downloaded from the internet or read from a network share), and if these files are loaded using `deluca.core.load`, an attacker could compromise these sources.

- Source Code Analysis:
    1. **File:** `/code/deluca/core.py`
    2. **Function:** `load(path)`
    3. **Code Snippet:**
    ```python
    import pickle
    # ...
    def load(path):
      return pickle.load(open(path, "rb"))
    ```
    4. **Vulnerability Point:** The `pickle.load(open(path, "rb"))` line directly deserializes data from the file specified by `path` using the `pickle` module.
    5. **Attack Vector:** An attacker provides a crafted file at `path`. When `load(path)` is called, `pickle.load` executes malicious code within the file.
    6. **Visualization:**

    ```
    [Attacker] --> Malicious Pickle File --> [System] --> deluca.core.load() --> Arbitrary Code Execution
    ```

- Security Test Case:
    1. **Create a malicious pickle file:**
    ```python
    import pickle
    import os

    class MaliciousClass:
        def __reduce__(self):
            return (os.system, ('touch /tmp/pwned',))

    malicious_obj = MaliciousClass()
    payload = pickle.dumps(malicious_obj)
    with open('malicious.pkl', 'wb') as f:
        f.write(payload)
    ```
    This script creates a file named `malicious.pkl` that, when loaded with `pickle.load`, will execute the command `touch /tmp/pwned`.

    2. **Create a test script to load the malicious file using `deluca.core.load`:**
    ```python
    from deluca.core import load

    file_path = 'malicious.pkl'  # Path to the malicious pickle file
    try:
        loaded_obj = load(file_path)
        print("File loaded (this line might not be reached if exploit is successful before)")
    except Exception as e:
        print(f"Error during loading: {e}")

    if os.path.exists('/tmp/pwned'):
        print("/tmp/pwned file exists - Vulnerability confirmed!")
    else:
        print("/tmp/pwned file does NOT exist - Vulnerability NOT confirmed!")
    ```

    3. **Run the test script.**
    4. **Expected Result:** If the vulnerability exists, the script will create a file named `/tmp/pwned` (or equivalent for Windows if adapted `os.system` command) on the system, and the output will indicate "`/tmp/pwned` file exists - Vulnerability confirmed!". If the vulnerability is mitigated or doesn't exist, the file will not be created, and the output will indicate "`/tmp/pwned` file does NOT exist - Vulnerability NOT confirmed!".

    5. **Cleanup (after testing):** Delete the `malicious.pkl` file and `/tmp/pwned` (if created).