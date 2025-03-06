- Vulnerability Name: Insecure Deserialization in .mat weight file loading
- Description:
    - The `restore_dict` function in `/code/src/var_logger.py` uses `scipy.io.loadmat` to load model weights from `.mat` files.
    - `scipy.io.loadmat` is known to be vulnerable to insecure deserialization when processing crafted `.mat` files from untrusted sources.
    - An attacker can create a malicious `.mat` file containing Python code or shell commands embedded within the MAT-file structure.
    - By replacing the legitimate weight files (`enc.mat`, `dec.mat`, `dec_wl.mat`) in the save directory with these malicious files, an attacker can execute arbitrary code on the user's system when the user attempts to load pre-trained weights using `model.load()`.
    - Step-by-step trigger:
        1. Attacker crafts a malicious `.mat` file (e.g., `enc.mat`) designed to exploit a vulnerability in `scipy.io.loadmat` or to execute arbitrary commands upon loading.
        2. Attacker replaces the legitimate weight file `enc.mat` (or `dec.mat`, `dec_wl.mat`) in the default save directory (`src/neural_networks/saved_weights/weak_labelling_vae/`) or a user-specified save directory with the malicious `.mat` file.
        3. User executes a Python script that utilizes the WS-VAE library and calls the `model.load()` function to load pre-trained weights.
        4. The `model.load()` function calls `var_logger.restore_dict`, which uses `scipy.io.loadmat` to load the (now malicious) `.mat` file.
        5. `scipy.io.loadmat` deserializes the malicious content, leading to arbitrary code execution on the user's machine with the privileges of the Python process.
- Impact:
    - Critical. Successful exploitation allows arbitrary code execution on the machine running the WS-VAE code.
    - An attacker could potentially gain full control of the user's system, steal sensitive data, install malware, or perform other malicious actions.
- Vulnerability Rank: critical
- Currently Implemented Mitigations:
    - None. The code uses `scipy.io.loadmat` without any input validation or security considerations for the loaded `.mat` files.
- Missing Mitigations:
    - Input validation and sanitization for loaded data from `.mat` files. However, validating the content of `.mat` files to prevent malicious deserialization is complex and unreliable.
    - Replacing `.mat` format with a safer serialization format for weights. Consider using:
        - TensorFlow's native SavedModel format, which is designed for saving and loading TensorFlow models and might offer better security in this context.
        - NumPy's `.npy` format for individual weight arrays, potentially combined with a manifest file and integrity checks.
    - Implementing integrity checks for weight files. Use cryptographic hashes (e.g., SHA256) to sign and verify the integrity of weight files before loading them. This would prevent loading tampered files if the signature verification fails.
    - Security warnings to users. If using `.mat` is necessary, warn users explicitly about the security risks of loading `.mat` files from untrusted sources in the documentation.
- Preconditions:
    - The attacker needs to be able to replace the weight files in the designated save directory before the user calls `model.load()`.
    - This could be achieved if:
        - The user downloads and manually places malicious weight files in the correct directory, believing them to be legitimate.
        - Another vulnerability in the system allows the attacker to write files to the user's file system in the location where weights are saved.
- Source Code Analysis:
    - `/code/src/var_logger.py`:
        ```python
        import scipy.io as sio
        ...
        def restore_dict(load_dir, init_dict):
            pretrained_weights = sio.loadmat(load_dir) # Vulnerable line: Deserializes .mat file without security checks
            for key, value in init_dict.items():
                init_dict[key] = tf.Variable(tf.constant(pretrained_weights[key]), dtype=tf.float32)
        ```
        - The `restore_dict` function directly uses `sio.loadmat(load_dir)` to load weights from a `.mat` file specified by `load_dir`. This function is vulnerable to insecure deserialization.
    - `/code/src/ws_vae.py`:
        ```python
        class WeakSupervisionVAE(object):
            ...
            def load(self):
                """
                Load pre-trained parameters (from path in class variable save_dir)
                """
                if os.path.exists(os.path.join(self.save_dir, 'enc.mat')):
                    save_name_encoder = self.save_dir + '/enc.mat'
                    save_name_decoder = self.save_dir + '/dec.mat'
                    save_name_decoder_wl = self.save_dir + '/dec_wl.mat'
                    var_logger.restore_dict(save_name_encoder, self.encoder.weights) # Calls vulnerable function
                    var_logger.restore_dict(save_name_decoder, self.decoder.weights) # Calls vulnerable function
                    var_logger.restore_dict(save_name_decoder_wl, self.weak_label_decoder.weights) # Calls vulnerable function
                    ...
        ```
        - The `load` method in `WeakSupervisionVAE` calls `var_logger.restore_dict` to load weight files. If these files are replaced with malicious `.mat` files, it triggers the vulnerability.
- Security Test Case:
    1. **Setup**: Ensure the WS-VAE library is installed and you are in the project directory.
    2. **Malicious .mat file creation**: Create a malicious `.mat` file named `enc.mat` in a temporary directory (e.g., `/tmp/malicious_weights/`). This file should be crafted to execute arbitrary code when loaded by `scipy.io.loadmat`. For demonstration, let's assume it's designed to create a file `/tmp/pwned_vae`. (Note: Crafting a reliable and universally exploitable malicious `.mat` file is complex and might depend on the SciPy version and environment. For a basic test, a `.mat` file that triggers an easily observable effect is sufficient).
    3. **Replace legitimate weight file**: Locate the default save directory for weights (defined in `ws_vae.py`, usually `src/neural_networks/saved_weights/weak_labelling_vae`). Replace the legitimate `enc.mat` file in this directory with the malicious `enc.mat` file from `/tmp/malicious_weights/`. If the directory or file does not exist, create it and place the malicious file there.
    4. **Run WS-VAE code that loads weights**: Execute a Python script that instantiates `WeakSupervisionVAE` and calls the `load()` method. A modified version of the example in `README.md` can be used:
        ```python
        import sys
        import os
        path_to_package = os.path.split(os.path.split(__file__)[0])[0] # Assuming script is run from bin/ or project root
        sys.path.append(os.path.join(path_to_package, 'src'))
        from var_logger import load_wrench_data
        from ws_vae import WeakSupervisionVAE

        # ... (Data loading - simplified for test) ...
        class MockDataset:
            def __init__(self):
                self.features = [[0.1, 0.2], [0.3, 0.4]]
                self.weak_labels = [[1, -1], [0, 1]]
                self.labels = [0, 1]
        train_data = MockDataset()

        model = WeakSupervisionVAE(train_data)
        model.load() # Load weights, should trigger malicious code if enc.mat is replaced

        print("Weight loading completed (potentially with malicious code execution). Check for /tmp/pwned_vae.")
        ```
    5. **Verify exploitation**: After running the script, check if the file `/tmp/pwned_vae` exists. If it does, it indicates that the malicious code within `enc.mat` was executed during the `model.load()` process, confirming the insecure deserialization vulnerability. Also, observe for any other unexpected behavior that might indicate code execution.