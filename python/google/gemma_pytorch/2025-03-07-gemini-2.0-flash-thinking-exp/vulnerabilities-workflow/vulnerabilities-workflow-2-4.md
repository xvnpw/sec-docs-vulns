- Vulnerability name: Path Traversal in Model Checkpoint Loading

- Description:
    An attacker can exploit a path traversal vulnerability by manipulating the `--ckpt` parameter in `scripts/run.py` and `scripts/run_xla.py`. This parameter is used to specify the path to the model checkpoint directory. By providing a crafted path that includes path traversal sequences like `../`, an attacker can potentially escape the intended checkpoint directory and access files outside of it when the `load_weights` function is called.

    Steps to trigger the vulnerability:
    1. The attacker executes the `run.py` or `run_xla.py` script.
    2. The attacker provides a malicious path as the value for the `--ckpt` parameter, for example: `--ckpt=/../../../../etc/`.
    3. The script parses the arguments and passes the provided `--ckpt` value directly to the `load_weights` function in `gemma/model.py` or `gemma/model_xla.py`.
    4. Inside the `load_weights` function, the provided path is used in `os.path.join` to construct file paths for loading model weights and index files.
    5. Due to the lack of sanitization, the `os.path.join` function resolves the path traversal sequences, potentially leading to file access outside the intended checkpoint directory.
    6. If the attacker provides a path that points to a sensitive file within the Docker container (e.g., `/etc/passwd`), the `load_weights` function might attempt to open and potentially read this file, although the code is designed to load model weights, it might still expose file existence or parts of the content if error handling is not robust.

- Impact:
    Successful exploitation of this vulnerability allows an attacker to read arbitrary files within the Docker container's file system. This can lead to:
    - Information Disclosure: An attacker could read sensitive files such as configuration files, private keys, or other data stored within the container.
    - Further Exploitation: Access to sensitive information can be used to further compromise the system or gain deeper access.

- Vulnerability rank: High

- Currently implemented mitigations:
    No mitigations are currently implemented in the provided code. The `--ckpt` parameter is taken as input and used directly in file path construction without any validation or sanitization.

- Missing mitigations:
    Input sanitization and validation for the `--ckpt` parameter are missing. Recommended mitigations include:
    - Path Validation: Implement checks to ensure that the provided `--ckpt` path is within an expected directory. This could involve:
        - Resolving the absolute path of the provided input using `os.path.abspath()`.
        - Checking if the resolved absolute path starts with a predefined allowed base directory.
    - Path Normalization: Normalize the input path using `os.path.normpath()` to remove path traversal components like `..`. However, this alone might not be sufficient and should be combined with path validation.
    - Restricting Access: Ensure that the Docker container's file system permissions are configured to minimize the impact of arbitrary file read. However, this is a general security measure and not a direct mitigation for the path traversal vulnerability itself.

- Preconditions:
    - The attacker must have the ability to execute the `run.py` or `run_xla.py` scripts, which is typically achieved by having access to a publicly available instance of the project (e.g., a deployed Docker container running the Gemma inference scripts).
    - The attacker needs to be able to modify or control the command-line arguments passed to these scripts, specifically the `--ckpt` parameter.

- Source code analysis:
    1. **`scripts/run.py` and `scripts/run_xla.py`:**
        - Both scripts use `argparse` to handle command-line arguments.
        - The `--ckpt` argument is defined and its value is directly assigned to the `args.ckpt` variable without any sanitization or validation.
        - This `args.ckpt` value is then passed directly to the `load_weights` function of the `GemmaForCausalLM` class.
        ```python
        # scripts/run.py
        parser = argparse.ArgumentParser()
        parser.add_argument("--ckpt", type=str, required=True)
        # ...
        args = parser.parse_args()
        # ...
        model.load_weights(args.ckpt)
        ```
        ```python
        # scripts/run_xla.py
        parser = argparse.ArgumentParser()
        parser.add_argument("--ckpt", type=str, required=True)
        # ...
        args = parser.parse_args()
        # ...
        model.load_weights(args.ckpt)
        ```
    2. **`gemma/model.py` and `gemma/model_xla.py`:**
        - The `load_weights` function in both `gemma/model.py` and `gemma/model_xla.py` takes the `model_path` (which corresponds to `args.ckpt`) as input.
        - It uses `os.path.isfile` to check if `model_path` is a file, and if not, it assumes it's a directory and uses `os.path.join` to construct paths to `pytorch_model.bin.index.json` and shard files.
        - There is no sanitization or validation of the `model_path` before using it in `os.path.join`.
        ```python
        # gemma/model.py
        def load_weights(self, model_path: str):
            if os.path.isfile(model_path):
                # ... file loading logic ...
            else:
                index_path = os.path.join(model_path, 'pytorch_model.bin.index.json') # Vulnerable path construction
                with open(index_path, "r", encoding="utf-8") as f: # File access using potentially malicious path
                    index = json.load(f)
                shard_files = list(set(index["weight_map"].values()))
                for shard_file in shard_files:
                    shard_path = os.path.join(model_path, shard_file) # Vulnerable path construction
                    state_dict = torch.load(shard_path, map_location="cpu", weights_only=True) # File access using potentially malicious path
                    self.load_state_dict(state_dict, strict=False)
                    # ...
        ```
        The same logic applies to `gemma/model_xla.py`.

    In summary, the vulnerability arises because the code directly uses the user-provided `--ckpt` path in `os.path.join` without any checks to prevent path traversal, allowing attackers to potentially access files outside the intended model checkpoint directory.

- Security test case:
    1. **Prerequisites:**
        - Ensure you have the Docker image built for the Gemma project as described in the README.
        - Run the Docker container in an interactive mode so you can observe the output and potentially examine the container's file system.

    2. **Run `run.py` with a path traversal payload:**
        - Execute the following command within your Docker environment (replace `${DOCKER_URI}` and `${VARIANT}` with appropriate values, and ensure you are in the `/code` directory inside the container):
        ```bash
        docker run -t --rm \
            -v /:/host_root \ # Mount the host root filesystem into the container (for demonstration purposes ONLY, do not do this in production)
            ${DOCKER_URI} \
            python scripts/run.py \
            --ckpt=/host_root/etc/passwd \ # Malicious ckpt path to access /etc/passwd on the host
            --variant="${VARIANT}" \
            --prompt="Test"
        ```
        **Note:** Mounting the host root filesystem (`-v /:/host_root`) is **highly discouraged** in production environments as it significantly increases the security risk. This is done here for demonstration purposes to easily access a known file (`/etc/passwd`) to verify the path traversal. In a real-world scenario, the attacker would be limited to files accessible within the container's filesystem.

    3. **Analyze the output:**
        - Examine the output of the script. If the path traversal is successful, you might see errors related to loading a non-model file as a model checkpoint, or potentially see parts of the `/etc/passwd` file content if the script attempts to process it as a model file.
        - **Expected Outcome:** The script will likely fail to load `/host_root/etc/passwd` as a valid model checkpoint, and you will see an error message. However, the attempt to access `/host_root/etc/passwd` demonstrates the path traversal vulnerability. In a more sophisticated exploit, an attacker might try to access other files within the container that could reveal sensitive information or be used for further attacks.

    4. **Run `run_xla.py` with a path traversal payload:**
        - Repeat step 2 and 3 using `scripts/run_xla.py` instead of `scripts/run.py`:
        ```bash
        docker run -t --rm \
            -v /:/host_root \ # Mount the host root filesystem into the container (for demonstration purposes ONLY, do not do this in production)
            ${DOCKER_URI} \
            python scripts/run_xla.py \
            --ckpt=/host_root/etc/passwd \ # Malicious ckpt path to access /etc/passwd on the host
            --variant="${VARIANT}"
        ```
        - Analyze the output similarly to step 3.

    5. **Expected Result:** Both `run.py` and `run_xla.py` should exhibit the path traversal behavior, attempting to access the file specified in the malicious `--ckpt` path. This confirms the vulnerability.

    **Important Security Note:** The provided test case uses host root mounting for demonstration only.  In a real deployment, an attacker would be restricted to the container's file system. However, the path traversal vulnerability still allows access to any file within the container that the user running the script has permissions to read, which can be a significant security risk.