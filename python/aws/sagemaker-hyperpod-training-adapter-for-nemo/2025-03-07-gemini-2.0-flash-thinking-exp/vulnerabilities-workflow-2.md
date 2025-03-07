## Combined Vulnerability Report

This document outlines identified security vulnerabilities within the project. Each vulnerability is detailed with its description, potential impact, severity ranking, current mitigations, missing mitigations, preconditions for exploitation, source code analysis, and a security test case to verify its presence.

### 1. Unsafe YAML Deserialization leading to Arbitrary Code Execution

- **Description:**
    1. The application uses YAML configuration files (e.g., `smp_mixtral_config.yaml`, `smp_llama_config.yaml`) to define model training parameters.
    2. If the library uses `yaml.load` or similar unsafe YAML loading methods to parse these configuration files, it becomes vulnerable to arbitrary code execution.
    3. An attacker can craft a malicious YAML configuration file containing Python code within the YAML structure.
    4. When a user loads and processes this malicious configuration file using the vulnerable YAML loading function, the embedded Python code gets executed.
    5. This can lead to arbitrary code execution on the user's machine with the privileges of the user running the training script.

- **Impact:**
    - Critical: An attacker can achieve arbitrary code execution on the machine running the training process. This allows for complete system compromise, including data theft, malware installation, and further propagation of attacks within the infrastructure.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - None: Based on the provided files, there is no explicit mitigation implemented against unsafe YAML deserialization. The code examples use YAML configuration files but there's no evident security measure in place for loading them safely.

- **Missing Mitigations:**
    - Use safe YAML loading methods: Replace any usage of `yaml.load` with `yaml.safe_load` throughout the codebase to prevent arbitrary code execution during YAML deserialization. This ensures that only standard YAML structures are parsed, and any embedded code is ignored.
    - Input validation: Implement validation and sanitization of configuration file inputs to ensure they conform to expected schemas and do not contain potentially malicious content.

- **Preconditions:**
    1. The user must use the library to load and process a malicious YAML configuration file provided by an attacker.
    2. The library must use an unsafe YAML loading method (like `yaml.load`) to parse the configuration file.

- **Source Code Analysis:**
    - The provided project files do not contain Python code that explicitly loads YAML files. However, the presence of `.yaml` configuration files in the `examples` directory and the usage of `hydra` in the example scripts (e.g., `mixtral_pretrain.py`, `llama_pretrain.py`) suggests that Hydra is used for configuration management.
    - Hydra, by default, uses `PyYAML` library to load YAML configuration files.
    - If the project or Hydra configurations are not explicitly set to use `yaml.safe_load`, it might be using the unsafe `yaml.load` by default, especially if older versions are in use or if default settings were not changed.
    - To confirm this vulnerability, the source code that loads and parses the YAML configuration files needs to be examined. Specifically, check for the usage of `yaml.load` vs `yaml.safe_load`. If `yaml.load` is used, or if the loading method is not explicitly set to `safe_load`, the vulnerability exists.
    - Without access to the source code that performs YAML loading, we must assume the worst-case scenario based on the common practice and the presence of YAML configuration files.

- **Security Test Case:**
    1. Create a malicious YAML configuration file (e.g., `malicious_config.yaml`) with the following content:

    ```yaml
    trainer:
      devices: 1
      num_nodes: 1
      accelerator: gpu
      precision: bf16
      max_steps: 1

    exp_manager:
      exp_dir: /tmp/vuln_test
      name: exploit_test
      create_tensorboard_logger: False
      create_checkpoint_callback: False

    use_smp_model: False
    distributed_backend: nccl

    model:
      model_type: llama_v3
      train_batch_size: 1
      val_batch_size: 1
      use_synthetic_data: True
      viztracer:
        enabled: True
        ranks: [0]
        output_file: "`/tmp/pwned`" # Attempt to create a file to verify code execution
    ```

    2. Modify one of the example training scripts (e.g., `examples/llama/llama_pretrain.py`) to load `malicious_config.yaml` instead of the default configuration. For example, change `@hydra.main(config_path="conf", config_name="smp_llama_config", version_base="1.2")` to `@hydra.main(config_path="conf", config_name="malicious_config", version_base="1.2")` and place `malicious_config.yaml` in the same `conf` directory.
    3. Run the modified training script: `python examples/llama/llama_pretrain.py`.
    4. After running the script, check if a file named `pwned` exists in the `/tmp/` directory. If the file exists, it confirms that the code embedded in the YAML file was executed, demonstrating arbitrary code execution vulnerability.

### 2. Unsecured `pip install` leading to potential malicious package substitution

- **Description:** An attacker could create a malicious Python package with a name similar to `hyperpod-nemo-adapter` and upload it to a public package index like PyPI. If a user, intending to install the legitimate `hyperpod-nemo-adapter` package, makes a typo or is tricked into using the malicious package name, `pip` might install the attacker's package instead. If the attacker's package includes malicious code in its `setup.py` or installed scripts, it could be executed during the installation process on the user's SageMaker HyperPod environment. This is especially risky if the user is running `pip install` with elevated privileges or in an environment where code execution can lead to significant impact.

- **Impact:** Arbitrary code execution on the user's training environment. This could lead to data exfiltration, modification of training jobs, denial of service, or complete compromise of the training environment.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:** No specific mitigations are implemented in the provided project files to prevent package substitution attacks. The `README.md` only provides the standard `pip install .[all]` command, without any security warnings or alternative secure installation methods.

- **Missing Mitigations:**
    - **Package name squatting:** Register the package name `hyperpod-nemo-adapter` on PyPI and other relevant package indices to prevent attackers from using similar names.
    - **Strong documentation with security warnings:** Clearly document the official package name and installation instructions, explicitly warning users about the risks of installing packages from untrusted sources or with similar names. Recommend installing directly from a trusted source (e.g., GitHub repository or AWS Marketplace if applicable) and verifying package integrity.
    - **Secure setup scripts:** Ensure `setup.py` and any other installation scripts are thoroughly reviewed for security vulnerabilities and follow secure coding practices to prevent execution of arbitrary code during installation. For example, avoid dynamic code execution or fetching code from external URLs during setup.
    - **Dependency verification:**  Although not directly related to setup scripts, consider using dependency pinning and hash checking in `requirements.txt` to ensure that dependencies are installed from trusted sources and have not been tampered with. However, this will not prevent initial substitution of the main package itself.
    - **Distribution via trusted channels:** Officially distribute the package through trusted channels like AWS Marketplace or a dedicated AWS repository, guiding users to install from these secure sources rather than relying on public package indices alone.

- **Preconditions:**
    - An attacker successfully creates and deploys a malicious package with a similar name to `hyperpod-nemo-adapter` on a public package index.
    - A user attempts to install `hyperpod-nemo-adapter` using `pip install .[all]` or a similar command, and due to typo, misdirection, or supply chain attack, `pip` resolves and installs the malicious package instead of the legitimate one.
    - The user executes `pip install` in an environment where arbitrary code execution is possible and has significant security implications (e.g., training environment with access to sensitive data or infrastructure).

- **Source Code Analysis:**
    - **File: /code/setup.py:** The `setup.py` file is a standard Python setup script used for packaging and installing Python projects. It uses `setuptools.setup()` which is the entry point for installation. The `parse_requirements()` function reads dependencies from `requirements*.txt` files. If a malicious package is installed instead of the legitimate one, the code within `setup.py` (especially if `install_requires`, `extras_require` or `entry_points` are manipulated) or in the dependencies' setup scripts could be executed during `pip install`. The `entry_points` section defines console scripts, which could be a target for malicious modification.
    - **File: /code/README.md:** The README provides installation instructions using `pip install .[all]`. This instruction, while standard, doesn't include any security warnings about potential package substitution attacks. It highlights `pip install` as the primary installation method, making it a prominent attack vector if users are not cautious.
    - **File: /code/requirements.txt and other requirements_*.txt:** These files list dependencies that will be installed by `pip install .[all]`. While dependency pinning is not analyzed in detail in these files, the general practice of `pip install` from package index without integrity checks opens up the possibility of dependency confusion if a malicious package takes over a dependency name. However, the primary vulnerability is related to substitution of the main package, not its direct dependencies.

- **Security Test Case:**
    1. **Set up attacker environment:** Create a malicious Python package with the same structure as `hyperpod-nemo-adapter` but with a slightly different name (e.g., `hyperpod-nemo-adapter-malicious`) or same name, and include malicious code in `setup.py` (e.g., code that prints a warning and sleeps for 10 seconds, or more harmful code).
    2. **Deploy malicious package:** Upload the malicious package to a public or private PyPI repository (if possible with a slightly different name to avoid direct overwrite, or attempt to perform a dependency confusion attack if same name).
    3. **Victim setup:** On a clean environment mimicking a SageMaker HyperPod setup, prepare to install `hyperpod-nemo-adapter`.
    4. **Attempt malicious install:** Instead of installing the legitimate package, intentionally or unintentionally use `pip install hyperpod-nemo-adapter-malicious .[all]` (or the substituted package name).
    5. **Observe execution:** Monitor the installation process. If the malicious package is installed, observe if the malicious code in `setup.py` is executed during `pip install`.
    6. **Verify vulnerability:** If the malicious code executes successfully during `pip install`, it confirms the vulnerability. For a more concrete test, the malicious code could attempt to write a file to the file system or make a network connection to demonstrate arbitrary code execution.

### 3. Local File Inclusion via Unsanitized Training Data Paths

- **Description:**
  - An attacker can exploit the lack of input validation and sanitization for the `train_dir` and `val_dir` parameters in the `model-config.yaml` configuration file.
  - Step 1: The attacker crafts a malicious `model-config.yaml` file.
  - Step 2: In this malicious configuration, the attacker sets the `data.train_dir` or `data.val_dir` parameters to point to a sensitive file on the server's file system, such as `/etc/passwd` or any other file they wish to access. For example:
    ```yaml
    data:
        train_dir: ["/etc/passwd"]
        val_dir: ["/fsx/datasets/c4/en/hf-tokenized/llama3/val"]
        dataset_type: hf
        use_synthetic_data: False
    ```
  - Step 3: The attacker provides this malicious `model-config.yaml` to the training adapter, either by directly modifying the configuration file used by the application or by influencing the configuration loading process if possible (e.g., through command-line arguments or API calls, assuming external attacker can influence this).
  - Step 4: When the training adapter loads the configuration and processes the data loading stage, it uses the attacker-controlled file path from `train_dir` or `val_dir` to perform file operations (e.g., attempting to read the dataset).
  - Step 5: Due to the absence of path sanitization or validation, the adapter attempts to access and potentially process the file specified by the attacker (e.g., `/etc/passwd`), leading to local file inclusion.

- **Impact:**
  - An attacker can read arbitrary files from the file system where the training adapter is running.
  - This can lead to the disclosure of sensitive information, including configuration files, credentials, source code, or other confidential data accessible to the user running the training process.
  - In certain scenarios, depending on how the file paths are used, it might be possible to escalate the attack beyond reading files, potentially leading to code execution if the included files are processed in a vulnerable manner.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
  - No mitigations are implemented in the provided project files. The configuration files (`*.yaml`) directly use the provided paths without any visible validation or sanitization mechanisms. There is no code in the provided PROJECT FILES that sanitizes or validates `train_dir` or `val_dir` parameters.

- **Missing Mitigations:**
  - Input validation: Implement checks to validate that the `train_dir` and `val_dir` paths are within expected directories (e.g., under `/fsx/datasets` or a designated data directory) and conform to expected formats.
  - Path sanitization: Sanitize the input paths to remove or escape any potentially malicious characters or sequences (e.g., `..`, absolute paths, symlinks) before using them in file operations.
  - Principle of least privilege: Ensure that the user account running the training adapter has the minimum necessary permissions to access only the required data directories and not the entire file system.

- **Preconditions:**
  - The attacker must be able to provide or modify the `model-config.yaml` file used by the training adapter. This could be achieved if the attacker has control over the training job configuration, can submit their own configuration, or if there is an interface that allows users to specify or modify the training configuration, and this interface is accessible to the attacker (even as an external user if the instance is publicly accessible and misconfigured).

- **Source Code Analysis:**
  - Based on the provided project files, there is no source code available to analyze the exact data loading implementation. Assuming a standard implementation, the vulnerability would occur in the Python code that reads the `model-config.yaml` and loads the training dataset.
  - Hypothetical vulnerable code flow:
    ```python
    import yaml
    import os

    def load_config(config_path):
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        return config

    def load_dataset(config):
        train_dirs = config['data']['train_dir'] # Attacker controlled value
        for train_dir in train_dirs:
            # Vulnerable code: Directly using train_dir without validation
            # Example: Assuming dataset files are directly accessed within train_dir
            dataset_files = [f for f in os.listdir(train_dir) if os.path.isfile(os.path.join(train_dir, f))]
            for dataset_file in dataset_files:
                with open(os.path.join(train_dir, dataset_file), 'r') as dataset_f: # Vulnerability: Open arbitrary file
                    # Process dataset_f content
                    pass
    ```
  - Visualization:
    ```
    [model-config.yaml (malicious train_dir)] --> [Load Config] --> (train_dir: "/etc/passwd") --> [Load Dataset Code] --> open("/etc/passwd") --> [File Access: /etc/passwd]
    ```

- **Security Test Case:**
  - Step 1: Prepare a malicious `model-config.yaml` file with the following content, replacing `/tmp/test_passwd` with a path you want to test (e.g., `/etc/passwd` - be cautious when testing with sensitive system files in a real environment, use a safe test file instead like creating `/tmp/test_passwd` with some dummy content):
    ```yaml
    trainer:
      devices: 1
      num_nodes: 1
      accelerator: gpu
      precision: bf16
      max_steps: 1
      log_every_n_steps: 1
      val_check_interval: 0
      limit_val_batches: 0

    exp_manager:
      exp_dir: ???
      name: experiment
      create_tensorboard_logger: False
      create_checkpoint_callback: False
      auto_checkpoint:
        enabled: False
      export_full_model:
        every_n_train_steps: 0
        save_last: False

    use_smp_model: False
    distributed_backend: nccl

    model:
      model_type: llama_v3
      train_batch_size: 1
      val_batch_size: 1
      max_context_width: 8
      max_position_embeddings: 8
      num_hidden_layers: 1
      hidden_size: 8
      num_attention_heads: 1
      intermediate_size: 8
      vocab_size: 32
      do_finetune: False
      data:
        train_dir: ["/tmp/test_passwd"] # Malicious path
        val_dir: ["/fsx/datasets/c4/en/hf-tokenized/llama3/val"]
        dataset_type: hf
        use_synthetic_data: False
      optim:
        name: adamw
        lr: 0.0001
        weight_decay: 0.01
        betas:
          - 0.9
          - 0.95
        sched:
          name: CosineAnnealing
          warmup_steps: 0
          constant_steps: 0
          min_lr: 0.000001
    ```
    Create a dummy file `/tmp/test_passwd` with some content:
    ```bash
    echo "test content for vulnerability check" > /tmp/test_passwd
    ```

  - Step 2: Run the training script (e.g., `examples/llama/llama_pretrain.py`) using the malicious configuration file. Assuming the configuration file is named `malicious_config.yaml`:
    ```bash
    python examples/llama/llama_pretrain.py --config=malicious_config.yaml
    ```
  - Step 3: Observe the logs and error messages. If the application attempts to read or process `/tmp/test_passwd` (or `/etc/passwd` if you tested with that, though highly discouraged), and potentially throws errors related to dataset format or content when trying to process `/tmp/test_passwd` as a dataset, this indicates successful local file inclusion. For example, you might see errors in the logs related to parsing dataset files or incorrect data format, which are different from normal operation when using valid dataset paths.
  - Step 4: (Optional, for more detailed verification): Modify the code temporarily to log the file paths being accessed during dataset loading. This will provide direct evidence that the application is indeed attempting to open the attacker-specified file path. For example, in the hypothetical vulnerable code, add a logging statement before `open(os.path.join(train_dir, dataset_file), 'r')`: `logging.info(f"Attempting to open file: {os.path.join(train_dir, dataset_file)}")`. After running the test case, check the logs for the "Attempting to open file:" message with the malicious path `/tmp/test_passwd`.

This test case, if successful, will demonstrate that the application is vulnerable to local file inclusion due to the insecure handling of file paths from the configuration.