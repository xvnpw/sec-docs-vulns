- Vulnerability Name: Local File Inclusion via Unsanitized Training Data Paths
- Description:
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
- Impact:
  - An attacker can read arbitrary files from the file system where the training adapter is running.
  - This can lead to the disclosure of sensitive information, including configuration files, credentials, source code, or other confidential data accessible to the user running the training process.
  - In certain scenarios, depending on how the file paths are used, it might be possible to escalate the attack beyond reading files, potentially leading to code execution if the included files are processed in a vulnerable manner.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
  - No mitigations are implemented in the provided project files. The configuration files (`*.yaml`) directly use the provided paths without any visible validation or sanitization mechanisms. There is no code in the provided PROJECT FILES that sanitizes or validates `train_dir` or `val_dir` parameters.
- Missing Mitigations:
  - Input validation: Implement checks to validate that the `train_dir` and `val_dir` paths are within expected directories (e.g., under `/fsx/datasets` or a designated data directory) and conform to expected formats.
  - Path sanitization: Sanitize the input paths to remove or escape any potentially malicious characters or sequences (e.g., `..`, absolute paths, symlinks) before using them in file operations.
  - Principle of least privilege: Ensure that the user account running the training adapter has the minimum necessary permissions to access only the required data directories and not the entire file system.
- Preconditions:
  - The attacker must be able to provide or modify the `model-config.yaml` file used by the training adapter. This could be achieved if the attacker has control over the training job configuration, can submit their own configuration, or if there is an interface that allows users to specify or modify the training configuration, and this interface is accessible to the attacker (even as an external user if the instance is publicly accessible and misconfigured).
- Source Code Analysis:
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
- Security Test Case:
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