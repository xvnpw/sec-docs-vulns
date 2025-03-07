## Vulnerability List

- Vulnerability Name: YAML Recipe Configuration Injection

- Description:
    1. The project uses YAML recipes to configure training and fine-tuning jobs.
    2. These recipes define parameters such as `train_dir`, `val_dir`, `exp_dir`, `hf_model_name_or_path`, and others.
    3. Launcher scripts (`run_hf_llama3_8b_seq16k_gpu_p5x16_pretrain.sh`, `run_hf_mistral_7b_seq8k_gpu_p5x32_pretrain.sh`, etc.) use environment variables (TRAIN_DIR, VAL_DIR, EXP_DIR, HF_MODEL_NAME_OR_PATH, etc.) to override parameters defined in the YAML recipes.
    4. An attacker can manipulate these environment variables when launching a training job (e.g., via Slurm submission scripts or EKS commands).
    5. By injecting malicious commands into environment variables that are used within the YAML recipe, an attacker could achieve arbitrary code execution during the training process.
    6. For example, if a recipe parameter is vulnerable to YAML injection and is used in a shell command execution, manipulating environment variables that override this parameter could lead to command injection.

- Impact:
    - Arbitrary code execution within the SageMaker training environment.
    - Data exfiltration by accessing training data, model checkpoints, or logs.
    - Model poisoning by manipulating the training process.
    - Privilege escalation within the training environment.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - None. The project does not implement any input validation or sanitization for environment variables used in recipe configurations.

- Missing Mitigations:
    - Input validation and sanitization for all environment variables that can override recipe parameters.
    - Secure YAML loading practices to prevent YAML injection attacks.
    - Principle of least privilege: Running training jobs with minimal necessary permissions to limit the impact of potential code execution vulnerabilities.

- Preconditions:
    - Attacker needs to be able to influence the environment variables used when launching a training job. This could be achieved by:
        - Modifying the launcher scripts before execution if the attacker has write access to the environment where the scripts are executed.
        - Providing malicious input through external systems that set environment variables for the training environment (less likely for external attacker).
        - In a real-world scenario, if the recipes are used within an application that allows users to specify training parameters via environment variables, then this vulnerability becomes directly exploitable by external users.

- Source Code Analysis:
    1. **File:** `/code/main.py`
    2. The `main` function uses `hydra.main` to load configurations from YAML files and command-line overrides.
    3. Launcher scripts (e.g., `/code/launcher_scripts/llama/run_hf_llama3_8b_seq16k_gpu_p5x16_pretrain.sh`) show how environment variables are used to override recipe parameters:
    ```bash
    TRAIN_DIR="${TRAIN_DIR}"
    VAL_DIR="${VAL_DIR}"
    EXP_DIR="${EXP_DIR}"
    HYDRA_FULL_ERROR=1 python3 ${SAGEMAKER_TRAINING_LAUNCHER_DIR}/main.py \
        recipes=training/llama/hf_llama3_8b_seq16k_gpu_p5x16_pretrain \
        base_results_dir=${SAGEMAKER_TRAINING_LAUNCHER_DIR}/results \
        recipes.run.name="hf-llama3-8b" \
        recipes.exp_manager.exp_dir=$EXP_DIR \
        recipes.model.data.train_dir=$TRAIN_DIR \
        recipes.model.data.val_dir=$VAL_DIR
    ```
    4. The `python3 ${SAGEMAKER_TRAINING_LAUNCHER_DIR}/main.py ...` command in the launcher scripts uses Hydra to load the recipe and override parameters using command-line arguments. These command-line arguments are directly constructed from environment variables like `TRAIN_DIR`, `VAL_DIR`, and `EXP_DIR`.
    5. The YAML recipes themselves (e.g., `/code/recipes_collection/recipes/training/llama/hf_llama3_8b_seq16k_gpu_p5x16_pretrain.yaml`) define parameters that can be overridden.
    6. If a recipe contains a vulnerability (e.g., a parameter used unsafely in shell execution) and an attacker can control the environment variables used by the launcher script, they can inject malicious commands.
    7. **Visualization:**
        ```
        [Attacker Controlled Environment Variables (TRAIN_DIR, EXP_DIR, etc.)] --> [Launcher Script (run_hf_llama3_8b_seq16k_gpu_p5x16_pretrain.sh)] --> [main.py (Hydra)] --> [YAML Recipe (hf_llama3_8b_seq16k_gpu_p5x16_pretrain.yaml)] --> [Training Execution (Potential Code Injection)]
        ```

- Security Test Case:
    1. **Objective:** Prove that an attacker can achieve arbitrary code execution by manipulating the `TRAIN_DIR` environment variable and exploiting a vulnerable parameter in a recipe.
    2. **Preconditions:**
        - Access to an environment where the SageMaker HyperPod recipes can be executed (e.g., a SageMaker HyperPod cluster or a local machine with the project set up).
        - Ability to set environment variables before running a launcher script.
    3. **Steps:**
        - **Identify a vulnerable recipe:** Choose any training recipe (e.g., `recipes_collection/recipes/training/llama/hf_llama3_8b_seq16k_gpu_p5x16_pretrain.yaml`). For simplicity, assume we are targeting `recipes.model.data.train_dir`. Although no direct command execution via `train_dir` is immediately evident in the provided files, the principle is to demonstrate how a manipulated environment variable passed through YAML can be a vulnerability if the recipe were to use it insecurely. For this test case, we will simulate a scenario where `train_dir` is used in an `os.system` command within a hypothetical vulnerable part of the training script that is executed by the recipe.
        - **Craft a malicious `TRAIN_DIR` environment variable:** Set `TRAIN_DIR` to a value containing a malicious command, for example: `"; touch /tmp/pwned; echo"` (This is a simplified example; in a real exploit, a more sophisticated payload would be used).
        - **Run a launcher script:** Execute a launcher script, such as `launcher_scripts/llama/run_hf_llama3_8b_seq16k_gpu_p5x16_pretrain.sh`, ensuring that the malicious `TRAIN_DIR` environment variable is set before execution.
        - **Observe the impact:** After the training job (or the initial setup phase) executes, check for the presence of the `/tmp/pwned` file within the training environment (e.g., by SSHing into the head node if using Slurm or checking logs if using SageMaker Jobs, assuming you can access the container or logs). If the file exists, it confirms arbitrary code execution.

    4. **Expected result:** The test should demonstrate that the malicious command injected through the `TRAIN_DIR` environment variable is executed within the training environment, proving the YAML configuration injection vulnerability. In this simplified test case, the creation of `/tmp/pwned` file would be the indicator of successful code execution.