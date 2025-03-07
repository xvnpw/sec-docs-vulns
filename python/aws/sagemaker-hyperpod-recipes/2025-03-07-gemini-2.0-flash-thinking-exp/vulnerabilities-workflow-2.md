## Combined Vulnerability List

### Vulnerability 1: Command Injection in Test Submission Scripts via `results_dir` Parameter

- **Description:**
    1. An attacker gains access to modify or influence the test submission scripts (e.g., `sagemaker-llama-8b_submission.sh`) or the parameters used by them.
    2. The attacker crafts a malicious `results_dir` string containing shell commands, for example: `"; touch /tmp/pwned; "`.
    3. The attacker executes the modified test submission script.
    4. During the execution of the script, the `{$results_dir}` variable, now containing the malicious payload, is expanded within shell commands, such as in `srun -l bash -c "scontrol show hostnames | sort > {$results_dir}/llama-8b/hostname"` or `srun -l bash {$results_dir}/llama-8b/launch_docker_container.sh`.
    5. The injected shell commands within the `results_dir` are executed, in this example, creating a file `/tmp/pwned`.

- **Impact:**
    - Arbitrary command execution on the head node of the SageMaker HyperPod cluster or the environment where the test submission script is executed.
    - This can lead to:
        - Data exfiltration by redirecting sensitive information to attacker-controlled servers.
        - System compromise by creating backdoor accounts or modifying system files.
        - Lateral movement to other parts of the infrastructure if the test environment is connected to internal networks.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - None. The project does not implement any input sanitization or command injection prevention mechanisms in the test submission scripts.

- **Missing Mitigations:**
    - Input sanitization for the `results_dir` parameter in test submission scripts.
    - Avoid using string interpolation with user-controlled parameters directly in shell commands.
    - Implement secure coding practices, such as parameterized commands or shell escaping, to prevent command injection.
    - Principle of least privilege should be applied to the test execution environment to limit the impact of potential command injection vulnerabilities.

- **Preconditions:**
    - The attacker needs to have the ability to modify the test submission scripts or control the `results_dir` parameter before the script execution. This is a less likely scenario for external attackers against a production system, but more relevant in development or CI/CD environments if those are not properly secured.

- **Source code analysis:**
    - File: `/code/tests/slurm_workflow/slurm_baseline_artifacts/llama-8b/sagemaker-llama-8b_submission.sh`
    - Lines:
      ```bash
      #SBATCH --output={$results_dir}/llama-8b/log-sagemaker-llama-8b_%j.out
      # ...
      # Prepare distributed files
      srun -l bash -c "scontrol show hostnames | sort > {$results_dir}/llama-8b/hostname"

      srun -l bash {$results_dir}/llama-8b/launch_docker_container.sh
      srun -l bash {$results_dir}/llama-8b/docker_exec_script.sh
      ```
    - Visualization:
      ```
      User Input (Malicious results_dir) --> sagemaker-llama-8b_submission.sh --> Shell Command Expansion ({$results_dir} in commands) --> Command Execution (Injected commands executed)
      ```
    - The `{$results_dir}` variable is directly embedded into shell commands executed by `srun -l bash -c` and `srun -l bash`. This allows for command injection if the content of `{$results_dir}` is attacker-controlled. The lack of sanitization on `{$results_dir}` before its use in shell commands creates this vulnerability.

- **Security Test Case:**
    1. Prepare a test environment where you can execute the `sagemaker-llama-8b_submission.sh` script.
    2. Modify the `sagemaker-llama-8b_submission.sh` script or its environment to set the `results_dir` variable to a malicious value, for example: `results_dir='"; touch /tmp/pwned; "'`. For testing purposes, you might directly modify the script to hardcode this malicious value for `results_dir` instead of relying on external input.
    3. Execute the modified `sagemaker-llama-8b_submission.sh` script.
    4. After the script execution, check if the file `/tmp/pwned` exists on the system.
    5. If the file `/tmp/pwned` is created, it confirms that the command injection vulnerability is present, as the injected `touch /tmp/pwned` command was successfully executed.

### Vulnerability 2: YAML Recipe Configuration Injection

- **Description:**
    1. The project uses YAML recipes to configure training and fine-tuning jobs.
    2. These recipes define parameters such as `train_dir`, `val_dir`, `exp_dir`, `hf_model_name_or_path`, and others.
    3. Launcher scripts (`run_hf_llama3_8b_seq16k_gpu_p5x16_pretrain.sh`, `run_hf_mistral_7b_seq8k_gpu_p5x32_pretrain.sh`, etc.) use environment variables (TRAIN_DIR, VAL_DIR, EXP_DIR, HF_MODEL_NAME_OR_PATH, etc.) to override parameters defined in the YAML recipes.
    4. An attacker can manipulate these environment variables when launching a training job (e.g., via Slurm submission scripts or EKS commands).
    5. By injecting malicious commands into environment variables that are used within the YAML recipe, an attacker could achieve arbitrary code execution during the training process.
    6. For example, if a recipe parameter is vulnerable to YAML injection and is used in a shell command execution, manipulating environment variables that override this parameter could lead to command injection.

- **Impact:**
    - Arbitrary code execution within the SageMaker training environment.
    - Data exfiltration by accessing training data, model checkpoints, or logs.
    - Model poisoning by manipulating the training process.
    - Privilege escalation within the training environment.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - None. The project does not implement any input validation or sanitization for environment variables used in recipe configurations.

- **Missing Mitigations:**
    - Input validation and sanitization for all environment variables that can override recipe parameters.
    - Secure YAML loading practices to prevent YAML injection attacks.
    - Principle of least privilege: Running training jobs with minimal necessary permissions to limit the impact of potential code execution vulnerabilities.

- **Preconditions:**
    - Attacker needs to be able to influence the environment variables used when launching a training job. This could be achieved by:
        - Modifying the launcher scripts before execution if the attacker has write access to the environment where the scripts are executed.
        - Providing malicious input through external systems that set environment variables for the training environment (less likely for external attacker).
        - In a real-world scenario, if the recipes are used within an application that allows users to specify training parameters via environment variables, then this vulnerability becomes directly exploitable by external users.

- **Source Code Analysis:**
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

- **Security Test Case:**
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

### Vulnerability 3: Insecure Data Path Handling leading to Model Poisoning and Unauthorized Data Access

- **Description:**
  1. The Amazon SageMaker HyperPod recipes project utilizes YAML recipe files to define training configurations, including paths to training and validation datasets (`train_dir`, `val_dir`).
  2. Launcher scripts, primarily shell scripts, are responsible for reading these recipe files and passing the data directory parameters to the training scripts executed within containers.
  3. The launcher scripts, such as `launcher_scripts/llama/run_hf_llama3_8b_seq16k_gpu_p5x16_pretrain.sh`, directly accept environment variables like `TRAIN_DIR` and `VAL_DIR` to specify data paths and pass them as command-line arguments to `main.py`.
  4. If these recipes or environment variables are not adequately validated or sanitized, a malicious actor could manipulate these paths to point to unauthorized data sources or inject malicious training data. This can lead to model poisoning or unauthorized data access.

- **Impact:**
  - Model Poisoning: Attackers can compromise the integrity of the trained model by substituting legitimate training data with malicious datasets, leading to unpredictable model behavior, biases, or backdoors.
  - Unauthorized Data Access: By manipulating data paths, attackers might gain unintended access to sensitive data residing in locations specified by the altered paths during the training process.
  - Potential AWS Resource Access: If the training process is designed to interact with other AWS resources based on these data paths, manipulation could extend to unauthorized access to other AWS services.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
  - The project incorporates `validations_wrapper.py`, `TypeValidator`, and `ValueValidator` to perform configuration validation. These components are intended to check the types and values of configuration parameters, acting as a preliminary security measure. However, the extent to which these validations specifically address data path sanitization and malicious input prevention is not evident from the provided files.

- **Missing Mitigations:**
  - Robust Input Sanitization and Validation: Implement comprehensive validation checks for data paths from recipes and environment variables to ensure they are legitimate, authorized, and safe. Include path traversal prevention and restrictions on allowed data source locations.
  - Principle of Least Privilege: Configure training containers and scripts to operate with minimal necessary permissions, thereby limiting potential damage from exploitation of vulnerabilities.
  - Security Documentation: Provide clear documentation outlining security best practices for users, specifically concerning the configuration and safeguarding of data paths within recipes and launcher scripts.

- **Preconditions:**
  - To exploit this vulnerability, an attacker needs the ability to:
    - Modify recipe files, which might be possible if the attacker gains access to the project's repository or configuration storage.
    - Control environment variables used by the launcher scripts, which is a more readily achievable precondition for external attackers with access to the execution environment.

- **Source Code Analysis:**
  - File: `/code/launcher_scripts/llama/run_hf_llama3_8b_seq16k_gpu_p5x16_pretrain.sh`:
    ```bash
    TRAIN_DIR="${TRAIN_DIR}" # Location of training dataset
    VAL_DIR="${VAL_DIR}" # Location of validation dataset
    EXP_DIR="${EXP_DIR}" # Location to save experiment info including logging, checkpoints, etc.

    HYDRA_FULL_ERROR=1 python3 ${SAGEMAKER_TRAINING_LAUNCHER_DIR}/main.py \
        recipes=training/llama/hf_llama3_8b_seq16k_gpu_p5x16_pretrain \
        base_results_dir=${SAGEMAKER_TRAINING_LAUNCHER_DIR}/results \
        recipes.run.name="hf-llama3-8b" \
        recipes.exp_manager.exp_dir=$EXP_DIR \
        recipes.model.data.train_dir=$TRAIN_DIR \
        recipes.model.data.val_dir=$VAL_DIR
    ```
    - This script directly passes the values of environment variables `TRAIN_DIR` and `VAL_DIR` to the `main.py` script as command-line arguments, without any explicit sanitization in this script.

  - File: `/code/main.py`:
    - `main.py` uses Hydra to manage configurations, including those potentially derived from recipe files and command-line arguments.
    - While `validations_wrapper.py` suggests input validation is in place, the specifics regarding data path validation and protection against malicious inputs require further investigation to confirm effectiveness.

- **Security Test Case:**
  1. Preconditions:
      - Set up a testing environment capable of running the project's launcher scripts.
      - Ensure you can set environment variables before executing launcher scripts.
  2. Steps:
      - Select a launcher script, for example, `launcher_scripts/llama/run_hf_llama3_8b_seq16k_gpu_p5x16_pretrain.sh`.
      - Set the environment variable `TRAIN_DIR` to a local directory containing a harmless, easily identifiable dataset (e.g., a small text file), simulating a malicious data source for testing without causing harm.
      - Execute the chosen launcher script with the modified `TRAIN_DIR` environment variable.
      - Monitor the training job execution. Verify if the training process utilizes data from the attacker-defined `TRAIN_DIR` instead of the expected legitimate dataset.
      - If feasible, examine the resulting trained model to detect any signs of data poisoning due to the injected malicious data.
  3. Expected Result:
      - Ideally, the system should reject the malicious data path due to validation mechanisms and terminate the training job with an error or warning message.
      - If validation is insufficient, the training process will proceed using the manipulated data, confirming the vulnerability.
      - A successful exploit might be evidenced by a poisoned model, exhibiting altered behavior as a result of training on attacker-controlled data.

### Vulnerability 4: YAML Recipe/Launcher Script Command Injection

- **Description:**
    1. An attacker modifies a recipe YAML file or a launcher script.
    2. The attacker injects malicious code into a configurable parameter within the YAML or script. Examples of such parameters include:
        - `training_cfg.entry_script` in custom script recipes, allowing to specify arbitrary script path.
        - `script_args` in custom script recipes, allowing to inject arbitrary arguments to the entry script.
        - `git.repo_url_or_path`, allowing to point to a malicious git repository.
        - Data directory paths (`train_dir`, `val_dir`) if these are directly used in commands without sanitization.
    3. A user, unknowingly or through social engineering, uses this modified recipe or script to launch a SageMaker HyperPod training job.
    4. During job execution, the launcher script processes the malicious configuration.
    5. The injected malicious code is executed within the SageMaker environment, inheriting the security context and permissions of the training job.

- **Impact:**
    - **High/Critical**: Successful exploitation allows arbitrary code execution within the SageMaker training environment.
    - This could lead to:
        - **Data Exfiltration**: Access and exfiltration of sensitive training data or model artifacts stored in AWS S3 or FSx.
        - **AWS Resource Compromise**: Unauthorized access to and modification of other AWS resources within the user's account, given the elevated privileges SageMaker jobs often have.
        - **Training Job Manipulation**:  Tampering with the training process, injecting backdoors into models, or altering training outcomes.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - None identified in the provided project files. The code relies on users providing trusted recipes and scripts.

- **Missing Mitigations:**
    - **Input Validation and Sanitization**: Implement robust validation and sanitization for all user-provided inputs in recipe YAML files and launcher scripts, especially for parameters that are used in command execution or file path construction. This should include:
        - Validating file paths against an allowlist of expected directories.
        - Sanitizing string inputs to prevent shell command injection (e.g., using shell-escape functions when constructing commands).
        - Validating URLs to ensure they point to trusted repositories.
    - **Principle of Least Privilege**:  Review and minimize the permissions granted to SageMaker training jobs. Restrict access only to the AWS resources strictly necessary for training.
    - **Code Review and Security Audits**: Conduct regular code reviews and security audits of recipe YAML files and launcher scripts, especially when adding new features or integrations.
    - **User Education**: Educate users about the risks of using untrusted or modified recipes and launcher scripts and encourage them to use only official recipes from trusted sources.

- **Preconditions:**
    - An attacker needs to be able to modify or provide a malicious recipe YAML file or launcher script to a user. This could be achieved through:
        - Compromising a system where recipes are stored and accessed.
        - Social engineering to trick a user into using a malicious recipe from an untrusted source.

- **Source Code Analysis:**
    - **Launcher Scripts (e.g., `/code/launcher_scripts/llama/run_hf_llama3_8b_seq8k_gpu_p5x16_pretrain.sh`)**:
        ```bash
        HYDRA_FULL_ERROR=1 python3 ${SAGEMAKER_TRAINING_LAUNCHER_DIR}/main.py \
            recipes=training/llama/hf_llama3_8b_seq16k_gpu_p5x16_pretrain \
            base_results_dir=${SAGEMAKER_TRAINING_LAUNCHER_DIR}/results \
            recipes.run.name="hf-llama3-8b" \
            recipes.exp_manager.exp_dir=$EXP_DIR \
            recipes.model.data.train_dir=$TRAIN_DIR \
            recipes.model.data.val_dir=$VAL_DIR \
        ```
        - The `EXP_DIR`, `TRAIN_DIR`, `VAL_DIR` variables are directly taken from environment variables and used in the `python3 main.py` command. While in this specific example, they are used as arguments to the Python script, if `main.py` or the recipes processed by it were to execute shell commands using these variables without sanitization, it would lead to command injection.
    - **Custom Script Launcher (`/code/launcher_scripts/custom_script/run_allreduce.sh`)**:
        ```bash
        HYDRA_FULL_ERROR=1 python3 ${SAGEMAKER_TRAINING_LAUNCHER_DIR}/main.py \
        --config-path=${SAGEMAKER_TRAINING_LAUNCHER_DIR}/launcher_scripts/custom_script \
        --config-name=config_slurm \
        base_results_dir=${SAGEMAKER_TRAINING_LAUNCHER_DIR}/results \
        training_cfg.entry_script=${SAGEMAKER_TRAINING_LAUNCHER_DIR}/laucher_scripts/custom_script/custom_allreduce.py \
        container_mounts=[${SAGEMAKER_TRAINING_LAUNCHER_DIR}] \
        container=<mycontainer>\
        ```
        - Here, `training_cfg.entry_script` is directly taken from the configuration and used to specify the script to be executed. If an attacker modifies `config_slurm.yaml` to point `training_cfg.entry_script` to a malicious script, it will be executed.
    - **K8s Templates (`/code/launcher/nemo/k8s_templates/training/train-script-gpu.yaml`)**:
        ```yaml
          data:
            train-script.sh: |
              #!/bin/bash
              torchrun $DISTRIBUTED_ARGS ${GIT_CLONE_DIR}{{ $config.scriptPath }} \
              {{- if $config.scriptArgs -}}
              {{ $config.scriptArgs }}
              {{- end }}
        ```
        -  `{{ $config.scriptPath }}` and `{{ $config.scriptArgs }}` from the `values.yaml` are directly used in the `torchrun` command in the Kubernetes pod. This means that if a malicious user can control the `scriptPath` or `scriptArgs` in the recipe used for K8s deployment, they can inject and execute arbitrary commands.

- **Security Test Case:**
    1. **Setup**:
        - Assume access to a SageMaker environment where HyperPod recipes can be executed.
        - Have the project repository cloned and set up locally.
    2. **Craft Malicious Recipe**:
        - Choose a recipe YAML file (e.g., `recipes_collection/recipes/training/llama/hf_llama3_8b_seq8k_gpu_p5x16_pretrain.yaml`).
        - Modify the recipe YAML to include a malicious command. For example, if using a custom script recipe, modify the `training_cfg.entry_script` to point to a script containing malicious code. Alternatively, inject a malicious command into `script_args` that will be passed to a seemingly benign `entry_script`.
        - For example, in `recipes_collection/recipes/training/llama/hf_llama3_8b_seq8k_gpu_p5x16_pretrain.yaml`, if the `exp_manager.exp_dir` was somehow used to execute commands (though not directly in this example, it illustrates the point), an attacker could try to set `exp_manager.exp_dir: "; malicious_command ;"` to attempt injection. A more direct example would be in a custom script recipe, modifying `training_cfg.script_args` to include shell commands.
        - For a more concrete example, if you had a recipe that *did* use a data directory path in a command (which this project may not directly do in a vulnerable way currently, but is a common pattern): modify a recipe and set `model.data.train_dir: "`/bin/touch /tmp/pwned`"`.
    3. **Launch Training Job with Malicious Recipe**:
        - Use the launcher script (e.g., `launcher_scripts/llama/run_hf_llama3_8b_seq8k_gpu_p5x16_pretrain.sh`) but point it to the *modified malicious recipe* instead of the original one.
        - Execute the launcher script in the SageMaker environment.
    4. **Verify Exploitation**:
        - Check the logs of the SageMaker training job.
        - Look for evidence that the injected malicious command was executed. For the `/bin/touch /tmp/pwned` example, check if the file `/tmp/pwned` was created within the training container or environment.
        - Monitor AWS CloudTrail logs for unexpected API calls or resource access that would indicate successful compromise of the security context.

This test case will demonstrate that by modifying the recipe YAML or launcher scripts, an attacker can achieve command injection and arbitrary code execution within the SageMaker HyperPod environment.