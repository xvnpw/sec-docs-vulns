### Vulnerability List:

- Vulnerability Name: YAML Recipe/Launcher Script Command Injection
- Description:
    1. An attacker modifies a recipe YAML file or a launcher script.
    2. The attacker injects malicious code into a configurable parameter within the YAML or script. Examples of such parameters include:
        - `training_cfg.entry_script` in custom script recipes, allowing to specify arbitrary script path.
        - `script_args` in custom script recipes, allowing to inject arbitrary arguments to the entry script.
        - `git.repo_url_or_path`, allowing to point to a malicious git repository.
        - Data directory paths (`train_dir`, `val_dir`) if these are directly used in commands without sanitization.
    3. A user, unknowingly or through social engineering, uses this modified recipe or script to launch a SageMaker HyperPod training job.
    4. During job execution, the launcher script processes the malicious configuration.
    5. The injected malicious code is executed within the SageMaker environment, inheriting the security context and permissions of the training job.
- Impact:
    - **High/Critical**: Successful exploitation allows arbitrary code execution within the SageMaker training environment.
    - This could lead to:
        - **Data Exfiltration**: Access and exfiltration of sensitive training data or model artifacts stored in AWS S3 or FSx.
        - **AWS Resource Compromise**: Unauthorized access to and modification of other AWS resources within the user's account, given the elevated privileges SageMaker jobs often have.
        - **Training Job Manipulation**:  Tampering with the training process, injecting backdoors into models, or altering training outcomes.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None identified in the provided project files. The code relies on users providing trusted recipes and scripts.
- Missing Mitigations:
    - **Input Validation and Sanitization**: Implement robust validation and sanitization for all user-provided inputs in recipe YAML files and launcher scripts, especially for parameters that are used in command execution or file path construction. This should include:
        - Validating file paths against an allowlist of expected directories.
        - Sanitizing string inputs to prevent shell command injection (e.g., using shell-escape functions when constructing commands).
        - Validating URLs to ensure they point to trusted repositories.
    - **Principle of Least Privilege**:  Review and minimize the permissions granted to SageMaker training jobs. Restrict access only to the AWS resources strictly necessary for training.
    - **Code Review and Security Audits**: Conduct regular code reviews and security audits of recipe YAML files and launcher scripts, especially when adding new features or integrations.
    - **User Education**: Educate users about the risks of using untrusted or modified recipes and launcher scripts and encourage them to use only official recipes from trusted sources.
- Preconditions:
    - An attacker needs to be able to modify or provide a malicious recipe YAML file or launcher script to a user. This could be achieved through:
        - Compromising a system where recipes are stored and accessed.
        - Social engineering to trick a user into using a malicious recipe from an untrusted source.
- Source Code Analysis:
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
- Security Test Case:
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