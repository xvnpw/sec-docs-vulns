- Vulnerability Name: Path Traversal in Experiment Name leading to Arbitrary File Write
- Description:
    1. The `run.sh` and `pre.sh` scripts take user-provided arguments, including `--exp_name`.
    2. This `exp_name` argument is used to construct the output directory path for logs and saved models.
    3. Specifically, the output directory is created using the experiment name as part of the path: `${ROOT}/log/${MODEL}_${TYPE}_${EXP}` in `pre.sh` and `${ROOT}/log/${MODEL}_${TYPE}_${EXP}/${TS}` in `run.sh`, where `${EXP}` is derived from `--exp_name`. Similarly for model saving paths in python scripts.
    4. By providing a crafted `--exp_name` containing path traversal sequences like `../../`, an attacker can control the output directory and potentially write files to arbitrary locations outside the intended project directories during training or preprocessing.
    5. For example, setting `--exp_name=../../../../tmp/pwned` in `run.sh` will cause the training logs and saved models to be written to a directory under `/tmp/pwned`, instead of the intended project's `log` and `output` directories.
- Impact:
    - Arbitrary File Write: An attacker can write files to arbitrary locations on the file system where the script is executed, limited by the permissions of the user running the script. This can be used for various malicious purposes, including:
        - Overwriting critical system files, potentially leading to system compromise.
        - Planting malicious scripts or executables in system directories for later execution.
        - Data exfiltration by writing sensitive information to world-readable locations.
        - Denial of Service by filling up disk space in critical partitions.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The project does not implement any sanitization or validation of the `exp_name` argument to prevent path traversal.
- Missing Mitigations:
    - Input Sanitization: Implement input validation and sanitization for the `exp_name` argument in `run.sh` and `pre.sh` to prevent path traversal sequences. This could involve:
        - Whitelisting allowed characters for `exp_name` (e.g., alphanumeric characters, underscores, hyphens).
        - Blacklisting path traversal sequences like `../`, `..\` and absolute paths starting with `/` or `C:\`.
        - Using a function to canonicalize the path and ensure it stays within the intended directory structure.
- Preconditions:
    - The attacker needs to be able to execute the `run.sh` or `pre.sh` scripts and control the command-line arguments, specifically the `--exp_name` argument. This is likely the case if a user is expected to run these scripts for training or preprocessing, and an attacker can influence the user to use a malicious `exp_name`.
- Source Code Analysis:
    1. **Entry Points:** The `run.sh` and `pre.sh` scripts are the entry points for training and preprocessing.
    2. **Argument Parsing:** Both scripts use `getopts` to parse command-line arguments, including `-e) EXP=${OPTARG};;` which assigns the value of `--exp_name` to the variable `EXP`.
    3. **Path Construction in Shell Scripts:** In `pre.sh`:
        ```bash
        log_dir=${ROOT}/log/${MODEL}_${TYPE}_${EXP}
        if [ ! -d ${log_dir}  ];then
          mkdir -p ${log_dir}
        fi
        ```
        In `run.sh`:
        ```bash
        log_dir=${ROOT}/log/${MODEL}_${TYPE}_${EXP}/${TS}
        if [ ! -d ${log_dir}  ];then
          mkdir -p ${log_dir}
        fi
        ```
        `${EXP}` is directly incorporated into the `log_dir` path without any sanitization. `${ROOT}` is defined as `$(dirname $(realpath ${0}))` which is the directory of the script itself and is considered safe.
    4. **Path Construction in Python Scripts:** While not explicitly shown in provided code snippets for model saving paths within python, the vulnerability is evident in shell script path construction for log directories. It is highly probable that similar unsanitized path constructions exist within the python scripts (e.g., in `Run.py` or `CumulativeTrainer.py`) for saving model files, as indicated by the description and the project's purpose of saving models. Examining `CumulativeTrainer.py` shows model saving:
        ```python
        def serialize(self, epoch, output_path, use_multiple_gpu=torch.cuda.is_available()):
            ...
            torch.save(this_model.state_dict(), os.path.join(output_path, '.'.join([str(epoch), 'pkl'])))
        ```
        `output_path` here is `OUTPUT_MODEL_DIR` from `Config.py` which is derived from `OUTPUT_DIR` and ultimately influenced by `exp_name`.
    5. **Vulnerable Path:** The vulnerable path is `${ROOT}/log/${MODEL}_${TYPE}_${EXP}` in shell scripts and likely similar paths in python for model saving, where `${EXP}` is directly derived from the user-controlled `--exp_name` argument.

- Security Test Case:
    1. **Prerequisites:**
        - Access to the project code.
        - Ability to execute `run.sh` script.
    2. **Steps:**
        - Navigate to the `/code/code/IMDB` directory in a terminal.
        - Execute the `run.sh` script with a malicious `exp_name` to trigger the path traversal vulnerability:
          ```bash
          sh run.sh -r train -m IMDB -t tf -e "../../../../tmp/pwned_experiment" -p '--n_epoch=1'
          ```
        - After the script execution completes (or even shortly after it starts), check if a directory and log file have been created in `/tmp/pwned_experiment`. For example, check for the existence of `/tmp/pwned_experiment/log/train.log`.
        - Also, check if model files are saved in an unexpected location, potentially under `/tmp/pwned_experiment/model/`. (Note: Model saving location might require deeper code analysis to pinpoint precisely if it uses the same vulnerable path construction).
    3. **Expected Result:**
        - A new directory and log file should be created under `/tmp/pwned_experiment/log/`, indicating that the path traversal in `exp_name` was successful in redirecting the log output to an attacker-controlled location.
        - If model saving path also uses the vulnerable `exp_name`, model files should also be written to an unexpected location under `/tmp/pwned_experiment/model/`.
    4. **Cleanup:**
        - Remove the created directory and files in `/tmp/pwned_experiment` if the test was successful.