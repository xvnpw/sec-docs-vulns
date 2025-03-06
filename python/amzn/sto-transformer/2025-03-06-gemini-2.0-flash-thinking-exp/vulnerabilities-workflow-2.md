## Combined Vulnerability List

### Vulnerability 1: Path Traversal in Experiment Name leading to Arbitrary File Write

*   #### Vulnerability Name
    Path Traversal in Experiment Name leading to Arbitrary File Write

*   #### Description
    1.  The `run.sh` and `pre.sh` scripts take user-provided arguments, including `--exp_name`.
    2.  This `exp_name` argument is used to construct the output directory path for logs and saved models.
    3.  Specifically, the output directory is created using the experiment name as part of the path: `${ROOT}/log/${MODEL}_${TYPE}_${EXP}` in `pre.sh` and `${ROOT}/log/${MODEL}_${TYPE}_${EXP}/${TS}` in `run.sh`, where `${EXP}` is derived from `--exp_name`. Similarly for model saving paths in python scripts.
    4.  By providing a crafted `--exp_name` containing path traversal sequences like `../../`, an attacker can control the output directory and potentially write files to arbitrary locations outside the intended project directories during training or preprocessing.
    5.  For example, setting `--exp_name=../../../../tmp/pwned` in `run.sh` will cause the training logs and saved models to be written to a directory under `/tmp/pwned`, instead of the intended project's `log` and `output` directories.

*   #### Impact
    -   Arbitrary File Write: An attacker can write files to arbitrary locations on the file system where the script is executed, limited by the permissions of the user running the script. This can be used for various malicious purposes, including:
        -   Overwriting critical system files, potentially leading to system compromise.
        -   Planting malicious scripts or executables in system directories for later execution.
        -   Data exfiltration by writing sensitive information to world-readable locations.
        -   Denial of Service by filling up disk space in critical partitions.

*   #### Vulnerability Rank
    High

*   #### Currently Implemented Mitigations
    None. The project does not implement any sanitization or validation of the `exp_name` argument to prevent path traversal.

*   #### Missing Mitigations
    -   Input Sanitization: Implement input validation and sanitization for the `exp_name` argument in `run.sh` and `pre.sh` to prevent path traversal sequences. This could involve:
        -   Whitelisting allowed characters for `exp_name` (e.g., alphanumeric characters, underscores, hyphens).
        -   Blacklisting path traversal sequences like `../`, `..\` and absolute paths starting with `/` or `C:\`.
        -   Using a function to canonicalize the path and ensure it stays within the intended directory structure.

*   #### Preconditions
    -   The attacker needs to be able to execute the `run.sh` or `pre.sh` scripts and control the command-line arguments, specifically the `--exp_name` argument. This is likely the case if a user is expected to run these scripts for training or preprocessing, and an attacker can influence the user to use a malicious `exp_name`.

*   #### Source Code Analysis
    1.  **Entry Points:** The `run.sh` and `pre.sh` scripts are the entry points for training and preprocessing.
    2.  **Argument Parsing:** Both scripts use `getopts` to parse command-line arguments, including `-e) EXP=${OPTARG};;` which assigns the value of `--exp_name` to the variable `EXP`.
    3.  **Path Construction in Shell Scripts:** In `pre.sh`:
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
    4.  **Path Construction in Python Scripts:** Examining `CumulativeTrainer.py` shows model saving:
        ```python
        def serialize(self, epoch, output_path, use_multiple_gpu=torch.cuda.is_available()):
            ...
            torch.save(this_model.state_dict(), os.path.join(output_path, '.'.join([str(epoch), 'pkl'])))
        ```
        `output_path` here is `OUTPUT_MODEL_DIR` from `Config.py` which is derived from `OUTPUT_DIR` and ultimately influenced by `exp_name`.
    5.  **Vulnerable Path:** The vulnerable path is `${ROOT}/log/${MODEL}_${TYPE}_${EXP}` in shell scripts and likely similar paths in python for model saving, where `${EXP}` is directly derived from the user-controlled `--exp_name` argument.

*   #### Security Test Case
    1.  **Prerequisites:**
        -   Access to the project code.
        -   Ability to execute `run.sh` script.
    2.  **Steps:**
        -   Navigate to the `/code/code/IMDB` directory in a terminal.
        -   Execute the `run.sh` script with a malicious `exp_name` to trigger the path traversal vulnerability:
            ```bash
            sh run.sh -r train -m IMDB -t tf -e "../../../../tmp/pwned_experiment" -p '--n_epoch=1'
            ```
        -   After the script execution completes (or even shortly after it starts), check if a directory and log file have been created in `/tmp/pwned_experiment`. For example, check for the existence of `/tmp/pwned_experiment/log/train.log`.
    3.  **Expected Result:**
        -   A new directory and log file should be created under `/tmp/pwned_experiment/log/`, indicating that the path traversal in `exp_name` was successful in redirecting the log output to an attacker-controlled location.
    4.  **Cleanup:**
        -   Remove the created directory and files in `/tmp/pwned_experiment` if the test was successful.

### Vulnerability 2: Command Injection via Unsanitized `PARAMS` Argument in `run.sh` and `pre.sh`

*   #### Vulnerability Name
    Command Injection via Unsanitized `PARAMS` Argument in `run.sh` and `pre.sh`

*   #### Description
    1.  The `run.sh` and `pre.sh` scripts are designed to execute Python scripts (`Run.py`) for training and preprocessing tasks.
    2.  These scripts use `getopts` to parse command-line arguments, including `-p` which is meant to pass "other parameters" to the Python scripts.
    3.  The value provided through the `-p` argument is stored in the `PARAMS` shell variable.
    4.  This `PARAMS` variable is directly embedded into a string called `hyper_params` without any sanitization.
    5.  The `hyper_params` string is then used as arguments when executing the Python script `Run.py` using `nohup python ${ROOT}/${MODEL}/Run.py ${hyper_params} ...`.
    6.  Due to the lack of sanitization, an attacker can inject arbitrary shell commands by crafting a malicious value for the `-p` argument. For example, including shell command separators like `;`, `&`, or `|` followed by malicious commands in the `-p` argument will lead to their execution on the server.

*   #### Impact
    -   Arbitrary command execution on the server.
    -   An attacker can potentially gain full control of the server by executing malicious commands.
    -   This could lead to data breaches, modification or deletion of data, installation of malware, denial of service, and other security compromises.

*   #### Vulnerability Rank
    Critical

*   #### Currently Implemented Mitigations
    None. The scripts directly and unsafely incorporate user-provided input into shell commands without any form of validation or sanitization.

*   #### Missing Mitigations
    -   Input Sanitization: The scripts should sanitize the `PARAMS` argument to prevent the injection of shell-sensitive characters or commands. This could involve:
        -   Validating the input against an expected format.
        -   Escaping shell-sensitive characters.
        -   Ideally, avoiding the direct use of shell variables to construct commands from user input altogether.
    -   Secure Parameter Passing: Instead of relying on shell command construction, a more secure approach would be to:
        -   Parse command-line arguments directly within the Python scripts (`Run.py`, `train.py`) using libraries like `argparse`.
        -   Pass parameters to the Python scripts as arguments in a controlled and parsed manner, avoiding shell interpretation of these parameters.
        -   Ensure that no system commands are executed within the Python scripts based on these parameters without rigorous validation.

*   #### Preconditions
    -   An attacker must have the ability to execute the `run.sh` or `pre.sh` scripts. This is typically the case for users authorized to train or preprocess models using the provided scripts.

*   #### Source Code Analysis
    **File: `/code/code/run.sh`**
    ```bash
    #!/bin/bash
    ...
    while getopts r:i:m:t:e:p: option
    do
       case "${option}"  in
                    i) GPU_ID=${OPTARG};;
                    r) MODE=${OPTARG};;
                    m) MODEL=${OPTARG};;
                    t) TYPE=${OPTARG};;
                    e) EXP=${OPTARG};;
                    p) PARAMS=${OPTARG};;  # <--- User controlled PARAMS
       esac
    done
    ...
    hyper_params="--mode=${MODE} --model_name=${MODEL} --model_type=${TYPE} --exp_name=${EXP} --job_id=${TS} --n_gpu=1 ${PARAMS} --debug=0" # <--- Unsanitized PARAMS used here
    nohup python ${ROOT}/${MODEL}/Run.py ${hyper_params} >> ${log_dir}/${MODE}.log 2>&1 & # <--- Command execution
    ```

    **File: `/code/code/pre.sh`**
    ```bash
    #!/bin/bash
    ...
    while getopts m:t:e:p: option
    do
       case "${option}"  in
                    m) MODEL=${OPTARG};;
                    t) TYPE=${OPTARG};;
                    e) EXP=${OPTARG};;
                    p) PARAMS=${OPTARG};; # <--- User controlled PARAMS
       esac
    done
    ...
    hyper_params="--mode=pre --model_name=${MODEL} --model_type=${TYPE} --exp_name=${EXP} --job_id=${TS} ${PARAMS} --n_gpu=1 --debug=0" # <--- Unsanitized PARAMS used here
    nohup python ${ROOT}/${MODEL}/Run.py ${hyper_params} >> ${log_dir}/${TS}_pre.log 2>&1 & # <--- Command execution
    ```

    In both `run.sh` and `pre.sh`, the `PARAMS` variable, which is directly derived from user-provided command-line arguments (`-p`), is incorporated into the `hyper_params` string without any sanitization. This `hyper_params` string is then used in the execution of the Python script `Run.py` via `nohup python ...`.  An attacker can inject arbitrary shell commands by crafting a malicious `PARAMS` value, which will be executed by the shell.

*   #### Security Test Case
    1.  **Assume the attacker has access to execute `run.sh`.**
    2.  **The attacker executes the following command:**
        ```bash
        ./code/run.sh -r train -m IMDB -t tf -e default -p '--n_epoch=5; touch /tmp/pwned_command_injection'
        ```
        Here, `--n_epoch=5; touch /tmp/pwned_command_injection` is the malicious payload injected through the `-p` argument.  `touch /tmp/pwned_command_injection` is a simple command to create an empty file named `pwned_command_injection` in the `/tmp` directory, which can be used to verify command execution.
    3.  **Execute the command and wait for it to complete.**
    4.  **Check if the file `/tmp/pwned_command_injection` exists on the server.**
    5.  **If the file `/tmp/pwned_command_injection` exists, it confirms that the `touch /tmp/pwned_command_injection` command injected through the `PARAMS` argument was successfully executed, demonstrating command injection vulnerability.**

    **Expected result:** The file `/tmp/pwned_command_injection` should be created in the `/tmp` directory, indicating successful command injection.