### Vulnerability List

#### 1. Command Injection in `run.sh` and `pre.sh` via `PARAMS` argument

*   **Description:**
    1. The `run.sh` and `pre.sh` scripts are designed to execute Python scripts (`Run.py`) for training and preprocessing tasks.
    2. These scripts use `getopts` to parse command-line arguments, including `-p` which is meant to pass "other parameters" to the Python scripts.
    3. The value provided through the `-p` argument is stored in the `PARAMS` shell variable.
    4. This `PARAMS` variable is directly embedded into a string called `hyper_params` without any sanitization.
    5. The `hyper_params` string is then used as arguments when executing the Python script `Run.py` using `nohup python ${ROOT}/${MODEL}/Run.py ${hyper_params} ...`.
    6. Due to the lack of sanitization, an attacker can inject arbitrary shell commands by crafting a malicious value for the `-p` argument. For example, including shell command separators like `;`, `&`, or `|` followed by malicious commands in the `-p` argument will lead to their execution on the server.

*   **Impact:**
    *   Arbitrary command execution on the server.
    *   An attacker can potentially gain full control of the server by executing malicious commands.
    *   This could lead to data breaches, modification or deletion of data, installation of malware, denial of service, and other security compromises.

*   **Vulnerability Rank:** Critical

*   **Currently Implemented Mitigations:**
    *   None. The scripts directly and unsafely incorporate user-provided input into shell commands without any form of validation or sanitization.

*   **Missing Mitigations:**
    *   **Input Sanitization:** The scripts should sanitize the `PARAMS` argument to prevent the injection of shell-sensitive characters or commands. This could involve:
        *   Validating the input against an expected format.
        *   Escaping shell-sensitive characters.
        *   Ideally, avoiding the direct use of shell variables to construct commands from user input altogether.
    *   **Secure Parameter Passing:** Instead of relying on shell command construction, a more secure approach would be to:
        *   Parse command-line arguments directly within the Python scripts (`Run.py`, `train.py`) using libraries like `argparse`.
        *   Pass parameters to the Python scripts as arguments in a controlled and parsed manner, avoiding shell interpretation of these parameters.
        *   Ensure that no system commands are executed within the Python scripts based on these parameters without rigorous validation.

*   **Preconditions:**
    *   An attacker must have the ability to execute the `run.sh` or `pre.sh` scripts. This is typically the case for users authorized to train or preprocess models using the provided scripts.

*   **Source Code Analysis:**
    *   **File: `/code/code/run.sh`**
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
                        p) PARAMS=${OPTARG};;  # <--- PARAMS argument captured here
           esac
        done
        ...
        hyper_params="--mode=${MODE} --model_name=${MODEL} --model_type=${TYPE} --exp_name=${EXP} --job_id=${TS} --n_gpu=1 ${PARAMS} --debug=0" # <--- PARAMS is directly used in hyper_params
        nohup python ${ROOT}/${MODEL}/Run.py ${hyper_params} >> ${log_dir}/${MODE}.log 2>&1 & # <--- hyper_params is used in system command
        ```
    *   **File: `/code/code/pre.sh`**
        ```bash
        #!/bin/bash
        #!/bin/bash
        ...
        while getopts m:t:e:p: option
        do
           case "${option}"  in
                        m) MODEL=${OPTARG};;
                        t) TYPE=${OPTARG};;
                        e) EXP=${OPTARG};;
                        p) PARAMS=${OPTARG};;  # <--- PARAMS argument captured here
           esac
        done
        ...
        hyper_params="--mode=pre --model_name=${MODEL} --model_type=${TYPE} --exp_name=${EXP} --job_id=${TS} ${PARAMS} --n_gpu=1 --debug=0" # <--- PARAMS is directly used in hyper_params
        nohup python ${ROOT}/${MODEL}/Run.py ${hyper_params} >> ${log_dir}/${TS}_pre.log 2>&1 & # <--- hyper_params is used in system command
        ```
    *   In both scripts, the `-p` argument's value is directly appended to the `hyper_params` string, which is then passed to the `python` command executed via `nohup`. This direct embedding without sanitization creates the command injection vulnerability.

*   **Security Test Case:**
    1.  Assume an attacker has access to execute `run.sh`.
    2.  The attacker crafts a malicious command to inject via the `-p` argument. For example:
        ```bash
        sh run.sh -r train -m IMDB -t tf -e default -p '--n_epoch=5; touch /tmp/pwned_command_injection'
        ```
        In this command, `--n_epoch=5; touch /tmp/pwned_command_injection` is passed as the `-p` argument. The `;` acts as a command separator in bash. `touch /tmp/pwned_command_injection` is a simple command that creates an empty file named `pwned_command_injection` in the `/tmp/` directory.
    3.  Execute the crafted command in a shell environment where the project is set up.
    4.  After execution, check if the file `/tmp/pwned_command_injection` exists.
    5.  If the file `/tmp/pwned_command_injection` is created, it confirms that the injected command `touch /tmp/pwned_command_injection` was executed successfully, demonstrating the command injection vulnerability.

This test case demonstrates that an attacker can inject and execute arbitrary commands on the system by manipulating the `-p` argument in `run.sh` and `pre.sh`.