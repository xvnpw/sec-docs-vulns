### Vulnerability List

- Vulnerability Name: Command Injection in `run.sh` and `pre.sh` scripts

- Description:
  The `run.sh` and `pre.sh` scripts are vulnerable to command injection. These scripts use `getopts` to parse command-line arguments, and the `-p` option is intended to pass additional parameters to the `Run.py` script. However, the value provided to the `-p` option is directly appended to the command string executed by `nohup python`, without any sanitization or validation. This allows an attacker to inject arbitrary shell commands by crafting a malicious `-p` argument.

  Steps to trigger vulnerability:
  1. An attacker crafts a malicious command injection payload. For example, they might want to execute `ls -la` on the server.
  2. The attacker executes `run.sh` or `pre.sh` and provides the malicious payload through the `-p` option. For example:
     ```bash
     sh run.sh -r train -m IMDB -t tf -e default -p '--n_epoch=5; ls -la'
     ```
  3. The `run.sh` script constructs the command string by appending the value of `-p` directly into the `hyper_params` variable.
  4. The `nohup python ${ROOT}/${MODEL}/Run.py ${hyper_params} ...` command is executed, which includes the injected command.
  5. The injected command `ls -la` is executed by the shell on the server, in addition to the intended Python script execution.

- Impact:
  Successful command injection can lead to arbitrary code execution on the server where the `run.sh` or `pre.sh` script is executed. An attacker could potentially:
    - Gain unauthorized access to the server and sensitive data.
    - Modify or delete data.
    - Install malware.
    - Use the server as part of a botnet.
    - Cause denial of service (although DoS vulnerabilities are explicitly excluded from this list, the initial access can lead to DoS).

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
  There are no mitigations implemented in the provided code to prevent command injection in `run.sh` and `pre.sh`. The scripts directly pass unsanitized user input to the shell.

- Missing Mitigations:
  To mitigate this vulnerability, the scripts should sanitize or validate the input provided through the `-p` option. Ideally, instead of directly passing parameters as a string, the arguments should be parsed and passed to the Python script in a controlled manner.
    - **Input Sanitization:** Sanitize the `-p` argument to remove or escape shell-sensitive characters before constructing the command. However, this approach is complex and error-prone.
    - **Parameterization:** Instead of constructing a string of parameters, directly pass the parsed arguments to the Python script's argument parser. This would require modifying `run.sh` and `pre.sh` to parse the `-p` option's value and pass each parameter individually.
    - **Avoid Shell Execution:** If possible, avoid using `nohup` and shell redirection directly within the script. Use Python's capabilities to handle logging and background processes if needed, although `nohup` and redirection are likely needed for the intended use case of running training jobs in the background.

- Preconditions:
  - The attacker needs to be able to execute `run.sh` or `pre.sh` with command-line arguments, either directly on the server or by instructing a user with access to the server to execute the command.
  - The scripts must be executed in an environment where the shell interprets and executes commands from the `-p` parameter.

- Source Code Analysis:
  1. **File: `/code/code/run.sh`**
     ```bash
     while getopts r:i:m:t:e:p: option
     do
        case "${option}"  in
                     i) GPU_ID=${OPTARG};;
                     r) MODE=${OPTARG};;
                     m) MODEL=${OPTARG};;
                     t) TYPE=${OPTARG};;
                     e) EXP=${OPTARG};;
                     p) PARAMS=${OPTARG};;  # other parameters
        esac
     done

     hyper_params="--mode=${MODE} --model_name=${MODEL} --model_type=${TYPE} --exp_name=${EXP} --job_id=${TS} --n_gpu=1 ${PARAMS} --debug=0"
     nohup python ${ROOT}/${MODEL}/Run.py ${hyper_params} >> ${log_dir}/${MODE}.log 2>&1 &
     ```
     - The script parses command-line options using `getopts`, including `-p PARAMS`.
     - The value of `PARAMS` is directly incorporated into the `hyper_params` string: `${PARAMS}`.
     - This `hyper_params` string is then used in the `nohup python ... ${hyper_params} ...` command, which is executed by the shell.
     - There is no sanitization of the `PARAMS` variable before it's used in the shell command.

  2. **File: `/code/code/pre.sh`**
     ```bash
     while getopts m:t:e:p: option
     do
        case "${option}"  in
                     m) MODEL=${OPTARG};;
                     t) TYPE=${OPTARG};;
                     e) EXP=${OPTARG};;
                     p) PARAMS=${OPTARG};;  # other parameters
        esac
     done

     hyper_params="--mode=pre --model_name=${MODEL} --model_type=${TYPE} --exp_name=${EXP} --job_id=${TS} ${PARAMS} --n_gpu=1 --debug=0"
     nohup python ${ROOT}/${MODEL}/Run.py ${hyper_params} >> ${log_dir}/${TS}_pre.log 2>&1 &
     ```
     - Similar to `run.sh`, `pre.sh` also parses the `-p PARAMS` option and directly uses it in the shell command without sanitization.

  3. **File: `/code/code/IMDB/Run.py` and `/code/code/CoLA/train.py`**
     - These Python scripts use `argparse` to handle command-line arguments. This part of the code itself is not directly vulnerable to command injection as it correctly parses arguments within the Python environment. However, they receive the potentially malicious arguments constructed by `run.sh` and `pre.sh`.

- Security Test Case:

  1. **Setup:** Assume you have access to the environment where the project is intended to run and can execute `run.sh` or `pre.sh`.
  2. **Vulnerability Test:**
     - Execute the `run.sh` script with a malicious payload in the `-p` argument:
       ```bash
       cd code/code/IMDB/
       sh run.sh -r train -m IMDB -t tf -e default -p '--n_epoch=5; touch /tmp/pwned.txt'
       ```
       This command attempts to create a file named `pwned.txt` in the `/tmp/` directory on the server, in addition to running the training script.
  3. **Verification:**
     - Check if the file `/tmp/pwned.txt` has been created on the server.
       ```bash
       ls -la /tmp/pwned.txt
       ```
     - If the file exists, it confirms that the injected command `touch /tmp/pwned.txt` was executed, proving the command injection vulnerability.
     - Additionally, check the log file generated by `run.sh` (e.g., `code/code/IMDB/log/IMDB_tf_default/<timestamp>/train.log`) to ensure the Python script also ran as intended (though its execution is secondary to confirming the injection).

This test case demonstrates that an attacker can inject and execute arbitrary shell commands by manipulating the `-p` parameter in `run.sh` and `pre.sh`, confirming the command injection vulnerability.