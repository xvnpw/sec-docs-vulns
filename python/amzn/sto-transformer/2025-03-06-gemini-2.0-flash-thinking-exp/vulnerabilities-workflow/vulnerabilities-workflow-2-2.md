### Vulnerability List:

*   #### Vulnerability Name: Command Injection via Unsanitized `PARAMS` Argument in `run.sh` and `pre.sh`

    *   Description:
        The `run.sh` and `pre.sh` scripts are entry points for executing Python scripts (`Run.py`). These scripts use `getopts` to parse command-line arguments, including a `-p` argument named `PARAMS`. The value of the `PARAMS` argument is directly appended to the `hyper_params` variable, which is then used to construct a command string executed by `python`.

        **Steps to trigger the vulnerability:**
        1.  The attacker crafts a malicious string that includes shell commands, intending to be passed as the `-p` argument to `run.sh` or `pre.sh`.
        2.  The `run.sh` or `pre.sh` script parses the command-line arguments.
        3.  The script constructs the `hyper_params` string by directly appending the attacker-controlled `PARAMS` value.
        4.  The script executes the Python script `Run.py` using `nohup python ${ROOT}/${MODEL}/Run.py ${hyper_params} >> ... 2>&1 &`.
        5.  Due to the lack of sanitization, the shell interprets the malicious commands injected through the `PARAMS` argument, leading to command injection.

    *   Impact:
        Successful command injection allows an attacker to execute arbitrary shell commands on the server running the training or preprocessing scripts. This could lead to:
        - Data breach: Access to sensitive data, including training datasets, model parameters, and logs.
        - System compromise: Full control over the server, allowing the attacker to install malware, create backdoors, or pivot to other systems.
        - Denial of service (indirect):  Although direct DoS is excluded, an attacker could use command injection to cause resource exhaustion or system instability, indirectly leading to denial of service.

    *   Vulnerability Rank: Critical

    *   Currently Implemented Mitigations:
        None. The code directly uses the user-supplied `PARAMS` argument in a shell command without any sanitization or validation.

    *   Missing Mitigations:
        - Input Sanitization: The `PARAMS` argument should be sanitized to remove or escape any shell- Metacharacters before being used in the command execution.
        - Input Validation: Validate the format and content of the `PARAMS` argument to ensure it conforms to expected values and does not contain malicious commands.
        - Parameterized Execution: Instead of constructing shell commands by string concatenation, use parameterized execution methods if available to prevent injection. In this case, the Python script `Run.py` should directly handle command-line arguments using `argparse` and avoid relying on shell script string manipulation.

    *   Preconditions:
        - The attacker needs to be able to execute the `run.sh` or `pre.sh` scripts with command-line arguments. This is typically possible if the scripts are exposed as part of an application or if the attacker has access to the server's command-line interface.
        - The application must be running in an environment where the shell commands executed by the scripts have sufficient privileges to cause harm (e.g., write access to sensitive files, network access).

    *   Source Code Analysis:
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

        **Visualization:**

        ```
        [Attacker Input: run.sh -p '"; malicious_command ; "']
            --> PARAMS variable in run.sh becomes:  '"; malicious_command ; "'
            --> hyper_params string becomes: "--mode=... --n_gpu=1 '"; malicious_command ; "' --debug=0"
            --> Executed command: nohup python ... Run.py --mode=... --n_gpu=1 '"; malicious_command ; "' --debug=0 >> ...
            --> Shell interprets '"; malicious_command ; "' as a command to be executed.
        ```


    *   Security Test Case:
        **Step-by-step test to prove the vulnerability:**
        1.  Assume the attacker has access to execute `run.sh`.
        2.  The attacker executes the following command:
            ```bash
            ./code/run.sh -r train -m IMDB -t tf -e default -p '--n_epoch=5; touch /tmp/pwned ;'
            ```
            Here, `--n_epoch=5; touch /tmp/pwned ;` is the malicious payload injected through the `-p` argument.  `touch /tmp/pwned` is a simple command to create an empty file named `pwned` in the `/tmp` directory, which can be used to verify command execution.
        3.  Execute the command and wait for it to complete.
        4.  Check if the file `/tmp/pwned` exists on the server.
        5.  If the file `/tmp/pwned` exists, it confirms that the `touch /tmp/pwned` command injected through the `PARAMS` argument was successfully executed, demonstrating command injection vulnerability.

        **Expected result:** The file `/tmp/pwned` should be created in the `/tmp` directory, indicating successful command injection.