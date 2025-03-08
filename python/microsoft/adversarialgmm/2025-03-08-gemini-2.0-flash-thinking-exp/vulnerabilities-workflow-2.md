## Combined Vulnerability List

### 1. Arbitrary Code Execution via Unsafe Deserialization in Monte Carlo Config Files

- **Description:**
    1. The `montecarlo` library uses Python config files (e.g., `ivconfig_one_z_one_t_paper_n_300_gamma_6.py`) to define Monte Carlo experiments.
    2. These config files are executed directly by `sweep_mc_from_config.py` and `mc_from_config.py` using `importlib.import_module`.
    3. An attacker could craft a malicious config file that, when imported and executed, performs arbitrary code execution on the system running the Monte Carlo experiments.
    4. This is possible because `importlib.import_module` directly executes the Python code within the config file.

- **Impact:**
    - **Critical**
    - Arbitrary code execution on the machine running the Monte Carlo experiments.
    - An attacker could gain full control of the system, steal sensitive data, or use it as a stepping stone for further attacks.

- **Vulnerability Rank:**
    - **Critical**

- **Currently Implemented Mitigations:**
    - None. The code directly imports and executes Python files.

- **Missing Mitigations:**
    - **Input Validation:** Implement strict validation and sanitization of config files before execution. However, given the nature of Python `importlib`, complete sanitization is complex and might not be reliable.
    - **Sandboxing/Isolation:** Run Monte Carlo experiments in a sandboxed or isolated environment to limit the impact of potential code execution vulnerabilities.
    - **Secure Configuration Loading:** Avoid directly executing config files as code. Instead, consider using a safer configuration format like JSON or YAML, and parse them to load experiment parameters. If Python code execution is necessary, explore safer alternatives to `importlib.import_module` or implement robust input validation and sandboxing.

- **Preconditions:**
    - The attacker needs to be able to provide or modify the `config_file` argument passed to `local_script.sh`, `local_script_linux.sh`, `local_script_osx.sh`, `sweep_mc_from_config.py` or `mc_from_config.py`. In a typical scenario, this could happen if an attacker can influence the experiment execution, for example, by submitting a malicious pull request that modifies the scripts or config files, or if the system running experiments is compromised.

- **Source Code Analysis:**
    - **File: /code/montecarlo/local_script_linux.sh, /code/montecarlo/local_script_osx.sh, /code/montecarlo/local_script.sh:**
    ```bash
    CONFIG=$1
    tmpdir='temp'
    tmpfile="${NODE_ID}_${CONFIG}"
    mkdir -p "${tmpdir}"
    cp ${CONFIG}.py ${tmpdir}/${tmpfile}.py
    sed -i s/__NODEID__/${NODE_ID}/g ${tmpdir}/${tmpfile}.py
    sed -i s/__NNODES__/${N_NODES}/g ${tmpdir}/${tmpfile}.py
    python sweep_mc_from_config.py --config ${tmpdir}.${tmpfile}
    rm ${tmpdir}/${tmpfile}.py
    ```
    - The script takes the config file name as a command-line argument (`$1`).
    - It copies the config file to a temporary directory and modifies it using `sed`.
    - Finally, it executes `sweep_mc_from_config.py` with the modified config file.

    - **File: /code/montecarlo/sweep_mc_from_config.py:**
    ```python
    import sys
    import argparse
    from mcpy.monte_carlo import MonteCarloSweep
    import importlib

    def monte_carlo_main():
        parser = argparse.ArgumentParser(description='Process some integers.')
        parser.add_argument('--config', type=str, help='config file')
        args = parser.parse_args(sys.argv[1:])

        config = importlib.import_module(args.config, __name__) # Vulnerable line
        MonteCarloSweep(config.CONFIG).run()

    if __name__=="__main__":
        monte_carlo_main()
    ```
    - The `sweep_mc_from_config.py` script uses `importlib.import_module(args.config, __name__)` to load the config file specified by the `--config` argument.
    - This directly executes the Python code in the provided config file.

- **Security Test Case:**
    1. Create a malicious config file named `malicious_config.py` with the following content:
    ```python
    import os
    CONFIG = {}
    os.system("touch /tmp/pwned") # Malicious command execution
    ```
    2. Run the Monte Carlo script using the malicious config file:
    ```bash
    chmod +x local_script.sh
    ./local_script.sh malicious_config
    ```
    3. Check if the file `/tmp/pwned` exists. If it exists, it confirms that the code from `malicious_config.py` was executed, demonstrating arbitrary code execution.
    4. For a safer test case that doesn't modify the system, you can try printing environment variables or performing other benign actions within the malicious config file to verify code execution.

### 2. Command Injection via Configuration File Name

- **Description:**
    A command injection vulnerability exists in the `local_script.sh`, `local_script_linux.sh`, and `local_script_osx.sh` scripts. This vulnerability can be triggered when a user executes one of these scripts with a maliciously crafted configuration file name as an argument. The scripts use the provided configuration file name in a `cp` command without proper sanitization. Specifically, the scripts execute the following steps:
    1. The script takes a configuration file name as the first argument, storing it in the `CONFIG` variable.
    2. It creates a temporary directory named `temp`.
    3. It attempts to copy the configuration file using the command `cp ${CONFIG}.py ${tmpdir}/${tmpfile}.py`. Due to the lack of sanitization of the `CONFIG` variable, if a malicious user provides a configuration file name containing shell command substitution (e.g., using backticks `` ` `` or `$(...)`), these commands will be executed during the shell's expansion of the `${CONFIG}` variable in the `cp` command.
    4. The rest of the script execution will proceed with the potentially modified temporary file.

- **Impact:**
    Successful exploitation of this vulnerability allows an attacker to execute arbitrary shell commands on the user's system with the privileges of the user running the script. This can lead to a complete compromise of the user's system, including data theft, malware installation, or denial of service.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    No mitigations are currently implemented in the project to prevent this vulnerability. The scripts directly use the user-supplied configuration file name in a shell command without any sanitization or validation.

- **Missing Mitigations:**
    The project lacks input sanitization and validation for the configuration file name argument passed to the shell scripts. To mitigate this vulnerability, the following mitigations should be implemented:
    - **Input Sanitization:** Sanitize the configuration file name to remove or escape any characters that could be interpreted as shell metacharacters. A safer approach would be to disallow special characters entirely and only allow alphanumeric characters, underscores, and hyphens.
    - **Secure File Handling:** Avoid using shell commands like `cp` to handle file operations where user-controlled input is involved. Use Python's built-in file handling functionalities instead, which do not involve shell expansion.
    - **Input Validation:** Validate that the configuration file name conforms to expected patterns before using it in any shell commands.

- **Preconditions:**
    To trigger this vulnerability, the following preconditions must be met:
    - The user must have the project installed and be able to execute the `local_script.sh`, `local_script_linux.sh`, or `local_script_osx.sh` scripts.
    - The user must be tricked into executing one of these scripts with a maliciously crafted configuration file name as a command-line argument.

- **Source Code Analysis:**
    1. **File:** `/code/montecarlo/local_script.sh` (and `/code/montecarlo/local_script_linux.sh`, `/code/montecarlo/local_script_osx.sh`)
    2. **Vulnerable Line:** `cp ${CONFIG}.py ${tmpdir}/${tmpfile}.py`
    3. **Analysis:**
        - The script takes the first command-line argument and assigns it to the variable `CONFIG`.
        - This `CONFIG` variable is then used directly within the `cp` command without any sanitization.
        - When the shell expands `${CONFIG}.py`, if `CONFIG` contains shell command substitution syntax like `$(command)` or backticks `` `command` ``, the shell will execute the embedded command.
        - For example, if a user executes: `local_script.sh "config_$(touch /tmp/pwned)"`, the shell will interpret `$(touch /tmp/pwned)` as a command to be executed, resulting in the creation of an empty file named `/tmp/pwned` before the `cp` command is executed.

- **Security Test Case:**
    1. **Step 1:** Open a terminal and navigate to the `/code/montecarlo` directory of the project.
    2. **Step 2:** Execute the `local_script.sh` script with a malicious configuration file name designed to inject a command. For example:
    ```bash
    ./local_script.sh "config_$(touch /tmp/mliv_pwned)"
    ```
    3. **Step 3:** After executing the command, check if the file `/tmp/mliv_pwned` has been created. You can use the following command to check:
    ```bash
    ls /tmp/mliv_pwned
    ```
    If the file `/tmp/mliv_pwned` exists, it confirms that the command injection vulnerability is present, and arbitrary commands can be executed via the configuration file name argument.