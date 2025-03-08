## Vulnerability List for mliv Project

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