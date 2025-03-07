## Combined Vulnerability List

### 1. Hugging Face Token Logging in Log Files

*   **Description:**
    1.  A user logs into Hugging Face using `huggingface-cli login`. This action stores the Hugging Face token in the Hugging Face credentials cache and potentially sets it as an environment variable `HF_TOKEN`.
    2.  An attacker modifies a benchmark script (e.g., `Benchmarks/NVIDIA/LLMBenchmark.py`) to intentionally cause an error during execution. This could involve introducing syntax errors or using invalid function arguments like an incorrect repository name in `snapshot_download`.
    3.  A user, unaware of the malicious modification, executes the benchmark script (e.g., by running `python3 NVIDIA_runner.py llm`).
    4.  The script execution fails due to the introduced error, generating error messages.
    5.  The `Infra/tools.py` module's `check_error` function captures the standard error and standard output of the failed subprocess commands. Error messages or environment details logged during the failure might inadvertently include the Hugging Face token, especially if it is present as an environment variable like `HF_TOKEN`.
    6.  The `write_log` function in `Infra/tools.py` then writes this error output, potentially containing the Hugging Face token, to the `Outputs/log.txt` file.
    7.  An attacker who gains access to the `Outputs/log.txt` file can extract the exposed Hugging Face token.

*   **Impact:**
    *   Exposure of sensitive Hugging Face credentials.
    *   Unauthorized access to private Hugging Face models and resources associated with the victim's Hugging Face account using the compromised token.
    *   Potential for malicious actions depending on token permissions, such as downloading private models, pushing malicious models, or accessing other Hugging Face resources.

*   **Vulnerability Rank:** High

*   **Currently Implemented Mitigations:**
    *   None. The project lacks explicit mechanisms to sanitize logs and prevent credential leakage.

*   **Missing Mitigations:**
    *   **Credential Sanitization in Logging:** Implement sanitization within the `Infra/tools.py`'s `write_log` and `check_error` functions. This should involve automatic detection and removal of potential secrets (like Hugging Face tokens, API keys) from log messages before writing them to the log file, possibly using regular expressions or advanced secret detection techniques.
    *   **Avoid Logging Environment Variables:** Review the codebase to prevent unintentional logging of environment variables, particularly in error messages. If environment logging is necessary for debugging, ensure sensitive variables are filtered out.
    *   **Principle of Least Privilege (Documentation):** Emphasize in documentation and scripts the principle of least privilege for Hugging Face tokens, advising users to grant only necessary permissions and be aware of exposure risks.

*   **Preconditions:**
    *   User has logged into Hugging Face using `huggingface-cli login` on the system executing benchmark scripts.
    *   Attacker can modify benchmark scripts within the repository (e.g., via a merged pull request or compromising a local copy).
    *   User executes the modified benchmark script.

*   **Source Code Analysis:**
    1.  **`Infra/tools.py` - `check_error` function:**
        ```python
        def check_error(results):
            if results.stderr:
                return results.stderr.decode("utf-8")
            return results.stdout.decode("utf-8")
        ```
        This function directly returns decoded standard error or standard output without sanitization, which is then passed to `write_log`.

    2.  **`Infra/tools.py` - `write_log` function:**
        ```python
        def write_log(message: str, filename: str = pwd):
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_entry = f"[{timestamp}]\n {message}\n"

            with open(filename, "a") as file:
                file.write(log_entry)
        ```
        This function writes the provided `message` to the log file without any filtering or sanitization.

    3.  **Benchmark scripts (e.g., `Benchmarks/NVIDIA/LLMBenchmark.py`):**
        ```python
        be2 = subprocess.run(build_engine_command, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        tools.write_log(tools.check_error(be2))
        ```
        Benchmark scripts use `subprocess.run` and log command outputs via `tools.write_log(tools.check_error(be2))`. Errors during command execution, potentially including environment variables like Hugging Face tokens, can be logged to `Outputs/log.txt`.

*   **Security Test Case:**
    1.  **Setup:**
        a. Clone the repository.
        b. Install dependencies.
        c. Log in to Hugging Face using `huggingface-cli login`.
    2.  **Modify Benchmark Script (NVIDIA LLMBenchmark):**
        a. Open `Benchmarks/NVIDIA/LLMBenchmark.py`.
        b. Modify `snapshot_download` in `download_models` to use an invalid `repo_id` (e.g., "invalid/model-repo-name").
        ```python
        def download_models(self):
            for model_name in self.config['models']:
                if self.config['models'][model_name]['use_model']:
                    snapshot_download(repo_id="invalid/model-repo-name", cache_dir=self.dir_path+"/hub") # Malicious modification
        ```
    3.  **Run Modified Benchmark:**
        a. Execute `python3 NVIDIA_runner.py llm`.
    4.  **Analyze Log File:**
        a. Open `Outputs/log.txt`.
        b. Search for the Hugging Face token pattern (e.g., "hf_...").
    5.  **Expected Result:**
        - Hugging Face token (or parts) found in `Outputs/log.txt` within error messages, confirming token logging due to script error.

### 2. Sensitive Information Logging in Output Logs

*   **Description:**
    1.  An attacker modifies a runner script (`NVIDIA_runner.py`, `AMD_runner.py`) or a benchmark script (`Benchmarks/NVIDIA/LLMBenchmark.py`).
    2.  The attacker injects code to execute a command that outputs sensitive information (e.g., environment variables, API keys) to standard output or standard error (e.g., `print(os.environ['AZURE_CLIENT_SECRET'])`).
    3.  The attacker tricks a user into downloading and running this modified script, potentially through social engineering or by hosting it in a look-alike repository.
    4.  When executed, the injected command outputs sensitive information.
    5.  The script captures standard output/error, passing it to `write_log` in `Infra/tools.py`.
    6.  `write_log` appends this output, including sensitive information, to `Outputs/log.txt`.
    7.  Sensitive information is logged in plain text in `Outputs/log.txt`.
    8.  An attacker gaining access to `Outputs/log.txt` can retrieve the logged sensitive information.

*   **Impact:**
    *   **Unauthorized Access:** Exposure of credentials (Azure, Hugging Face API keys) grants unauthorized access to user accounts and resources.
    *   **Data Breach:** Exposure of other sensitive information can lead to data breaches.

*   **Vulnerability Rank:** High

*   **Currently Implemented Mitigations:**
    *   None. No sanitization or filtering is performed on logged messages. `write_log` in `Infra/tools.py` directly logs any provided message. Runner scripts blindly log command outputs.

*   **Missing Mitigations:**
    *   **Secure Logging Practices:**
        *   **Output Sanitization/Filtering:** Modify `write_log` or runner script logging to sanitize command outputs before logging. Implement regex filtering to remove sensitive patterns (API keys, secrets).
        *   **Avoid Logging Sensitive Outputs:** Identify commands potentially outputting sensitive info. Avoid logging their stdout/stderr or selectively log only non-sensitive parts.
        *   **Secure Credential Handling Documentation:** Advise users against storing credentials in environment variables or config files. Recommend secure credential management and avoid echoing credentials during setup.

*   **Preconditions:**
    *   User runs a modified script from an attacker.
    *   Sensitive information (Azure credentials, API keys) is accessible to the script (e.g., environment variables).

*   **Source Code Analysis:**
    *   **`Infra/tools.py`:**
        ```python
        import os
        import datetime
        pwd = os.getcwd() + "/Outputs/log.txt"

        def write_log(message: str, filename: str = pwd):
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_entry = f"[{timestamp}]\n {message}\n"

            with open(filename, "a") as file:
                file.write(log_entry)
        ```
        `write_log` writes messages directly to log files without sanitization.

    *   **`NVIDIA_runner.py` (and `AMD_runner.py`):**
        ```python
        from Infra import tools
        ...
        tools.write_log(tools.check_error(results)) # Logging command output
        ```
        Runner scripts use `tools.check_error` and `tools.write_log` to log command outputs, including stdout and stderr, making them vulnerable to logging sensitive data.

*   **Security Test Case:**
    1.  **Modify `NVIDIA_runner.py`:**
        *   Open `/code/NVIDIA_runner.py`.
        *   In `get_system_specs()`, add code to log a dummy sensitive environment variable:
            ```python
            import os
            sensitive_env_variable = "DUMMY_API_KEY_FOR_TEST"
            if sensitive_env_variable in os.environ:
                sensitive_info = os.environ[sensitive_env_variable]
                print(f"Intentional logging of sensitive information: {sensitive_info}")
            ```
    2.  **Set up environment variable (optional):**
        *   `export DUMMY_API_KEY_FOR_TEST="TEST_API_KEY_VALUE_12345"`
    3.  **Run modified script:**
        *   `python3 NVIDIA_runner.py hbm`
    4.  **Examine output log:**
        *   Open `/code/Outputs/log.txt`.
        *   Search for `Intentional logging of sensitive information:`.
        *   Find the logged sensitive information in `Outputs/log.txt`.

    5.  **Clean up (optional):**
        *   Remove added lines from `NVIDIA_runner.py`.
        *   `unset DUMMY_API_KEY_FOR_TEST`.

    **Expected Result:**  `Outputs/log.txt` contains the intentionally logged sensitive information, confirming the vulnerability.

### 3. Malicious Dependency Installation via Modified `install-dependencies.sh`

*   **Description:**
    - A user clones the repository to benchmark AI workloads.
    - The repository provides `install-dependencies.sh` to simplify dependency installation.
    - An attacker forks the repository.
    - The attacker modifies `install-dependencies.sh` in their fork to include malicious commands (backdoors, data exfiltration, system compromise).
    - The attacker social engineers a user to run the modified `install-dependencies.sh` from the attacker's fork.
    - Executing the compromised script runs malicious commands on the user's system during dependency installation.
    - This compromises the user's benchmarking environment.

*   **Impact:**
    - Complete compromise of the user's environment with user privileges.
    - Unauthorized access to sensitive data (benchmark results, configurations, cloud credentials).
    - Installation of persistent backdoors.
    - Potential lateral movement within the user's infrastructure.

*   **Vulnerability Rank:** High

*   **Currently Implemented Mitigations:**
    - None. No security measures to prevent running modified scripts or verify `install-dependencies.sh` integrity. Relies on user trust and due diligence.

*   **Missing Mitigations:**
    *   **Script Integrity Verification:**
        - **Checksums:** Provide checksums (SHA256) of the official `install-dependencies.sh` in README for manual verification.
        - **Digital Signatures:** Digitally sign `install-dependencies.sh` (complex for public GitHub).
    *   **User Education and Warnings:**
        - Add prominent warnings in README near `install-dependencies.sh` instructions about risks of untrusted scripts and importance of verification.
        - Recommend reviewing scripts before execution.
    *   **Virtual Environment Recommendation:** Explicitly encourage virtual environments in README to isolate dependencies and limit compromise impact.

*   **Preconditions:**
    - Attacker can fork the repository.
    - Attacker can modify `install-dependencies.sh` in their fork.
    - Attacker convinces user to run the modified script (social engineering).
    - User has execution permissions for shell scripts and `pip`.
    - User has `git`, `python3`, and `pip` installed.

*   **Source Code Analysis:**
    - File: `/code/install-dependencies.sh`
        - Bash script (`#!/bin/bash`).
        - `set -euo pipefail` for robustness.
        - `usage()` function for help.
        - Checks for `-h` or `--help`.
        - Detects GPU platform ('AMD' or 'NVIDIA').
        - `pip=${1:-'python3 -m pip'}` allows custom `pip` (minor concern).
        - Virtual environment warning.
        - `clone_repo()` function clones git repos (URLs and commits hardcoded, potential manipulation point but script modification is primary vector).
        - Conditional dependency installation based on platform (`pip install -r requirements_*.txt`, `pip install`). Malicious commands can be injected here or in `requirements_*.txt`.
        - AMD specific cloning and installation of `triton`, `flash-attention` - further injection points.
        - `fio` warning (not security relevant).

*   **Security Test Case:**
    - Step 1: Test environment with `git`, `python3`, `bash`.
    - Step 2: Fork the repository.
    - Step 3: Clone forked repo: `git clone https://github.com/<your-username>/AI-benchmarking-guide.git`.
    - Step 4: `cd AI-benchmarking-guide/code`.
    - Step 5: Modify `install-dependencies.sh`, add `echo "Vulnerable!" >> /tmp/vulnerable.txt` at the beginning.
    - Step 6: `chmod +x install-dependencies.sh`.
    - Step 7: `./install-dependencies.sh`.
    - Step 8: `cat /tmp/vulnerable.txt`.

    - Expected Result: `/tmp/vulnerable.txt` exists and contains "Vulnerable!", confirming command execution from modified script.