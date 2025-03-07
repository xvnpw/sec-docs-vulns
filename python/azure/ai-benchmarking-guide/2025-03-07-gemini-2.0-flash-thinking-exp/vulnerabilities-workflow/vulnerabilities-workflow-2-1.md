* Vulnerability Name: Hugging Face Token Logging in Log Files
* Description:
    1. A user logs into Hugging Face using `huggingface-cli login` as instructed in the README. This stores the Hugging Face token in the Hugging Face credentials cache, and might also set it as an environment variable `HF_TOKEN` in some contexts depending on the environment and `huggingface-cli` version.
    2. An attacker modifies one of the benchmark scripts (e.g., `Benchmarks/NVIDIA/LLMBenchmark.py`) to intentionally cause an error during script execution. For example, the attacker could modify the `snapshot_download` function call to use an invalid repository name, or introduce a syntax error in the script.
    3. A user, unaware of the malicious modification, executes the benchmark script (e.g., by running `python3 NVIDIA_runner.py llm`).
    4. Due to the introduced error, the Python script execution fails, and error messages are generated.
    5. The `Infra/tools.py` module's `check_error` function is used to log the stderr and stdout of subprocess commands. If the error message or any part of the environment is captured in the standard error output during the failure (which can happen depending on the error and logging configuration of underlying libraries or the shell environment), it might inadvertently include the Hugging Face token, especially if it is present as an environment variable like `HF_TOKEN`.
    6. The `write_log` function in `Infra/tools.py` then writes this error output, potentially containing the Hugging Face token, to the `Outputs/log.txt` file.
    7. An attacker can then access the `Outputs/log.txt` file (if they have access to the system or if the log file is inadvertently exposed) and extract the Hugging Face token.

* Impact:
    - Exposure of sensitive Hugging Face credentials (Hugging Face token).
    - An attacker can use the compromised Hugging Face token to access private Hugging Face models and resources associated with the victim's Hugging Face account.
    - Depending on the permissions associated with the compromised token, the attacker might be able to perform actions such as downloading private models, pushing malicious models, or accessing other Hugging Face resources.

* Vulnerability Rank: Medium
* Currently Implemented Mitigations:
    - None. The project does not explicitly handle or sanitize logs to prevent credential leakage.

* Missing Mitigations:
    - **Credential Sanitization in Logging:** Implement sanitization in the `Infra/tools.py`'s `write_log` and `check_error` functions to automatically detect and remove potential secrets (like Hugging Face tokens, API keys, etc.) from log messages before writing them to the log file. This could involve regular expressions or more sophisticated secret detection techniques.
    - **Avoid Logging Environment Variables:** Review the codebase to ensure that environment variables are not inadvertently logged, especially in error messages. If environment logging is necessary for debugging, ensure sensitive variables are filtered out.
    - **Principle of Least Privilege:**  While not a direct code mitigation, emphasize in documentation and scripts the principle of least privilege for Hugging Face tokens. Users should only grant the necessary permissions to their tokens and be aware of the risks of exposing them.

* Preconditions:
    - User has logged into Hugging Face using `huggingface-cli login` on the system where the benchmark scripts are executed.
    - An attacker has the ability to modify the benchmark scripts within the repository (e.g., through a pull request that gets merged, or by compromising the user's local copy if run locally).
    - The user executes the modified benchmark script.

* Source Code Analysis:
    1. **`Infra/tools.py` - `check_error` function:**
    ```python
    def check_error(results):
        if results.stderr:
            return results.stderr.decode("utf-8")
        return results.stdout.decode("utf-8")
    ```
    This function directly returns the decoded standard error (`results.stderr.decode("utf-8")`) if it exists, or standard output. This output is then passed to `write_log`.
    2. **`Infra/tools.py` - `write_log` function:**
    ```python
    def write_log(message: str, filename: str = pwd):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}]\n {message}\n"

        with open(filename, "a") as file:
            file.write(log_entry)
    ```
    This function takes a `message` string and writes it to the log file. No sanitization or filtering is performed on the `message`.
    3. **Benchmark scripts (e.g., `Benchmarks/NVIDIA/LLMBenchmark.py`):**
    ```python
    be2 = subprocess.run(build_engine_command, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    tools.write_log(tools.check_error(be2))
    ```
    Benchmark scripts use `subprocess.run` to execute commands and then log the output using `tools.write_log(tools.check_error(be2))`. If `build_engine_command` or any other command fails and outputs error messages to stderr that include environment variables (which can happen due to shell configurations or error reporting from underlying libraries), these error messages, potentially containing the Hugging Face token, will be logged to `Outputs/log.txt`.

* Security Test Case:
    1. **Setup:**
        a. Clone the repository to a test machine.
        b. Install dependencies as per the README.
        c. Log in to Hugging Face using `huggingface-cli login` with a valid Hugging Face account and token.
    2. **Modify Benchmark Script (NVIDIA LLMBenchmark):**
        a. Open `Benchmarks/NVIDIA/LLMBenchmark.py`.
        b. In the `download_models` function, modify the `repo_id` in `snapshot_download` to an invalid repository name (e.g., "invalid/model-repo-name").
        ```python
        def download_models(self):
            for model_name in self.config['models']:
                if self.config['models'][model_name]['use_model']:
                    snapshot_download(repo_id="invalid/model-repo-name", cache_dir=self.dir_path+"/hub") # Malicious modification
        ```
    3. **Run Modified Benchmark:**
        a. Execute the LLM benchmark: `python3 NVIDIA_runner.py llm`
    4. **Analyze Log File:**
        a. Open the `Outputs/log.txt` file.
        b. Search for the Hugging Face token. Depending on the error reporting and environment, the token might be present in the error output related to the `snapshot_download` failure or general environment logging during the error. Look for patterns resembling Hugging Face tokens (e.g., "hf_...").
    5. **Expected Result:**
        - The Hugging Face token (or parts of it) is found in the `Outputs/log.txt` file within the error messages. This confirms the vulnerability as the token is being logged due to an error during script execution.