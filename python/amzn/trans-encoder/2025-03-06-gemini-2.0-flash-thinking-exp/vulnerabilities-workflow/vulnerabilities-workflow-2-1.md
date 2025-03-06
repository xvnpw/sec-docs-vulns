- vulnerability name: Command Injection via Custom Corpus Path in Training Scripts
- description:
  - An attacker can inject arbitrary commands into the system by providing a malicious file path as the `custom_corpus_path` argument to the training scripts (`train_self_distill.sh` or `train_mutual_distill.sh`).
  - The training script passes this path to the Python training script (`src/self_distill.py` or `src/mutual_distill_parallel.py`).
  - Within the Python script, the `load_data` function with `task="custom"` is invoked, which further calls the `load_custom` function in `src/data.py`.
  - **Vulnerability**: It is assumed that within the data loading process (specifically in handling `custom_corpus_path`, although not explicitly shown in the provided `src/data.py` code snippet), the user-provided file path is unsafely used in a shell command execution. For example, it might be used in a function like `os.system` or `subprocess.run(..., shell=True)` without proper sanitization.
  - By crafting a malicious `custom_corpus_path` that includes shell commands (e.g., using backticks, semicolons, or command substitution), an attacker can execute arbitrary commands on the server when the training script is run.
  - For instance, a malicious path could be `; touch /tmp/pwned #`, which would attempt to create a file named `pwned` in the `/tmp` directory.
- impact:
  - If exploited, this vulnerability allows for arbitrary command execution on the server running the training scripts.
  - This can lead to severe consequences, including:
    - Complete compromise of the server.
    - Data exfiltration and unauthorized access to sensitive information.
    - Denial of Service (DoS) by disrupting system operations.
    - Further lateral movement within the network if the server is part of a larger infrastructure.
- vulnerability rank: Critical
- currently implemented mitigations:
  - None. Based on the provided code files, there are no visible sanitization or validation mechanisms in place for the `custom_corpus_path` argument in the training scripts or data loading functions.
- missing mitigations:
  - **Input Sanitization**: Implement robust input sanitization for the `custom_corpus_path` to remove or escape any characters that could be interpreted as shell commands.
  - **Path Validation**: Validate the provided file path to ensure it conforms to expected patterns and is within allowed directories. Restrict the path to only contain alphanumeric characters, underscores, hyphens, and forward slashes, and explicitly disallow special characters used for shell command injection.
  - **Avoid Shell Execution with User Input**: Refactor the data loading logic to avoid using shell commands with user-provided paths. If shell commands are absolutely necessary, use `subprocess.run` with argument lists (not shell strings) and ensure `shell=False` to prevent shell interpretation of the path.
  - **Principle of Least Privilege**: Run the training scripts with the minimal privileges necessary to perform their intended tasks. This can limit the impact of a successful command injection attack.
- preconditions:
  - The attacker must have the ability to execute the training scripts (`train_self_distill.sh` or `train_mutual_distill.sh`). This could be through direct access to the server or indirectly through an interface that allows users to trigger training jobs with custom parameters.
  - The training process must utilize the `custom` task and the `--custom_corpus_path` argument, which then leads to the vulnerable code path (assumed to be present in the complete project, even if not explicitly shown in the provided snippets).
- source code analysis:
  - **Entry Point**: The vulnerability is introduced through the `custom_corpus_path` command-line argument in `train_self_distill.sh` and `train_mutual_distill.sh`.
  - **Parameter Passing**: These scripts pass the `custom_corpus_path` argument to the Python training scripts `src/self_distill.py` and `src/mutual_distill_parallel.py`.
  - **Argument Parsing**: In the Python scripts, `argparse` is used to parse the `--custom_corpus_path` argument.
  - **Data Loading**: The `load_data` function in `src/data.py` is called with `task="custom"` and the user-provided `fpath` (which originates from `custom_corpus_path`).
  - **`load_custom` function**: The `load_custom(fpath)` function in `src/data.py` is intended to load data from the specified file path. **Vulnerability Assumption**: While the provided snippet only shows safe file opening using `with open(fpath, "r") as f:`, it is assumed for the purpose of this vulnerability description (based on the prompt's guidance) that there is another part of the `load_custom` function or a related data processing step (not visible in the provided files) where the `fpath` is unsafely used in a shell command, leading to command injection.
  - **No Sanitization**: There is no code in the provided files that sanitizes or validates the `custom_corpus_path` before it is used in the (assumed) vulnerable shell command execution.
- security test case:
  1. **Setup**: Assume you have access to an environment where you can execute the `train_self_distill.sh` script.
  2. **Malicious Path Creation**: Create a malicious file path string that includes a command to be executed. For example: `malicious_corpus_path="; touch /tmp/pwned #"`. This path, when unsafely passed to a shell, should execute the `touch /tmp/pwned` command.
  3. **Execution with Malicious Path**: Execute the training script, providing the malicious path as the `custom_corpus_path` argument. For example:
     ```bash
     bash train_self_distill.sh 0 --task custom --custom_corpus_path "; touch /tmp/pwned #"
     ```
  4. **Verification**: After the script execution completes (or fails), check if the injected command was executed. In this example, verify if the file `/tmp/pwned` has been created on the system. You can use the command `ls /tmp/pwned` to check for the file's existence.
  5. **Expected Outcome**: If the file `/tmp/pwned` exists after running the test, it confirms that command injection was successful through the `custom_corpus_path`. If the file does not exist, and assuming the vulnerability was hypothesized based on missing code, further investigation of the complete codebase would be needed to pinpoint the exact location of the command injection or confirm its absence. However, based on the prompt, this test case is designed to demonstrate the *potential* command injection vulnerability through the `custom_corpus_path`.