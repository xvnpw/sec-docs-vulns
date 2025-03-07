- vulnerability name: Path Traversal in Evaluation Script Output Directory

- description:
    1. The `balloon_learning_environment.eval.eval` script uses the `--output_dir` argument to specify the directory where evaluation results are saved.
    2. An attacker could potentially provide a malicious path for `--output_dir`, such as `/../../../../tmp/evil_dir`, aiming to write files outside the intended `/tmp/ble/eval` directory.
    3. If the `eval.py` script does not properly sanitize the `--output_dir` input, it might be vulnerable to path traversal.
    4. By crafting a specific `--output_dir` value, an attacker could potentially overwrite or create files in arbitrary locations on the system where the evaluation script is executed.

- impact:
    - High: Arbitrary File Write. If exploited, this vulnerability allows an attacker to write files to any location on the file system accessible to the user running the evaluation script. This can lead to various malicious outcomes, including:
        - Overwriting critical system files, potentially leading to system instability or denial of service.
        - Creating malicious files in startup directories to achieve persistent code execution.
        - Writing files to user's home directories, potentially overwriting user data or configuration files.

- vulnerability rank: High

- currently implemented mitigations:
    - None: Based on the provided files, there is no explicit sanitization or validation of the `output_dir` path within the evaluation script.

- missing mitigations:
    - Input sanitization: Implement path sanitization for the `--output_dir` argument in `eval.py` to prevent path traversal. This could involve:
        - Using a library function to canonicalize the path and resolve symbolic links to prevent traversal using `..`.
        - Validating that the output directory is within an expected base directory and rejecting paths that attempt to go outside of it.
        - Using allowlisting to only permit specific characters or path structures.

- preconditions:
    - The user must execute the `balloon_learning_environment.eval.eval` script.
    - The attacker needs to control the `--output_dir` argument, which is typically passed via command line.

- source code analysis:
    1. File `/code/balloon_learning_environment/eval/eval.py` defines the entry point for the evaluation script.
    2. The script uses `absl.flags` to define command-line arguments, including `--output_dir`:
    ```python
    flags.DEFINE_string('output_dir', '/tmp/ble/eval',
                        'The directory to output the json summary.')
    ```
    3. The `FLAGS.output_dir` is used later in the script to construct the output file path:
    ```python
    def write_result(result: Sequence[eval_lib.EvaluationResult]) -> None:
        ...
        dir_path = os.path.join(FLAGS.output_dir, FLAGS.suite)
        file_path = os.path.join(dir_path, file_name)
        ...
        os.makedirs(dir_path, exist_ok=True)
        with open(file_path, 'w') as f:
          json.dump(result, f, cls=eval_lib.EvalResultEncoder, indent=indent)
    ```
    4.  The code uses `os.path.join` to construct the directory path and file path. While `os.path.join` itself doesn't prevent path traversal, it depends on how `FLAGS.output_dir` is handled before being passed to `os.path.join`.
    5. **Crucially, there is no sanitization or validation of `FLAGS.output_dir` before it is used in `os.path.join` and `os.makedirs` and `open`.** This means if an attacker provides a path like `/../../../../tmp/evil_dir`, `os.path.join` will construct a path that traverses out of the intended directory. `os.makedirs` will create directories along this potentially malicious path, and `open` will create a file at the attacker-specified location.

- security test case:
    1. Assume an attacker has access to run the `eval.py` script, either locally or on a system where the BLE is installed.
    2. The attacker crafts a command to run the evaluation script, providing a malicious `--output_dir` argument designed to traverse directories and write a file to a sensitive location, for example `/tmp/evil_dir`:
    ```bash
    python -m balloon_learning_environment.eval.eval \
      --agent=random \
      --suite=micro_eval \
      --output_dir='/../../../../tmp/evil_dir'
    ```
    3. Execute the command.
    4. After the script execution, check if a file named `random.json` (or `<agent_name>.json`) has been created in the `/tmp/evil_dir` directory.
    5. If the file is created in `/tmp/evil_dir`, it confirms the path traversal vulnerability, as the intention was to write within `/tmp/ble/eval`.

This test case demonstrates that an attacker can control file creation location using the `--output_dir` argument, confirming the path traversal vulnerability.