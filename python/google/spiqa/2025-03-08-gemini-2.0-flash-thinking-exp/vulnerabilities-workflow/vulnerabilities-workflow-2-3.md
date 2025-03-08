- vulnerability name: Path Traversal in Response File Output Path
- description: The evaluation scripts in this project use the `--response_root` argument to specify the directory where the evaluation response files are saved. This argument, provided by the user when running the scripts, is directly used in file path operations without sufficient sanitization or validation. This allows an attacker to manipulate the `--response_root` argument to include path traversal characters (like `../`) and write response files to arbitrary locations on the file system, outside the intended response directory.

  **Steps to trigger the vulnerability:**
  1. An attacker executes any of the evaluation scripts (e.g., `gemini_qa_test-a_evaluation_image+caption.py`).
  2. The attacker provides a maliciously crafted path as the `--response_root` argument, such as `../../../../tmp/spiqa_output`.
  3. The evaluation script uses `os.makedirs` to create the directory specified by `--response_root` and `os.path.join` and `open` to create and write response files within this directory.
  4. Due to the lack of path sanitization, the response files are created in the attacker-specified directory (e.g., `/tmp/spiqa_output`) instead of the intended project subdirectory.

- impact: Arbitrary File Write. By exploiting this path traversal vulnerability, an attacker can write files to arbitrary locations on the server's file system where the evaluation script is executed. This could lead to several critical security impacts:
  - Overwriting existing files: An attacker could overwrite critical system files, configuration files, or application files, potentially leading to system instability, denial of service, or unauthorized modification of application behavior.
  - Creating files in sensitive directories: An attacker could create new files in sensitive directories, potentially including malicious scripts or executables that could be later used for further attacks, such as gaining unauthorized access or escalating privileges.
  - Data exfiltration (indirect): While direct data exfiltration might not be the primary impact, an attacker could potentially overwrite application logs or create files in web server directories to indirectly leak sensitive information.

- vulnerability rank: High
- currently implemented mitigations: None. The code directly uses the user-provided `response_root` argument without any validation or sanitization.
- missing mitigations:
  - Input validation: Implement validation for the `--response_root` argument to ensure it is a safe path and does not contain path traversal sequences like `../` or malicious characters.
  - Path sanitization: Sanitize the user-provided path to remove any path traversal sequences before using it in file operations.
  - Restricting output directory: Restrict the output directory to a predefined safe location within the project directory. Use absolute paths and avoid using user-supplied paths directly.
- preconditions:
  1. The attacker must have the ability to execute one of the evaluation scripts (e.g., through a publicly accessible interface if available, or by directly running the script if they have access to the environment).
  2. The attacker needs to be able to provide command-line arguments to the script, specifically the `--response_root` argument.
- source code analysis:
  - Multiple Python scripts across different evaluation tasks (test-a, test-b, test-c) within the `/code/evals` directory are vulnerable.
  - Example from `/code/evals/test-a/closed_models/gemini_qa_test-a_evaluation_image+caption.py`:
    ```python
    parser = argparse.ArgumentParser(description='Evaluate on Qasa/Qasper.')
    parser.add_argument('--response_root', type=str, help='Response Root path.')
    args = parser.parse_args()

    _RESPONSE_ROOT = args.response_root
    os.makedirs(_RESPONSE_ROOT, exist_ok=True)

    for paper_id, paper in testA_data.items():
        if os.path.exists(os.path.join(_RESPONSE_ROOT, str(paper_id) + '_response.json')):
            continue
        # ...
        with open(os.path.join(_RESPONSE_ROOT, str(paper_id) + '_response.json'), 'w') as f:
            json.dump(response_paper, f)
    ```
  - In this code snippet, `args.response_root` directly takes the value from the command line and assigns it to `_RESPONSE_ROOT`.
  - `os.makedirs(_RESPONSE_ROOT, exist_ok=True)` creates the directory structure based on the potentially malicious path.
  - `os.path.join(_RESPONSE_ROOT, str(paper_id) + '_response.json')` constructs the full file path for saving the response, incorporating the attacker-controlled `_RESPONSE_ROOT`.
  - `open(os.path.join(_RESPONSE_ROOT, str(paper_id) + '_response.json'), 'w')` opens the file in write mode at the attacker-specified location.
  - **Visualization:**
    ```
    User Input (--response_root) --> args.response_root --> _RESPONSE_ROOT --> os.makedirs/os.path.join/open --> File Write at Attacker Controlled Path
    ```
  - This pattern is repeated across all evaluation scripts that utilize the `--response_root` argument.

- security test case:
  1. Clone the SPIQA repository to your local machine:
     ```bash
     git clone <repository_url>
     cd spiqa/code/evals/test-a/closed_models/
     ```
  2. Run the `gemini_qa_test-a_evaluation_image+caption.py` script, providing a path traversal payload for the `--response_root` argument. In this example, we attempt to write the output to the `/tmp/spiqa_output` directory (assuming `/tmp` is writable):
     ```bash
     python gemini_qa_test-a_evaluation_image+caption.py --response_root "../../../../../tmp/spiqa_output" --image_resolution -1 --model_id gemini-1.5-pro
     ```
     **Note:** You might need to set the `api_key` in the script if it requires one, though the path traversal vulnerability is independent of API key validity. For testing purposes, you can use a placeholder API key or comment out the API calls if the script allows it without errors for the initial file writing stage.
  3. After the script execution, check if the response files (e.g., `1702.03584v3_response.json`, `1702.04447v2_response.json`, etc.) are created in the `/tmp/spiqa_output` directory:
     ```bash
     ls /tmp/spiqa_output/
     ```
  4. If you find the response files in `/tmp/spiqa_output`, it confirms the path traversal vulnerability. The script was able to write files outside of the intended `evals/test-a/closed_models/` directory and traversed up to the `/tmp/spiqa_output` directory, demonstrating arbitrary file write capability.