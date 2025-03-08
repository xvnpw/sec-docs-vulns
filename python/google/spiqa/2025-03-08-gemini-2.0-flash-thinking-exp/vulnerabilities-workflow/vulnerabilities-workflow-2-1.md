- Vulnerability Name: Path Traversal in Response File Output
  - Description: The evaluation scripts use `os.path.join` to create file paths for saving model responses under the directory specified by the `--response_root` argument. By providing a crafted input dataset (SPIQA_testA.json, SPIQA_testB.json, SPIQA_testC.json) containing a malicious `paper_id` that includes path traversal sequences (e.g., `../../`, `..\\`), an attacker can write response files to arbitrary locations outside the intended `--response_root` directory. This is because the `paper_id` is incorporated into the output file path without proper sanitization.
  - Impact: An attacker can overwrite or create files in arbitrary locations on the user's file system. This can lead to various security issues, including:
    - Data Corruption: Overwriting critical system files or user data.
    - Information Disclosure: Creating files in publicly accessible directories containing sensitive information.
    - Arbitrary Code Execution: Overwriting executable files or configuration files to inject malicious code that could be executed when those files are accessed or run by the user or system.
  - Vulnerability Rank: High
  - Currently Implemented Mitigations: None. The code directly uses `os.path.join` with unsanitized `paper_id` to construct file paths.
  - Missing Mitigations:
    - Sanitize or validate the `paper_id` to prevent path traversal sequences. Implement input validation to ensure that `paper_id` does not contain directory traversal characters like `..`, `.` or path separators.
    - Use secure path manipulation functions that prevent traversal, such as `os.path.abspath` to canonicalize the path and verify it's still within the intended base directory. Alternatively, consider using a library like `pathlib` for safer path manipulation.
  - Preconditions:
    - The user must run any evaluation script from the `/code/evals` directory.
    - The user must provide a `--response_root` argument specifying the base directory for saving responses.
    - The evaluation scripts process a dataset (e.g., SPIQA_testA.json) that has been maliciously crafted to include `paper_id` values with path traversal sequences.
  - Source Code Analysis: The vulnerability is present in multiple evaluation scripts across different test sets (test-A, test-B, test-C) and model types (closed and open source) because they share similar file saving logic.

    For example, in `/code/evals/test-c/closed_models/gemini_qa_test-c_evaluation_image+caption.py`:
    ```python
    _RESPONSE_ROOT = args.response_root
    os.makedirs(_RESPONSE_ROOT, exist_ok=True)
    ...
    for paper_id, paper in qasper_data.items():
        ...
        with open(os.path.join(_RESPONSE_ROOT, str(paper_id) + '_response.json'), 'w') as f:
            json.dump(response_paper, f)
    ```
    - `_RESPONSE_ROOT` is directly assigned the value of `args.response_root`, which is user-controlled.
    - `paper_id` is read from the input `qasper_data` JSON file, which can be manipulated by an attacker.
    - `os.path.join(_RESPONSE_ROOT, str(paper_id) + '_response.json')` concatenates `_RESPONSE_ROOT` and `paper_id` to form the output file path. If `paper_id` contains path traversal characters, the resulting path can escape the intended `_RESPONSE_ROOT` directory.
    - `open(...)` opens the file at the constructed path in write mode ('w'), allowing an attacker to write arbitrary content (model responses in JSON format) to the traversed location.

    This pattern is repeated in other evaluation scripts, making them all vulnerable to the same path traversal issue.

  - Security Test Case:
    1. **Prepare Malicious Data:** Create a malicious JSON data file (e.g., `malicious_spiqa_testC.json`) based on the format of `../../../datasets/test-C/SPIQA_testC.json`. In this file, insert a crafted `paper_id` with path traversal characters into one of the paper entries. For example:
    ```json
    {
      "..__malicious": {
        "question": ["What is the meaning of life?"],
        "answer": [{"free_form_answer": "42"}],
        "question_key": ["q1"],
        "figures_and_tables": [],
        "referred_figures_tables": [[]],
        "arxiv_id": "malicious_arxiv_id",
        "full_text": []
      },
      "1808.08780": {
        "question": ["What is the question for paper 1808.08780?"],
        "answer": [{"free_form_answer": "This is a normal answer"}],
        "question_key": ["q2"],
        "figures_and_tables": [],
        "referred_figures_tables": [[]],
        "arxiv_id": "1808.08780",
        "full_text": []
      }
    }
    ```
    Save this file as `malicious_spiqa_testC.json` in the `/code/datasets/test-C/` directory, replacing the original `SPIQA_testC.json` for testing purposes, or create a separate test dataset and modify the script to use it.

    2. **Run Evaluation Script:** Execute one of the evaluation scripts, for example, using the Gemini model evaluation script for test-C:
    ```bash
    cd /code/evals/test-c/closed_models/
    python gemini_qa_test-c_evaluation_image+caption.py --response_root /tmp/output --model_id gemini-1.5-pro
    ```
    *Note:* You might need to set up the environment and API keys as described in the README to run the script successfully. However, for testing the path traversal vulnerability, the API key and model execution are not strictly necessary as long as the script attempts to create the output file.*

    3. **Check for File Creation:** After running the script, check if a file has been created outside the specified `--response_root` directory (`/tmp/output`). In this specific example with `paper_id` as `..__malicious`, check for a file named `__malicious_response.json` in the `/tmp/` directory:
    ```bash
    ls /tmp/__malicious_response.json
    ```
    If the file `__malicious_response.json` exists in `/tmp/`, it confirms the path traversal vulnerability, as the file was written outside the intended `/tmp/output` directory.

    4. **Cleanup:** Delete the created malicious response file from `/tmp`:
    ```bash
    rm /tmp/__malicious_response.json
    ```
    And restore the original `SPIQA_testC.json` if you replaced it in step 1.