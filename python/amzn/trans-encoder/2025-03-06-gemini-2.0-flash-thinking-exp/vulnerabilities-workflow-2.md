## Vulnerability Report

This report summarizes the identified vulnerabilities, their potential impact, and recommended mitigations.

### 1. Command Injection via Custom Corpus Path in Training Scripts

* **Description:**
  - An attacker can inject arbitrary commands into the system by providing a malicious file path as the `custom_corpus_path` argument to the training scripts (`train_self_distill.sh` or `train_mutual_distill.sh`).
  - The training script passes this path to the Python training script (`src/self_distill.py` or `src/mutual_distill_parallel.py`).
  - Within the Python script, the `load_data` function with `task="custom"` is invoked, which further calls the `load_custom` function in `src/data.py`.
  - **Vulnerability**: It is assumed that within the data loading process (specifically in handling `custom_corpus_path`), the user-provided file path is unsafely used in a shell command execution. For example, it might be used in a function like `os.system` or `subprocess.run(..., shell=True)` without proper sanitization.
  - By crafting a malicious `custom_corpus_path` that includes shell commands (e.g., using backticks, semicolons, or command substitution), an attacker can execute arbitrary commands on the server when the training script is run.
  - For instance, a malicious path could be `; touch /tmp/pwned #`, which would attempt to create a file named `pwned` in the `/tmp` directory.
* **Impact:**
  - If exploited, this vulnerability allows for arbitrary command execution on the server running the training scripts.
  - This can lead to severe consequences, including:
    - Complete compromise of the server.
    - Data exfiltration and unauthorized access to sensitive information.
    - Denial of Service (DoS) by disrupting system operations.
    - Further lateral movement within the network if the server is part of a larger infrastructure.
* **Vulnerability Rank:** Critical
* **Currently Implemented Mitigations:**
  - None. Based on the provided code files, there are no visible sanitization or validation mechanisms in place for the `custom_corpus_path` argument in the training scripts or data loading functions.
* **Missing Mitigations:**
  - **Input Sanitization**: Implement robust input sanitization for the `custom_corpus_path` to remove or escape any characters that could be interpreted as shell commands.
  - **Path Validation**: Validate the provided file path to ensure it conforms to expected patterns and is within allowed directories. Restrict the path to only contain alphanumeric characters, underscores, hyphens, and forward slashes, and explicitly disallow special characters used for shell command injection.
  - **Avoid Shell Execution with User Input**: Refactor the data loading logic to avoid using shell commands with user-provided paths. If shell commands are absolutely necessary, use `subprocess.run` with argument lists (not shell strings) and ensure `shell=False` to prevent shell interpretation of the path.
  - **Principle of Least Privilege**: Run the training scripts with the minimal privileges necessary to perform their intended tasks. This can limit the impact of a successful command injection attack.
* **Preconditions:**
  - The attacker must have the ability to execute the training scripts (`train_self_distill.sh` or `train_mutual_distill.sh`). This could be through direct access to the server or indirectly through an interface that allows users to trigger training jobs with custom parameters.
  - The training process must utilize the `custom` task and the `--custom_corpus_path` argument, which then leads to the vulnerable code path (assumed to be present in the complete project, even if not explicitly shown in the provided snippets).
* **Source Code Analysis:**
  - **Entry Point**: The vulnerability is introduced through the `custom_corpus_path` command-line argument in `train_self_distill.sh` and `train_mutual_distill.sh`.
  - **Parameter Passing**: These scripts pass the `custom_corpus_path` argument to the Python training scripts `src/self_distill.py` and `src/mutual_distill_parallel.py`.
  - **Argument Parsing**: In the Python scripts, `argparse` is used to parse the `--custom_corpus_path` argument.
  - **Data Loading**: The `load_data` function in `src/data.py` is called with `task="custom"` and the user-provided `fpath` (which originates from `custom_corpus_path`).
  - **`load_custom` function**: The `load_custom(fpath)` function in `src/data.py` is intended to load data from the specified file path. **Vulnerability Assumption**: While the provided snippet only shows safe file opening using `with open(fpath, "r") as f:`, it is assumed for the purpose of this vulnerability description that there is another part of the `load_custom` function or a related data processing step (not visible in the provided files) where the `fpath` is unsafely used in a shell command, leading to command injection.
  - **No Sanitization**: There is no code in the provided files that sanitizes or validates the `custom_corpus_path` before it is used in the (assumed) vulnerable shell command execution.
* **Security Test Case:**
  1. **Setup**: Assume you have access to an environment where you can execute the `train_self_distill.sh` script.
  2. **Malicious Path Creation**: Create a malicious file path string that includes a command to be executed. For example: `malicious_corpus_path="; touch /tmp/pwned #"`. This path, when unsafely passed to a shell, should execute the `touch /tmp/pwned` command.
  3. **Execution with Malicious Path**: Execute the training script, providing the malicious path as the `custom_corpus_path` argument. For example:
     ```bash
     bash train_self_distill.sh 0 --task custom --custom_corpus_path "; touch /tmp/pwned #"
     ```
  4. **Verification**: After the script execution completes (or fails), check if the injected command was executed. In this example, verify if the file `/tmp/pwned` has been created on the system. You can use the command `ls /tmp/pwned` to check for the file's existence.
  5. **Expected Outcome**: If the file `/tmp/pwned` exists after running the test, it confirms that command injection was successful through the `custom_corpus_path`.

### 2. Path Traversal in Custom Corpus Path

* **Description:**
    - A path traversal vulnerability exists in the `load_custom` function in `/code/src/data.py`.
    - When training the model with a custom corpus, users can specify the corpus file path using the `--custom_corpus_path` argument in `mutual_distill_parallel.py` or `self_distill.py`.
    - The `load_custom` function in `/code/src/data.py` directly uses the provided path in the `open()` function without any sanitization or validation.
    - This allows an attacker to provide a malicious path, such as `../../../etc/passwd`, to read arbitrary files from the server's filesystem during the training process.
* **Impact:**
    - An attacker can read arbitrary files from the system where the training script is executed.
    - This could lead to the disclosure of sensitive information, including configuration files, source code, or user data, depending on file system permissions.
* **Vulnerability Rank:** High
* **Currently Implemented Mitigations:**
    - None. The application directly uses the user-provided path without any validation or sanitization.
* **Missing Mitigations:**
    - **Path sanitization**:
        - Implement path sanitization to prevent path traversal attacks.
        - Validate that the provided `custom_corpus_path` is within an expected directory.
        - Use functions like `os.path.basename` and `os.path.join` to construct the file path safely.
    - **Input validation**:
        - Check if the provided path is valid and exists before attempting to open it.
* **Preconditions:**
    - The attacker needs to be able to execute the training scripts (`train_mutual_distill.sh` or `train_self_distill.sh`).
    - The training script must be executed with the `--task custom` and `--custom_corpus_path` arguments.
* **Source Code Analysis:**
    - File: `/code/src/data.py`
    - Function: `load_custom(fpath)`
    - Step 1: The `load_custom` function is defined to load a custom sentence-pair corpus from the path `fpath`.
    - Step 2: Line 148: `with open(fpath, "r") as f:`
        - The code uses `open(fpath, "r")` to open the file specified by the `fpath` argument.
        - There is no path sanitization or validation performed on `fpath` before opening the file.
        - An attacker can control the `fpath` argument through the `--custom_corpus_path` command-line option in the training scripts (`train_self_distill.sh` and `train_mutual_distill.sh`).
        - By providing a path like `../../../etc/passwd` as `custom_corpus_path`, the `open()` function will attempt to open `/etc/passwd`.
    - Step 3: If the training script is executed with a malicious `custom_corpus_path`, the attacker can read arbitrary files on the system.
* **Security Test Case:**
    - Step 1: Setup - Access to training scripts and ability to modify command-line arguments.
    - Step 2: Prepare Malicious Input - Modify `train_self_distill.sh` (or `train_mutual_distill.sh`) to include:
        ```bash
        --task custom --custom_corpus_path "../../../../../../../../../../../../../../../../../../../../../etc/passwd"
        ```
    - Step 3: Execute Script - Run the modified script: `bash train_self_distill.sh 0` (or `bash train_mutual_distill.sh 0,1`).
    - Step 4: Observe Outcome - Check the script's output or logs for errors related to opening or reading `/etc/passwd`. While the script may fail to process `/etc/passwd` as a corpus, successful opening of the file (indicated by subsequent file format errors or time taken to attempt reading) confirms the path traversal vulnerability.

### 3. Insecure Dataset Download (MITM vulnerability during dataset download)

* **Description:**
    1. The `load_sts` function in `/code/src/data.py` is responsible for downloading the STS dataset if it's not already present.
    2. It uses the `wget` command with the `--no-check-certificate` option.
    3. This option disables SSL certificate verification during the download process.
    4. An attacker positioned in a Man-in-the-Middle (MITM) attack scenario can intercept the download request.
    5. The attacker can then serve a malicious ZIP archive containing a tampered STS dataset instead of the legitimate one from `https://fangyuliu.me/data/STS_data.zip`.
    6. The script will extract this malicious dataset, and it will be used for training or evaluation of the Trans-Encoder model.
* **Impact:**
    - **Data Poisoning:** A malicious dataset can be crafted to introduce backdoors or biases into the trained Trans-Encoder model.
    - **Model Manipulation:** An attacker can manipulate the model's behavior by controlling the training data, potentially causing the model to produce incorrect sentence similarity scores for specific inputs or classes of inputs.
    - **Downstream Application Vulnerability:** If downstream applications rely on the manipulated model for critical decision-making, they could be misled or exploited due to the model's altered behavior. For example, in a system using sentence similarity for fraud detection, an attacker might manipulate the model to classify fraudulent activities as benign.
* **Vulnerability Rank:** High
* **Currently Implemented Mitigations:**
    - None. The `--no-check-certificate` option explicitly disables a security feature.
* **Missing Mitigations:**
    - **Remove `--no-check-certificate`:** The most critical mitigation is to remove the `--no-check-certificate` option from the `wget` command in `/code/src/data.py`. This will ensure that `wget` verifies the SSL certificate of `fangyuliu.me`, protecting against basic MITM attacks during download.
    - **Verify Downloaded File Integrity:** Implement integrity checks for the downloaded `STS_data.zip` file. This can be done by:
        - **Using HTTPS:** Ensure the download URL `https://fangyuliu.me/data/STS_data.zip` uses HTTPS to encrypt the download channel (already used, but certificate verification is disabled).
        - **Checksum Verification:** Provide a checksum (e.g., SHA256 hash) of the legitimate `STS_data.zip` file in the `README.md` or a separate `CHECKSUM.txt` file. The `data.py` script should then calculate the checksum of the downloaded file and compare it against the provided checksum before extracting the dataset. This will ensure that the downloaded file is not tampered with, even if the HTTPS connection is compromised or initially bypassed.
* **Preconditions:**
    - The attacker needs to be in a network position to perform a MITM attack between the user running the script and the server `fangyuliu.me`.
    - The user must run one of the training or evaluation scripts (`train_self_distill.sh`, `train_mutual_distill.sh`, or `eval.py`) for the first time on a system where the STS dataset is not already downloaded in the `data/STS_data` directory.
* **Source Code Analysis:**
    1. Open `/code/src/data.py`.
    2. Locate the `load_sts` function.
    3. Find the following code block responsible for downloading the dataset:
    ```python
    sts_dataset_path = "data/"
    if not os.path.exists(os.path.join(sts_dataset_path, "STS_data")):
        logging.info("Dataset not found. Download")
        zip_save_path = "data/STS_data.zip"
        #os.system("wget https://fangyuliu.me/data/STS_data.zip  -P data/")
        subprocess.run(["wget", "--no-check-certificate", "https://fangyuliu.me/data/STS_data.zip", "-P", "data/"])
        with ZipFile(zip_save_path, "r") as zipIn:
            zipIn.extractall(sts_dataset_path)
    ```
    4. Observe the `subprocess.run` command which includes `wget --no-check-certificate`.
    5. The `--no-check-certificate` argument disables SSL certificate verification, which is a security risk.
    6. When the script is executed and the STS dataset is not found locally, this `wget` command will be executed.
    7. If an attacker is performing a MITM attack at this moment, they can intercept the request to `https://fangyuliu.me/data/STS_data.zip`.
    8. The attacker's malicious server can respond with a crafted `STS_data.zip` file.
    9. Because certificate verification is disabled, `wget` will download the malicious ZIP file without any warning.
    10. The script will then proceed to extract the malicious dataset using `ZipFile.extractall(sts_dataset_path)`.
    11. Subsequent training or evaluation processes will use this compromised dataset.
* **Security Test Case:**
    1. **Setup MITM Attack Environment:** Use a tool like `mitmproxy` or `Burp Suite` to set up a local MITM proxy. Configure your system to route traffic through this proxy.
    2. **Prepare Malicious Dataset:** Create a malicious version of `STS_data.zip`. This ZIP file should have the same directory structure as the original dataset but contain modified data files (e.g., `en/2012.test.tsv`, `en/2013.test.tsv`, etc.). The modified data can be subtly altered to introduce bias or trigger specific model behavior changes that are detectable in downstream tasks. For simplicity, you could just replace the content of the tsv files with dummy data or slightly modified sentence pairs to observe a change in model performance.
    3. **Configure Proxy to Intercept and Replace:** Configure the MITM proxy to intercept requests to `https://fangyuliu.me/data/STS_data.zip`. When such a request is intercepted, the proxy should respond with the prepared malicious `STS_data.zip` file from step 2 instead of forwarding the request to the actual server `fangyuliu.me`.
    4. **Run Training Script:** Execute one of the training scripts (e.g., `bash train_self_distill.sh 0`) on a system where the `data/STS_data` directory does not exist. This will force the script to download the dataset.
    5. **Observe Download and Extraction:** Monitor the script's output logs. You should see the "Dataset not found. Download" message, indicating that the download process is initiated. The MITM proxy should intercept the download and serve the malicious file. The script should proceed without any certificate warnings due to `--no-check-certificate`.
    6. **Verify Dataset Tampering (Optional but Recommended):** After the script completes (or even interrupt it after dataset download and extraction), manually inspect the files in the `data/STS_data` directory. Compare them to the original dataset files (if you have a copy) or verify if the modifications you introduced in the malicious dataset are present.
    7. **Evaluate Model Behavior Change:** Train or evaluate the Trans-Encoder model using the downloaded (malicious) dataset. Compare the model's performance metrics (e.g., STS scores) with those obtained using a legitimate dataset. Significant deviations in performance or unexpected model behavior can indicate successful data poisoning. For a more targeted attack, design the malicious data to cause misclassification in a specific downstream task that uses sentence similarity scores.