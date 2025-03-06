## Combined Vulnerability List

### Path Traversal in Inference Script via `dataset` and `output_suffix` parameters

- **Description:**
  1. The `run_inference.sh` script takes `DATASET` and `SUFFIX` variables as input, which are passed to `inference.py` as the `--dataset` and `--output_suffix` arguments respectively.
  2. The `inference.py` script uses the `--dataset` argument to construct file paths, likely within functions like `dataset_params.get_model_params` and `dataset_params.get_split_params`. The `--output_suffix` is used to construct the output file name: `est_pose_file = '{}/mrcnet_{}-test_{}.csv'.format(p['eval_root'], p['dataset'], p['output_suffix_name'])` where `p['output_suffix_name'] = '{}_{}'.format(args.checkpoint_name, args.output_suffix)`.
  3. If an attacker can modify the `DATASET` or `SUFFIX` variables in `run_inference.sh` to include path traversal characters (e.g., `../`), they could potentially access or create files outside of the intended directories.
  4. For example, setting `DATASET=../../../../etc/passwd` might cause the application to attempt to open `/path/to/bop_root/../../../../etc/passwd/model_info.json`, potentially exposing system files. Setting `SUFFIX=../../../../tmp/output` might cause the application to write output CSV to `/tmp/output.csv` overwriting potentially sensitive files if the application has write permissions there.

- **Impact:**
    - Arbitrary File Read: An attacker could read arbitrary files from the server's file system, including sensitive configuration files, code, or data by manipulating `DATASET`.
    - Arbitrary File Write (potentially): An attacker could write or overwrite arbitrary files on the server's file system by manipulating `SUFFIX`, if the application has write permissions to those locations.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:** None

- **Missing Mitigations:**
    - Input validation and sanitization for the `dataset` and `output_suffix` parameters to prevent path traversal characters.
    - Using secure file path construction methods that prevent traversal, regardless of input.
    - Restricting write permissions to output directories.

- **Preconditions:**
    - The attacker needs to be able to modify the `DATASET` or `SUFFIX` variables in `run_inference.sh` or directly call `inference.py` with malicious `--dataset` or `--output_suffix` arguments.

- **Source Code Analysis:**
    1. `/code/scripts/run_inference.sh`: The script defines `DATASET` and `SUFFIX` variables and passes them as `--dataset` and `--output_suffix` arguments to `inference.py`.
       ```bash
       DATASET=tless
       SUFFIX=0320
       python inference.py --dataset $DATASET --output_suffix $SUFFIX ...
       ```
    2. `/code/inference.py`: The script parses the `--dataset` and `--output_suffix` arguments and stores them in `args.dataset` and `args.output_suffix`.
       ```python
       parser = argparse.ArgumentParser()
       parser.add_argument('--dataset', type=str, required=True)
       parser.add_argument('--output_suffix', type=str, default='')
       args = parser.parse_args()
       dataset_name = args.dataset
       output_suffix = args.output_suffix
       ```
    3. The `dataset_name` variable is then used to construct file paths for reading model information. The `output_suffix` is used to construct the output file path for saving inference results.
       ```python
       p = {
           'dataset': args.dataset,
           'bop_root': bop_cfg.DATASET_ROOT,
           'eval_root': bop_cfg.EVAL_ROOT,
           'output_suffix_name': '{}_{}'.format(
               args.checkpoint_name, args.output_suffix),
           ...
       }
       dataset_id2cls = bop_cfg.DATASET_CONFIG[p['dataset']]['id2cls']
       dp_model = dataset_params.get_model_params(
           p['bop_root'], p['dataset'], model_type)
       dp_data = dataset_params.get_split_params(
           p['bop_root'], p['dataset'], 'test')
       with open(dp_model['models_info_path'], 'r') as fp: # Potential path traversal via dataset
           model_info = json.load(fp)

       est_pose_file = '{}/mrcnet_{}-test_{}.csv'.format(
           p['eval_root'], p['dataset'], p['output_suffix_name']) # Potential path traversal via dataset and output_suffix
       inout.save_bop_results(est_pose_file, bop19_pose_est_results) # File write here, potential path traversal via est_pose_file
       ```

- **Security Test Case:**
    1. **Arbitrary File Read:**
       - Modify `/code/scripts/run_inference.sh`: Change the `DATASET` variable to a path traversal string:
         ```bash
         DATASET='../../../../etc/passwd'
         SUFFIX=0320
         ```
       - Run `/code/scripts/run_inference.sh`: `bash scripts/run_inference.sh`.
       - Observe output/errors: Check the output and error logs of `inference.py`. Look for errors related to accessing `/etc/passwd/model_info.json` or similar paths, indicating a path traversal attempt.
    2. **Arbitrary File Write:**
       - Modify `/code/scripts/run_inference.sh`: Change the `SUFFIX` variable to a path traversal string to write to `/tmp`:
         ```bash
         DATASET='tless'
         SUFFIX='../../../../tmp/output'
         ```
       - Run `/code/scripts/run_inference.sh`: `bash scripts/run_inference.sh`.
       - Check for file creation: After running, check if a file `output.csv` is created in the `/tmp` directory.
       - Verify file content: Examine the content of `/tmp/output.csv` to confirm if it contains the expected inference output data, which would confirm arbitrary file write capability.

### Malicious Pre-trained Model Weights - Supply Chain Attack

- **Description:**
  1. The project `README.md` instructs users to download pre-trained model weights from a provided Google Drive link.
  2. Users are expected to manually download the weights and place them in the `chkpt_<dataset>` directory within the project structure.
  3. The `run_inference.sh` script is then used to execute inference, which loads the pre-trained model weights from the local `chkpt_<dataset>` directory using `torch.load()` in `inference.py`.
  4. An attacker could perform a supply chain attack by compromising the provided Google Drive link and replacing the legitimate pre-trained model weights file with a malicious one.
  5. If a user follows the instructions and downloads the compromised weights, the `inference.py` script will load these malicious weights during inference execution.
  6. Due to the insecure nature of `torch.load()`, a malicious model weights file could contain embedded code that gets executed on the user's machine when the model is loaded, leading to arbitrary code execution.

- **Impact:**
  - Arbitrary code execution on the user's machine.
  - Full compromise of the user's system is possible depending on the attacker's payload in the malicious model weights.
  - Potential data exfiltration, malware installation, or denial of service.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:** None. The project directly uses the downloaded pre-trained weights without any integrity checks or secure download mechanisms.

- **Missing Mitigations:**
  - **Integrity checks:** Implement integrity checks for the downloaded pre-trained model weights. This could involve providing a checksum (e.g., SHA256 hash) of the legitimate weights in the `README.md` and verifying this checksum after downloading the file.
  - **Secure hosting:** Host the pre-trained weights on a more secure and controlled platform, such as GitHub releases, which offers better version control and integrity.
  - **Code review and hardening:** Conduct a thorough security code review of the model loading process in `inference.py` and explore safer alternatives to `torch.load()` or implement sandboxing/isolation techniques if `torch.load()` must be used.
  - **User warnings:** Include a clear warning in the `README.md` about the potential security risks of downloading pre-trained models from external sources and advise users to manually verify the integrity of the downloaded files if checksums are provided, or to download from trusted sources if available.

- **Preconditions:**
  - The user must download the pre-trained model weights by clicking the provided Google Drive link in `README.md`.
  - The attacker must have successfully compromised the Google Drive link and replaced the legitimate model weights file with a malicious file.

- **Source Code Analysis:**
  - `/code/README.md`: The `README.md` file contains the vulnerable Google Drive download link in the "Inference" section:
    ```markdown
    Our pretrained model weights can be downloaded from [this link](https://drive.google.com/file/d/1Bz2ZFAoTHk-pjCcr3HceCLIcj0ugYYia/view?usp=sharing).
    ```
    This link is the entry point for the supply chain attack.
  - `/code/scripts/run_inference.sh`: This script executes the inference process and utilizes the downloaded weights. It sets up the inference command:
    ```bash
    python inference.py \
        --dataset $DATASET \
        --checkpoint_name chkpt_${DATASET} \
        --model_name tless \
        --output_suffix $SUFFIX
    ```
    The `--checkpoint_name chkpt_${DATASET}` argument indicates that the weights are loaded from the `chkpt_${DATASET}` directory, which is where the user is instructed to place the downloaded weights.
  - `/code/inference.py`: The `inference.py` script is where the model weights are actually loaded.
    ```python
    checkpoint = torch.load(p['checkpoint'], map_location=device)
    ```
    The `torch.load()` function directly loads and deserializes the Python objects from the provided file path without any integrity or authenticity checks. If a malicious file is placed at this path, `torch.load()` will execute its contents.

- **Security Test Case:**
  1. **Environment Setup:** Follow the instructions in the `README.md` to set up the environment and install dependencies.
  2. **Malicious Model Weight Creation:** Create a malicious PyTorch model weights file (e.g., `tless.pth`). This file should contain code that will execute arbitrary commands when `torch.load()` is called. A simple proof-of-concept payload could be to print a message to the console or create a file in the user's temporary directory. For example, the malicious `tless.pth` could be crafted to include code that executes `os.system('touch /tmp/pwned')` when loaded.
  3. **Simulate Weights Replacement:** Since direct modification of the Google Drive link is not possible in this context, simulate the attack by manually placing the malicious `tless.pth` file into the `chkpt_tless` directory within the project. Ensure to remove or rename any legitimate `tless.pth` file that might already be present from previous steps.
  4. **Execute Inference Script:** Run the inference script using the command: `bash scripts/run_inference.sh`.
  5. **Verify Code Execution:** After running the inference script, check for the indicators of malicious code execution. In the example payload, verify if the file `/tmp/pwned` has been created. If the file exists, it confirms that the malicious code embedded in the `tless.pth` was executed when `torch.load()` processed the file during the inference process, thus validating the vulnerability.

### Command Injection in `run_inference.sh` via `DATASET` variable

- **Description:**
    1. The `run_inference.sh` script executes the `inference.py` Python script.
    2. The script takes user-controlled input through the `DATASET` environment variable (or defaults to `tless` if not set).
    3. The value of the `DATASET` variable is directly incorporated into the `python inference.py` command as arguments `--dataset $DATASET` and `--checkpoint_name chkpt_${DATASET}` without any sanitization.
    4. An attacker can manipulate the `DATASET` variable to inject arbitrary shell commands. For example, setting `DATASET` to  `tless; touch injected.txt` will cause the script to execute `touch injected.txt` command after the intended dataset name.

- **Impact:**
    - **High:** Successful command injection allows an attacker to execute arbitrary commands on the server or user's machine running the inference script. This can lead to:
        - **Data Breach:** Access to sensitive data, including model weights, datasets, and potentially other files on the system.
        - **System Compromise:** Complete control over the system, allowing for malware installation, data manipulation, or denial of service.
        - **Lateral Movement:** Potential to use the compromised system as a stepping stone to attack other systems in the network.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:** None. The script directly uses the unsanitized variable in a command execution.

- **Missing Mitigations:**
    - Input Sanitization:  The script should sanitize or validate the `DATASET` variable to ensure it only contains expected characters (e.g., alphanumeric and underscores) and prevents command injection.
    - Input Validation:  Check if the provided `DATASET` is within an expected list of datasets and reject invalid inputs.
    - Parameterization: Use parameterized queries or commands where possible, although this might be less applicable in shell scripting but relevant when constructing commands in Python code.
    - Principle of Least Privilege: Run the script with minimal necessary privileges to limit the impact of a successful command injection.

- **Preconditions:**
    - The attacker needs to be able to modify the `DATASET` environment variable before executing the `run_inference.sh` script. This is typically possible if the attacker can execute the script themselves or influence its execution environment.

- **Source Code Analysis:**
    - **File:** `/code/scripts/run_inference.sh`
    - **Line 3:** `DATASET=tless` -  Default value for `DATASET` is set to `tless`. This can be overridden by setting the environment variable `DATASET` before running the script.
    - **Line 4:** `SUFFIX=0320` - Default value for `SUFFIX`. Similar to `DATASET`, this can be overridden.
    - **Line 9:** `python inference.py \` -  Execution of the `inference.py` script.
    - **Line 10:** `--dataset $DATASET \` -  The value of the `DATASET` variable is passed as an argument to `inference.py`.
    - **Line 11:** `--checkpoint_name chkpt_${DATASET} \` - The `DATASET` variable is used to construct the checkpoint directory name.

    **Vulnerability Flow:**
    ```
    User Input (DATASET variable) --> run_inference.sh script --> Command Construction (`python inference.py --dataset $DATASET ...`) --> Command Execution (bash shell) --> Command Injection if DATASET is malicious
    ```

- **Security Test Case:**
    1. **Precondition:** Access to a system where MRC-Net project is deployed and the ability to execute shell scripts.
    2. **Step 1:** Open a terminal and navigate to the `/code/scripts` directory of the MRC-Net project.
    3. **Step 2:** Set the `DATASET` environment variable to a malicious payload designed for command injection. For example:
        ```bash
        export DATASET="tless; touch injected_file.txt"
        ```
    4. **Step 3:** Execute the `run_inference.sh` script:
        ```bash
        bash run_inference.sh
        ```
    5. **Step 4:** Check for successful command injection. After the script execution, verify if a file named `injected_file.txt` has been created in the project's directory.

### Command Injection in `run_inference.sh` via `SUFFIX` variable

- **Description:**
    1.  Similar to the `DATASET` variable, the `SUFFIX` variable in `run_inference.sh` is also taken as user input (or defaults to `0320`).
    2.  The value of `SUFFIX` is directly used in the `python inference.py` command as argument `--output_suffix $SUFFIX` without sanitization.
    3.  An attacker can manipulate the `SUFFIX` variable to inject shell commands. For example, setting `SUFFIX` to `0320; touch injected_suffix.txt` will attempt to execute `touch injected_suffix.txt` after the intended suffix.

- **Impact:**
    - **High:** The impact is similar to the command injection via the `DATASET` variable, allowing for arbitrary command execution with the same potential consequences: data breach, system compromise, and lateral movement.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:** None. The script directly uses the unsanitized `SUFFIX` variable.

- **Missing Mitigations:**
    - Input Sanitization: Sanitize or validate the `SUFFIX` variable to allow only expected characters.
    - Input Validation: Validate if the `SUFFIX` is in an expected format or range if applicable.
    - Parameterization: While less applicable in shell scripts, consider parameterized approaches where feasible in command construction.
    - Principle of Least Privilege: Run the script with minimal privileges.

- **Preconditions:**
    - The attacker needs to be able to modify the `SUFFIX` environment variable before executing `run_inference.sh`.

- **Source Code Analysis:**
    - **File:** `/code/scripts/run_inference.sh`
    - **Line 4:** `SUFFIX=0320` - Default value for `SUFFIX`. Can be overridden by environment variable.
    - **Line 13:** `--output_suffix $SUFFIX` -  The value of the `SUFFIX` variable is passed as an argument to `inference.py`.

    **Vulnerability Flow:**
    ```
    User Input (SUFFIX variable) --> run_inference.sh script --> Command Construction (`python inference.py --output_suffix $SUFFIX`) --> Command Execution (bash shell) --> Command Injection if SUFFIX is malicious
    ```

- **Security Test Case:**
    1. **Precondition:** Access to a system with MRC-Net project and shell script execution capability.
    2. **Step 1:** Navigate to the `/code/scripts` directory.
    3. **Step 2:** Set the `SUFFIX` environment variable with a malicious payload:
        ```bash
        export SUFFIX="0320; touch injected_suffix_file.txt"
        ```
    4. **Step 3:** Execute `run_inference.sh`:
        ```bash
        bash run_inference.sh
        ```
    5. **Step 4:** Check for `injected_suffix_file.txt` in the project directory.