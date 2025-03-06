### Vulnerability List

- **Vulnerability Name:** Command Injection in `run_inference.sh` via `DATASET` variable

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

- **Currently Implemented Mitigations:**
    - None. The script directly uses the unsanitized variable in a command execution.

- **Missing Mitigations:**
    - **Input Sanitization:**  The script should sanitize or validate the `DATASET` variable to ensure it only contains expected characters (e.g., alphanumeric and underscores) and prevents command injection.
    - **Input Validation:**  Check if the provided `DATASET` is within an expected list of datasets and reject invalid inputs.
    - **Parameterization:** Use parameterized queries or commands where possible, although this might be less applicable in shell scripting but relevant when constructing commands in Python code.
    - **Principle of Least Privilege:** Run the script with minimal necessary privileges to limit the impact of a successful command injection.

- **Preconditions:**
    - The attacker needs to be able to modify the `DATASET` environment variable before executing the `run_inference.sh` script. This is typically possible if the attacker can execute the script themselves or influence its execution environment.

- **Source Code Analysis:**
    - **File:** `/code/scripts/run_inference.sh`
    - **Line 3:** `DATASET=tless` -  Default value for `DATASET` is set to `tless`. This can be overridden by setting the environment variable `DATASET` before running the script.
    - **Line 4:** `SUFFIX=0320` - Default value for `SUFFIX`. Similar to `DATASET`, this can be overridden.
    - **Line 9:** `python inference.py \` -  Execution of the `inference.py` script.
    - **Line 10:** `--dataset $DATASET \` -  The value of the `DATASET` variable is passed as an argument to `inference.py`.
    - **Line 11:** `--checkpoint_name chkpt_${DATASET} \` - The `DATASET` variable is used to construct the checkpoint directory name.
    - **Line 13:** `--output_suffix $SUFFIX` - The `SUFFIX` variable is passed as an argument.

    **Vulnerability Flow:**
    ```
    User Input (DATASET variable) --> run_inference.sh script --> Command Construction (`python inference.py --dataset $DATASET ...`) --> Command Execution (bash shell) --> Command Injection if DATASET is malicious
    ```
    **Visualization:**
    ```mermaid
    graph LR
        A[User Input: DATASET] --> B(run_inference.sh);
        B --> C{Command Construction};
        C --> D["python inference.py --dataset $DATASET ..."];
        D --> E(bash Shell);
        E -- Malicious DATASET --> F[Command Injection];
        E -- Benign DATASET --> G[Normal Execution];
    ```

- **Security Test Case:**
    1. **Precondition:** Access to a system where MRC-Net project is deployed and the ability to execute shell scripts.
    2. **Step 1:** Open a terminal and navigate to the `/code/scripts` directory of the MRC-Net project.
    3. **Step 2:** Set the `DATASET` environment variable to a malicious payload designed for command injection. For example:
        ```bash
        export DATASET="tless; touch injected_file.txt"
        ```
        This payload attempts to first use `tless` as a dataset name, and then execute the command `touch injected_file.txt` using the shell command separator `;`.
    4. **Step 3:** Execute the `run_inference.sh` script:
        ```bash
        bash run_inference.sh
        ```
    5. **Step 4:** Check for successful command injection. After the script execution, verify if a file named `injected_file.txt` has been created in the project's directory.
    6. **Expected Result:** If the vulnerability exists, the `injected_file.txt` file will be present, indicating that the `touch injected_file.txt` command was successfully executed due to command injection through the `DATASET` variable.

- **Vulnerability Name:** Command Injection in `run_inference.sh` via `SUFFIX` variable

- **Description:**
    1.  Similar to the `DATASET` variable, the `SUFFIX` variable in `run_inference.sh` is also taken as user input (or defaults to `0320`).
    2.  The value of `SUFFIX` is directly used in the `python inference.py` command as argument `--output_suffix $SUFFIX` without sanitization.
    3.  An attacker can manipulate the `SUFFIX` variable to inject shell commands. For example, setting `SUFFIX` to `0320; touch injected_suffix.txt` will attempt to execute `touch injected_suffix.txt` after the intended suffix.

- **Impact:**
    - **High:** The impact is similar to the command injection via the `DATASET` variable, allowing for arbitrary command execution with the same potential consequences: data breach, system compromise, and lateral movement.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - None. The script directly uses the unsanitized `SUFFIX` variable.

- **Missing Mitigations:**
    - **Input Sanitization:** Sanitize or validate the `SUFFIX` variable to allow only expected characters.
    - **Input Validation:** Validate if the `SUFFIX` is in an expected format or range if applicable.
    - **Parameterization:** While less applicable in shell scripts, consider parameterized approaches where feasible in command construction.
    - **Principle of Least Privilege:** Run the script with minimal privileges.

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
    6. **Expected Result:** Presence of `injected_suffix_file.txt` confirms successful command injection via `SUFFIX`.