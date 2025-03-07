### Vulnerability List:

* Vulnerability Name: Command Injection via Model Path in `simulate_codalab.sh`

* Description:
    1. The `simulate_codalab.sh` script in `/code/airdialogue/codalab/` takes a model path as a command-line argument (`$3`, referred to as `$model` in the script).
    2. This `$model` path is directly incorporated into a command execution: `bash $model/scripts/codalab_selfplay_step.sh ...`.
    3. If a malicious user provides a crafted `$model` path, for example, one containing backticks or shell command substitution, it can lead to arbitrary command execution on the server when `simulate_codalab.sh` is run.
    4. For example, a malicious user could provide a `$model` path like `/tmp/evil_model; touch /tmp/pwned`, where `/tmp/evil_model` is a directory they control. When `simulate_codalab.sh` is executed with this path, the shell will first attempt to execute `/tmp/evil_model/scripts/codalab_selfplay_step.sh` and before that, it will execute `touch /tmp/pwned`.

* Impact:
    - **High**. Successful command injection allows an attacker to execute arbitrary commands on the system running `simulate_codalab.sh`.
    - This could lead to:
        - Unauthorized access to sensitive data.
        - Modification or deletion of files.
        - Installation of malware.
        - Full compromise of the system.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - None. The script directly uses the user-provided `$model` path in a command execution without any sanitization or validation.

* Missing Mitigations:
    - **Input validation and sanitization:** The `$model` path should be strictly validated to ensure it conforms to expected patterns and does not contain any shell-executable characters or commands.
    - **Path sanitization:** Use shell built-ins or safer path manipulation methods to construct the path to `codalab_selfplay_step.sh` instead of direct string concatenation.
    - **Principle of least privilege:** Ensure that the script is run with the minimum necessary privileges to reduce the potential damage from a successful command injection.

* Preconditions:
    - The attacker needs to be able to execute the `simulate_codalab.sh` script and control the command-line arguments, specifically the first, second and third arguments which correspond to `$datajson`, `$kbjson`, and `$model`. In a real-world scenario, this might be possible if the `airdialogue` tools are exposed via a web interface or API where users can indirectly trigger this script with controlled inputs.
    - The script `scripts/codalab_selfplay_step.sh` must exist relative to the path provided as `$model`.

* Source Code Analysis:
    ```sh
    File: /code/airdialogue/codalab/simulate_codalab.sh

    ...
    model=$3
    ...
    bash $model/scripts/codalab_selfplay_step.sh $agentout $agentjson $kbjson
    ...
    bash $model/scripts/codalab_selfplay_step.sh $clientout $clientjson
    ...
    bash $model/scripts/codalab_selfplay_step.sh $agentout $agentjson $kbjson
    ...
    ```
    - The vulnerability lies in the lines where `bash $model/scripts/codalab_selfplay_step.sh` is executed.
    - `$model` is directly taken from the third command line argument `$3`.
    - There is no check to validate `$model`.
    - An attacker can set `$model` to a malicious string, such as `$(touch /tmp/pwned)`.
    - When the script reaches the line `bash $model/scripts/codalab_selfplay_step.sh ...`, the shell will interpret `$model` and execute the injected command `touch /tmp/pwned` before attempting to execute the (likely non-existent or malicious) script at the constructed path.

* Security Test Case:
    1. **Prepare a malicious model path:** Create a directory named `evil_model` in `/tmp`. Inside `evil_model`, create a subdirectory named `scripts`. Inside `scripts`, create a file named `codalab_selfplay_step.sh` with the following content:
    ```sh
    #!/bin/bash
    echo "Fake codalab_selfplay_step.sh"
    ```
    Make `codalab_selfplay_step.sh` executable: `chmod +x /tmp/evil_model/scripts/codalab_selfplay_step.sh`.

    2. **Execute `simulate_codalab.sh` with the malicious model path:**
    ```bash
    bash /code/airdialogue/codalab/simulate_codalab.sh data.json kb.json '/tmp/evil_model; touch /tmp/pwned'
    ```
    Note: `data.json` and `kb.json` can be dummy files.

    3. **Verify command execution:** Check if the file `/tmp/pwned` has been created. If the file exists, it confirms that the `touch /tmp/pwned` command injected through the `$model` path was executed.

    **Expected Result:** The file `/tmp/pwned` should be created, demonstrating successful command injection.