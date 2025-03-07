### Vulnerability List

* Vulnerability Name: Deserialization of Untrusted Data via Pickle in Agent Restoration

* Description:
    1. The `restore_agent_from_pickle` function in `/code/src/platotk/restore.py` is used to restore reinforcement learning agents from checkpoint files.
    2. This function uses the `pickle.load()` method in Python to deserialize the `algorithm_state.pkl` file located within the provided checkpoint path.
    3. Pickle is known to be insecure when handling untrusted data because it can execute arbitrary code during deserialization.
    4. If an attacker can replace the legitimate `algorithm_state.pkl` file with a malicious one, the `restore_agent_from_pickle` function will execute arbitrary code when loading the agent.
    5. In the context of Plato toolkit, a user provides a custom simulation environment and potentially related configurations, which could include specifying or influencing the checkpoint path for agent loading in deployment scenarios or custom assessments. This allows a malicious user to inject a compromised checkpoint.
    6. When the Plato toolkit attempts to load the agent using the compromised checkpoint, the malicious pickle file is deserialized, leading to arbitrary code execution on the Azure Machine Learning compute instance.

* Impact:
    - **Critical**: Arbitrary code execution on the Azure Machine Learning compute instance.
    - An attacker can gain complete control over the AML compute instance.
    - Potential data exfiltration from the AML workspace.
    - Potential unauthorized access to other Azure services if the AML instance has sufficient permissions.
    - Compromise of the reinforcement learning training process and results.

* Vulnerability Rank: Critical

* Currently Implemented Mitigations:
    - None. The code directly uses `pickle.load()` without any security considerations.

* Missing Mitigations:
    - **Replace Pickle with a Secure Serialization Format**: Use a safer serialization format like `safetensors` or JSON for storing agent states and configurations. These formats do not allow arbitrary code execution during deserialization.
    - **Input Validation and Sanitization**: If pickle must be used, implement strict validation of the checkpoint files and their contents before deserialization. However, this is complex and generally not recommended for mitigating pickle vulnerabilities.
    - **Principle of Least Privilege**: Ensure that the AML compute instances running Plato toolkit have the minimum necessary permissions to reduce the impact of potential compromise.
    - **User Education**: Clearly document the security risks associated with using custom simulation environments and loading checkpoints from untrusted sources. Warn users against using checkpoints from unknown or untrusted origins.

* Preconditions:
    1. An attacker needs to be able to replace the `algorithm_state.pkl` file in a checkpoint directory that will be used by the Plato toolkit to restore an agent.
    2. The Plato toolkit must be configured to load the agent from this attacker-controlled checkpoint directory. This could happen in deployment scenarios using `score.py` or in custom assessment scenarios using `main.py` from `custom-assessments` example.

* Source Code Analysis:
    1. **File:** `/code/src/platotk/restore.py`
    2. **Function:** `restore_agent_from_pickle(observation_space, action_space, checkpoint_path, name_env="sim_env")`
    3. **Vulnerable Code:**
    ```python
    with open(Path(checkpoint_path) / "algorithm_state.pkl", "rb") as fp:
        data = pickle.load(fp) # Vulnerable line: Deserialization of pickle data
    ```
    4. **Explanation:**
        - The function takes `checkpoint_path` as input, which specifies the directory containing the agent's checkpoint files.
        - It constructs the path to `algorithm_state.pkl` by joining `checkpoint_path` and `"algorithm_state.pkl"`.
        - It opens `algorithm_state.pkl` in read binary mode (`"rb"`) and loads the pickled data using `pickle.load(fp)`.
        - **Vulnerability**: `pickle.load()` deserializes the data from the file. If this file is replaced with a malicious pickle file, `pickle.load()` will execute arbitrary code embedded in the malicious file.
    5. **Attack Vector Visualization:**
    ```mermaid
    graph LR
        A[Attacker provides malicious algorithm_state.pkl] --> B(Replaces legitimate algorithm_state.pkl in Checkpoint);
        B --> C[Plato Toolkit (restore_agent_from_pickle)];
        C --> D{pickle.load()};
        D --> E[Arbitrary Code Execution on AML Compute];
    ```

* Security Test Case:
    1. **Prerequisites:**
        - Access to an environment where Plato toolkit can be executed (e.g., a local development environment or an Azure ML compute instance).
        - Ability to modify files in a checkpoint directory used by Plato toolkit.
    2. **Steps:**
        - **Step 1: Create a malicious pickle file.**
            - Create a Python file (e.g., `malicious_payload.py`) with the following content to generate a malicious pickle payload:
            ```python
            import pickle
            import os

            class MaliciousClass:
                def __reduce__(self):
                    return (os.system, ('touch /tmp/pwned',)) # Malicious command: creates file /tmp/pwned

            payload = MaliciousClass()
            pickle.dump(payload, open('algorithm_state.pkl', 'wb'))
            ```
            - Run this Python file to generate `algorithm_state.pkl` in the current directory. This file now contains a malicious payload that will execute `touch /tmp/pwned` when deserialized.
        - **Step 2: Prepare a checkpoint directory.**
            - Choose any example in the `examples` directory (e.g., `getting-started-on-aml`).
            - Train the agent locally or on AML to generate a checkpoint in the `outputs` directory (or download an existing checkpoint). Let's assume the checkpoint directory is `examples/getting-started-on-aml/checkpoints/checkpoint_000010`.
        - **Step 3: Replace the legitimate `algorithm_state.pkl` with the malicious one.**
            - Navigate to the checkpoint directory: `examples/getting-started-on-aml/checkpoints/checkpoint_000010`.
            - Replace the existing `algorithm_state.pkl` with the malicious `algorithm_state.pkl` created in Step 1.
        - **Step 4: Modify `score.py` (or another script that uses `restore_agent_from_pickle`).**
            - If testing with `score.py` from `examples/deploy-agent`, ensure that `CHECKPOINT_FOLDER` in `score.py` is set to `"checkpoint_000010"` (or the name of your modified checkpoint folder).
        - **Step 5: Run the `score.py` script (or your modified script).**
            - Execute the `score.py` script. For local testing, you might need to set up the environment as described in the `deploy-agent` example README.
        - **Step 6: Verify code execution.**
            - After running `score.py`, check if the file `/tmp/pwned` has been created on the system where `score.py` was executed. The existence of this file confirms that the malicious code within the pickle file was executed during deserialization by `pickle.load()`.