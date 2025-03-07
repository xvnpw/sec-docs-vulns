### Vulnerability List

- Vulnerability Name: Insecure Deserialization in Agent Restoration
- Description:
    - The Plato toolkit uses Python's `pickle` library to serialize and deserialize reinforcement learning agents for checkpointing and restoring.
    - The `restore_agent_from_pickle` function in `/code/src/platotk/restore.py` directly loads agent state from pickle files using `pickle.load()`.
    - If a malicious actor can replace or modify the checkpoint files (e.g., `algorithm_state.pkl`), they can inject arbitrary Python code into the pickled data.
    - When the `restore_agent_from_pickle` function is called to restore the agent from this tampered checkpoint, the injected code will be executed during deserialization.
    - This can be triggered when deploying a trained agent using the provided deployment examples, as these examples load checkpoints to serve the agent.
- Impact:
    - **Critical**. Arbitrary code execution on the server or machine where the agent is being restored.
    - An attacker could gain full control of the system, steal sensitive data, or disrupt operations.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None. The code directly uses `pickle.load` without any security considerations.
- Missing Mitigations:
    - Replace `pickle` with a secure serialization format like `cloudpickle` with restricted unpickling capabilities or use a safer serialization library altogether (e.g., `safetensors`).
    - Implement integrity checks for checkpoint files (e.g., digital signatures) to ensure they haven't been tampered with.
    - Provide clear warnings in documentation against using untrusted checkpoints.
- Preconditions:
    - A trained agent checkpoint is available.
    - The attacker has the ability to replace or modify the checkpoint files used during agent restoration. This could be through compromising storage, man-in-the-middle attacks during checkpoint download if applicable, or social engineering to get a user to load a malicious checkpoint.
- Source Code Analysis:
    - File: `/code/src/platotk/restore.py`
    ```python
    import pickle
    # ...
    def restore_agent_from_pickle(
        observation_space,
        action_space,
        checkpoint_path,
        name_env="sim_env",
    ):
        """Restore an RLlib agent by unpickling and modifying config."""
        with open(Path(checkpoint_path) / "algorithm_state.pkl", "rb") as fp:
            data = pickle.load(fp) # Insecure deserialization vulnerability here
        # ...
    ```
    - The line `data = pickle.load(fp)` is the point of vulnerability. `pickle.load` deserializes data from the file `algorithm_state.pkl`. If this file is replaced with a malicious pickle file, arbitrary code can be executed when this line is reached.
    - File: `/code/examples/deploy-on-aml/score.py`
    ```python
    from platotk.restore import restore_agent_from_pickle
    # ...
    def init():
        """Initialize the agent from the checkpoints."""
        global model
        # ...
        checkpoint_folder = Path(os.getenv("AZUREML_MODEL_DIR")) / CHECKPOINT_FOLDER
        model = restore_agent_from_pickle( # Vulnerable function call
            observation_space, action_space, checkpoint_folder
        )
        logging.info("Init complete")
    ```
    - The `score.py` script, used for deployment, calls the vulnerable `restore_agent_from_pickle` function during initialization, making the deployed agent vulnerable to insecure deserialization attacks if a malicious checkpoint is used.
- Security Test Case:
    1. **Prepare a malicious pickle file:** Create a Python script to generate a malicious `algorithm_state.pkl` file. This file should contain pickled data that, when deserialized, executes arbitrary code (e.g., create a file in `/tmp/pwned`).
        ```python
        import pickle
        import os

        class MaliciousPayload(object):
            def __reduce__(self):
                return (os.system, ('touch /tmp/pwned',))

        payload = MaliciousPayload()
        with open("algorithm_state.pkl", "wb") as f:
            pickle.dump({'config': None, 'worker': None, 'policy_map': None, '__version__': '2.5.0', 'ray_version': '2.5.0', 'payload': payload}, f)
        ```
    2. **Replace checkpoint file:** In the `/code/examples/deploy-agent/checkpoints/checkpoint_000010` folder (or any checkpoint folder used for deployment), replace the original `algorithm_state.pkl` with the malicious `algorithm_state.pkl` generated in step 1.
    3. **Deploy the agent:** Follow the deployment steps outlined in `/code/examples/deploy-agent/README.md` or `/code/examples/deploy-on-aml/README.md` to deploy the agent using the modified checkpoint.
    4. **Trigger agent execution:** Send a request to the deployed agent endpoint as described in the deployment documentation (e.g., using `curl` or Python requests). This will trigger the `init()` function in `score.py` and subsequently the `restore_agent_from_pickle` function, loading the malicious pickle file.
    5. **Verify code execution:** Check if the arbitrary code was executed. In this test case, verify if the file `/tmp/pwned` was created on the system where the agent is deployed. If the file exists, it confirms successful arbitrary code execution due to insecure deserialization.

- Vulnerability Name: Command Injection in Anylogic Simulation Example
- Description:
    - The example for running Anylogic simulations in `/code/examples/getting-started-anylogic-sim/src/sim.py` uses `subprocess.Popen` to start the Anylogic simulator.
    - The path to the simulator executable is dynamically discovered using `Path(__file__).parent.rglob("*_linux.sh")`.
    - While the script intends to find a specific shell script, if an attacker can place a malicious file ending with `_linux.sh` in the same directory or a parent directory that is searched, this malicious script could be executed instead of the intended Anylogic simulator.
    - Environment variables used for the subprocess, like `SIM_API_HOST`, `SIM_CONTEXT`, `SIM_WORKSPACE`, and `SIM_ACCESS_KEY`, are set based on internal configurations but are generally not user-controlled in this example. However, if these were ever dynamically constructed from user input in a real-world scenario based on this example, it could also lead to command injection.
- Impact:
    - **High**. Arbitrary command execution on the machine running the simulation.
    - An attacker could potentially gain control of the simulation environment or the machine it's running on.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The code directly uses `subprocess.Popen` with a dynamically discovered file path.
- Missing Mitigations:
    - **Hardcode the expected path** to the Anylogic simulator script instead of dynamically discovering it.
    - **Validate the discovered script path** to ensure it's the expected file and location.
    - **Avoid using shell scripts** to launch the simulator if possible. Directly execute the Anylogic simulator if a direct executable is available and controllable.
    - **Sanitize environment variables** if they are ever derived from user inputs in more complex scenarios to prevent injection through environment variables.
- Preconditions:
    - Using the Anylogic simulation example from `/code/examples/getting-started-anylogic-sim`.
    - An attacker can place a malicious file named `something_linux.sh` in the `/code/examples/getting-started-anylogic-sim/src/` directory or a parent directory that would be found by `rglob("*_linux.sh")` *before* the legitimate Anylogic script. File placement might require local access or exploiting another vulnerability to upload files.
- Source Code Analysis:
    - File: `/code/examples/getting-started-anylogic-sim/src/sim.py`
    ```python
    import subprocess
    from pathlib import Path
    # ...
    class SimWrapper(Env):
        # ...
        def start_sim_framework(self):
            """Start Baobab API and external sim."""

            # Find the sim executable
            scripts = [script for script in Path(__file__).parent.rglob("*_linux.sh")] # Vulnerable file discovery
            if len(scripts) > 1:
                raise RuntimeError(f"Too many Anylogic sims found: {scripts}")
            elif len(scripts) < 1:
                raise RuntimeError("No Anylogic sim found.")
            sim_exec = scripts.pop()

            # ...

            # Launch the sim that will connect to Baobab
            penv = {
                "SIM_API_HOST": self.base_url,
                "SIM_CONTEXT": "{}",
                "SIM_WORKSPACE": "dummy",
                "SIM_ACCESS_KEY": "dummy",
            }
            subprocess.Popen([sim_exec], env=penv) # Command execution
            time.sleep(5)
    ```
    - The line `scripts = [script for script in Path(__file__).parent.rglob("*_linux.sh")]` searches for any file ending in `_linux.sh` in the directory and its subdirectories. If a malicious script with this naming convention is placed in an accessible location, it could be picked up.
    - `subprocess.Popen([sim_exec], env=penv)` then executes the discovered `sim_exec` script. If `sim_exec` points to a malicious script, command injection occurs.
- Security Test Case:
    1. **Create a malicious script:** Create a file named `malicious_linux.sh` in the `/code/examples/getting-started-anylogic-sim/src/` directory with the following content:
        ```bash
        #!/bin/bash
        touch /tmp/command_injection_pwned
        ```
        Make it executable: `chmod +x malicious_linux.sh`.
    2. **Run the Anylogic example:** Follow the instructions in `/code/examples/getting-started-anylogic-sim/README.md` to run the example locally or on AML. This will cause `SimWrapper.start_sim_framework()` to execute.
    3. **Verify command execution:** Check if the file `/tmp/command_injection_pwned` was created. If it exists, it indicates that the malicious script `malicious_linux.sh` was executed instead of the intended Anylogic simulator, demonstrating command injection.