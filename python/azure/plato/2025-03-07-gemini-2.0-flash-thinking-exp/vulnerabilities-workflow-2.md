## Combined Vulnerability List

This document outlines critical and high severity vulnerabilities identified in the Plato toolkit. These vulnerabilities could allow for arbitrary code execution and significant security breaches if exploited.

### 1. Insecure Deserialization in Agent Restoration

- **Vulnerability Name:** Insecure Deserialization in Agent Restoration
- **Description:**
    - The Plato toolkit utilizes Python's `pickle` library for serializing and deserializing reinforcement learning agents during checkpointing and restoration processes.
    - The `restore_agent_from_pickle` function, located in `/code/src/platotk/restore.py`, directly loads agent states from pickle files using `pickle.load()`.
    - If a malicious actor gains the ability to replace or modify checkpoint files, such as `algorithm_state.pkl`, they can inject malicious Python code into the pickled data.
    - When the `restore_agent_from_pickle` function is subsequently invoked to restore an agent from a tampered checkpoint, the embedded malicious code will be executed during the deserialization process.
    - This vulnerability can be exploited during the deployment of trained agents using provided deployment examples, as these examples load checkpoints to serve the agent.
- **Impact:**
    - **Critical**. Exploitation leads to arbitrary code execution on the server or machine where the agent is being restored.
    - Successful exploitation can grant an attacker complete control over the affected system, enabling them to steal sensitive data, disrupt operations, or perform other malicious actions.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    - None. The codebase directly employs `pickle.load` without any security measures in place.
- **Missing Mitigations:**
    - Replace the insecure `pickle` library with a secure serialization format. Consider using `cloudpickle` with restricted unpickling capabilities or transitioning to a safer serialization library such as `safetensors`.
    - Implement integrity checks for checkpoint files. Employ digital signatures to ensure the authenticity and integrity of checkpoint files, preventing tampering.
    - Issue clear warnings in the documentation. Explicitly caution users against using checkpoints from untrusted sources due to the inherent risks of insecure deserialization.
- **Preconditions:**
    - A trained agent checkpoint must be available.
    - An attacker must possess the capability to replace or modify the checkpoint files utilized during agent restoration. This could be achieved through various means, including compromising storage systems, man-in-the-middle attacks during checkpoint downloads, or social engineering tactics to induce a user to load a malicious checkpoint.
- **Source Code Analysis:**
    - **File:** `/code/src/platotk/restore.py`
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
    - The vulnerability lies within the line `data = pickle.load(fp)`. `pickle.load` deserializes data from the `algorithm_state.pkl` file. Replacing this file with a malicious pickle file allows for arbitrary code execution when this line is executed.
    - **File:** `/code/examples/deploy-on-aml/score.py`
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
    - The deployment script `score.py` invokes the vulnerable `restore_agent_from_pickle` function during agent initialization. This makes deployed agents susceptible to insecure deserialization if a compromised checkpoint is employed.
- **Security Test Case:**
    1. **Malicious Pickle File Creation:** Generate a malicious `algorithm_state.pkl` file using the following Python script. This script creates a pickle file that, upon deserialization, will execute arbitrary code (specifically, it will create a file named `/tmp/pwned`).
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
    2. **Checkpoint File Replacement:** Navigate to the checkpoint directory, for instance, `/code/examples/deploy-agent/checkpoints/checkpoint_000010`, and replace the original `algorithm_state.pkl` with the malicious file generated in the previous step.
    3. **Agent Deployment:** Follow the deployment instructions in `/code/examples/deploy-agent/README.md` or `/code/examples/deploy-on-aml/README.md` to deploy the agent, ensuring the modified checkpoint is used.
    4. **Trigger Agent Execution:** Send a request to the deployed agent endpoint as described in the deployment documentation (e.g., using `curl` or Python requests). This will trigger the `init()` function in `score.py`, subsequently calling `restore_agent_from_pickle` and loading the malicious pickle file.
    5. **Verification of Code Execution:** Check for the creation of the file `/tmp/pwned` on the system where the agent is deployed. The presence of this file confirms successful arbitrary code execution due to insecure deserialization.

### 2. Command Injection in Anylogic Simulation Example

- **Vulnerability Name:** Command Injection in Anylogic Simulation Example
- **Description:**
    - The Anylogic simulation example, located in `/code/examples/getting-started-anylogic-sim/src/sim.py`, utilizes `subprocess.Popen` to initiate the Anylogic simulator.
    - The path to the simulator executable is dynamically determined using `Path(__file__).parent.rglob("*_linux.sh")`.
    - While the intention is to locate a specific shell script, an attacker could exploit this by placing a malicious file ending with `_linux.sh` in the same directory or a parent directory searched by `rglob("*_linux.sh")`. This malicious script could then be executed instead of the intended Anylogic simulator.
    - Although environment variables used in the subprocess (e.g., `SIM_API_HOST`, `SIM_CONTEXT`, `SIM_WORKSPACE`, `SIM_ACCESS_KEY`) are internally configured and not directly user-controlled in this example, dynamically constructing these from user inputs based on this example in a real-world scenario could also introduce command injection vulnerabilities.
- **Impact:**
    - **High**. Exploitation results in arbitrary command execution on the machine running the simulation.
    - An attacker could potentially compromise the simulation environment or the host machine.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - None. The code directly uses `subprocess.Popen` with a dynamically discovered file path, without any validation or security measures.
- **Missing Mitigations:**
    - **Hardcode the simulator path:** Instead of dynamically discovering the path, hardcode the expected path to the Anylogic simulator script. This eliminates the risk of executing a malicious script from an unexpected location.
    - **Validate discovered script path:** If dynamic discovery is necessary, validate that the discovered script path points to the expected file and location. Implement checks to ensure the script is indeed the legitimate Anylogic simulator.
    - **Avoid shell scripts:** If feasible, avoid using shell scripts to launch the simulator. Directly execute the Anylogic simulator if a direct executable is available and controllable. This reduces the attack surface associated with shell script execution.
    - **Sanitize environment variables:** In more complex scenarios where environment variables are derived from user inputs, rigorously sanitize these variables to prevent injection attacks. Ensure no malicious commands can be injected through environment variable manipulation.
- **Preconditions:**
    - The Anylogic simulation example from `/code/examples/getting-started-anylogic-sim` must be in use.
    - An attacker must be able to place a malicious file named `something_linux.sh` in the `/code/examples/getting-started-anylogic-sim/src/` directory or a parent directory that `rglob("*_linux.sh")` would find before the legitimate Anylogic script. Placing the malicious file may require local access or exploiting another vulnerability to upload files.
- **Source Code Analysis:**
    - **File:** `/code/examples/getting-started-anylogic-sim/src/sim.py`
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
    - The line `scripts = [script for script in Path(__file__).parent.rglob("*_linux.sh")]` is vulnerable because it searches for any file ending in `_linux.sh` within the directory and its subdirectories. If a malicious script with this naming convention is placed in an accessible location, it could be discovered.
    - Subsequently, `subprocess.Popen([sim_exec], env=penv)` executes the discovered `sim_exec` script. If `sim_exec` points to a malicious script, command injection occurs, allowing arbitrary commands to be executed.
- **Security Test Case:**
    1. **Malicious Script Creation:** Create a file named `malicious_linux.sh` in the `/code/examples/getting-started-anylogic-sim/src/` directory. Add the following content to this file:
        ```bash
        #!/bin/bash
        touch /tmp/command_injection_pwned
        ```
        Make the script executable using `chmod +x malicious_linux.sh`.
    2. **Run Anylogic Example:** Execute the Anylogic example as described in `/code/examples/getting-started-anylogic-sim/README.md`, either locally or on AML. This action will lead to the execution of `SimWrapper.start_sim_framework()`.
    3. **Verify Command Execution:** After running the example, check for the existence of the file `/tmp/command_injection_pwned`. If this file is present, it confirms that the malicious script `malicious_linux.sh` was executed instead of the intended Anylogic simulator, thus demonstrating command injection.

### 3. Insecure Deserialization/Input Validation in Custom Simulation Environments

- **Vulnerability Name:** Insecure Deserialization/Input Validation in Custom Simulation Environments
- **Description:**
    - This vulnerability arises from the integration of user-created custom simulation environments with Plato, where insufficient security measures in custom environment development can lead to exploitation.
    - Attackers can exploit vulnerabilities in custom simulation environments that accept external configuration parameters, such as through the `options` argument in the `reset()` method, environment variables, or configuration files.
    - By crafting malicious inputs for these configuration parameters, attackers can target insecure deserialization (e.g., using `pickle.loads`) or inadequate input validation within the custom environment.
    - When Plato trains or assesses an agent, it passes configurations to the custom environment. If the custom environment mishandles these configurations, the malicious input is executed.
    - For instance, if a custom environment uses `pickle.loads` to deserialize a configuration string from the `options` in `reset()` without proper sanitization, a malicious pickled object can be injected, resulting in code execution on the system.
- **Impact:**
    - Remote code execution on the Azure Machine Learning compute cluster or local machine where Plato is running.
    - Potential data exfiltration from the AML workspace or local machine.
    - Compromise of the reinforcement learning training process, potentially leading to poisoned agents or unreliable training outcomes.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - None. Plato toolkit itself does not implement security measures for custom simulation environments. The security of these environments is solely the responsibility of the user developing them.
- **Missing Mitigations:**
    - **Enhanced Documentation and Best Practices:** Improve Plato documentation to explicitly warn users about the security risks associated with integrating custom simulation environments. Provide comprehensive guidelines and best practices for secure development, emphasizing the critical importance of input validation and avoiding insecure deserialization methods.
    - **Input Validation Examples and Helper Functions:** Include illustrative code examples and potentially helper functions within Plato to demonstrate and simplify common input validation tasks within custom environments. Focus on validating data types, ranges, formats, and sanitizing inputs to effectively prevent injection attacks.
    - **Security Scanning and Testing Recommendations:** Advise users to perform thorough security scanning and penetration testing on their custom simulation environments before deploying them with Plato. This proactive approach can help identify and rectify potential vulnerabilities before they can be exploited.
- **Preconditions:**
    - A user must integrate a custom-built simulation environment with the Plato toolkit.
    - The custom environment must be designed to accept external configuration parameters without implementing proper input validation and sanitization.
    - An attacker must be able to control or influence these configuration parameters, possibly through manipulating job configurations or external data sources used by the environment.
- **Source Code Analysis:**
    - The core Plato toolkit code itself does not contain inherent insecure deserialization vulnerabilities.
    - The vulnerability arises from the design and implementation of custom simulation environments by users, where security flaws like insecure deserialization or insufficient input validation can be introduced.
    - For example, a user might modify the `reset()` method in their custom environment (similar to the example in `examples/custom-assessments/src/sim.py`) to process configurations from the `options` argument using insecure functions like `pickle.loads` without proper input sanitization.
    - Plato's design philosophy prioritizes flexibility, enabling the integration of diverse Python environments. However, this flexibility places the onus of security on the users of the toolkit to ensure the security of their custom components.
- **Security Test Case:**
    1. **Malicious Pickled Object Generation:** Create a malicious pickled object designed to execute arbitrary code upon deserialization. For a simplified test, this code will create a file in the `/tmp` directory:
    ```python
    import pickle
    import os

    malicious_code = lambda: os.system('touch /tmp/plato_pwned') # Simplified malicious payload
    malicious_object = pickle.dumps(malicious_code)
    ```
    2. **Modify Custom Environment for Insecure Deserialization:** Edit the `reset()` method in the example custom simulation environment (`examples/custom-assessments/src/sim.py`) to incorporate insecure deserialization of configuration data from the `options` argument:
    ```python
    def reset(self, *, seed: Optional[dict] = None, options: Optional[dict] = None):
        self.iter = 0
        if options is not None and options.get("config_string") is not None:
            import pickle
            config_data = pickle.loads(options["config_string"]) # Insecure deserialization
            config_data() # Execute malicious code from deserialized object
            self.state = {"value": np.random.randint(0, 100)}
        elif options is None or options.get("value") is None:
            self.state = {"value": np.random.randint(0, 100)}
        else:
            self.state = {"value": options["value"]}
        return self._get_obs(), self._get_info()
    ```
    3. **Inject Malicious Payload in `main.py`:** Modify the `run_episodes` function in `examples/custom-assessments/src/main.py` to inject the malicious pickled object as a configuration parameter within the `initial_conditions`:
    ```python
    initial_conditions = [{"value": 10}, {"config_string": malicious_object}] # Inject malicious payload
    ```
    4. **Execute `main.py`:** Run `examples/custom-assessments/src/main.py` locally using the `--test-local` flag: `python main.py --test-local`.
    5. **Verify Code Execution:** After execution, check if the file `/tmp/plato_pwned` exists. If this file has been created, it confirms successful code execution due to insecure deserialization within the custom simulation environment, demonstrating the vulnerability. This test validates the risk associated with user-implemented custom environments and highlights the importance of secure coding practices when integrating with Plato.

### 4. Arbitrary Code Execution via Malicious Custom Simulation Environment

- **Vulnerability Name:** Arbitrary Code Execution via Malicious Custom Simulation Environment
- **Description:**
    - Users can integrate custom simulation environments with Plato for reinforcement learning tasks on Azure ML, providing flexibility but also introducing security risks if malicious environments are used.
    - An attacker can create a malicious custom simulation environment containing arbitrary code, and if a user unknowingly uses this environment with Plato, the malicious code will be executed within the Azure ML environment during a training job.
    - **Step-by-step trigger:**
        1.  An attacker develops a malicious custom simulation environment (e.g., a Python script) that includes code designed to perform malicious actions, such as data exfiltration or system command execution.
        2.  The attacker makes this malicious environment accessible to potential Plato users, perhaps through a public repository or via social engineering tactics.
        3.  An unsuspecting user downloads or obtains the malicious custom simulation environment.
        4.  The user integrates the malicious environment into their Plato project, following the project's documentation for custom environment integration (e.g., as shown in `examples/getting-started-on-aml`).
        5.  The user configures and initiates a reinforcement learning training job on Azure ML using Plato, which loads and utilizes the integrated malicious simulation environment.
        6.  During the initialization or execution phase of the simulation environment within the Azure ML compute environment, the malicious code embedded in the environment is executed, potentially compromising the system.
- **Impact:** Arbitrary code execution on the user's Azure ML environment. This can have severe consequences:
    - Data exfiltration from the Azure ML workspace or connected data resources.
    - Unauthorized access to and manipulation of other Azure resources.
    - Denial of Service (DoS) attacks targeting Azure ML resources.
    - Lateral movement within the user's Azure infrastructure if credentials are compromised, potentially leading to broader security breaches.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:** None. The system currently lacks any built-in mitigations to prevent the execution of malicious code within custom simulation environments.
- **Missing Mitigations:**
    - **Input validation for custom simulation environments:** Implement mechanisms to validate custom simulation environments to detect and prevent the execution of malicious code. This is technically challenging for general-purpose code but could involve static analysis or sandboxing techniques.
    - **Sandboxing or isolation of custom simulation environments:** Enforce sandboxing or isolation for custom simulation environments during execution to limit the potential impact of malicious code. This would require significant architectural changes to containerize or isolate environment execution.
    - **Clear and prominent documentation warnings:** Provide clear and prominent warnings in the documentation about the risks of using untrusted custom simulation environments. Strongly advise users to only use environments from trusted sources and to meticulously review the code of any custom environment before integration.
- **Preconditions:**
    - An attacker must be able to provide or convince a user to utilize a malicious custom simulation environment. This could be achieved through social engineering, by hosting the malicious environment in a seemingly legitimate repository, or by compromising a trusted source.
    - The user must integrate the malicious environment into their Plato project and subsequently run a training job on Azure ML, which will trigger the execution of the environment's code.
- **Source Code Analysis:**
    - Project examples such as `examples/getting-started-on-aml`, `examples/getting-started-anylogic-sim`, `examples/curriculum-learning`, and `examples/custom-assessments` demonstrate the standard process of integrating custom simulation environments within Plato.
    - The `register_env` function from `ray.tune.registry` is used to register these custom environments, making them available for use with RLlib algorithms during training and assessment.
    - When a training job is initiated, Plato and Ray RLlib load and instantiate the registered environment, which inherently executes any code present within the environment's Python files or related components (e.g., Anylogic simulations).
    - Currently, there is no built-in mechanism within Plato to validate, inspect, or restrict the code execution of these custom environments. The system implicitly trusts the code provided by the user as the simulation environment.
    - **Example code snippet from `examples/getting-started-on-aml/src/main.py`:**
    ```python
    from ray.tune.registry import register_env
    from sim import SimpleAdder as SimEnv # User-provided simulation environment

    # Register the simulation as an RLlib environment.
    register_env("sim_env", lambda config: SimEnv(config))
    ```
    - This code directly registers and utilizes the `SimEnv` class, which is defined in a user-provided file (`sim.py`). If `sim.py` contains malicious code, this code will be executed whenever the environment is instantiated during the training process.
- **Security Test Case:**
    1. **Malicious Simulation Environment Creation:** Create a malicious simulation environment file (e.g., `malicious_sim.py`) containing code that executes a system command upon initialization. For this example, the malicious code will create a file in `/tmp`:
        ```python
        # malicious_sim.py
        import os
        from gymnasium import Env
        from gymnasium.spaces import Discrete

        class MaliciousSim(Env):
            def __init__(self, env_config):
                super().__init__()
                self.action_space = Discrete(2)
                self.observation_space = Discrete(2)
                # Malicious code: create a file in /tmp as an example
                os.system('touch /tmp/pwned_by_plato.txt')
                print("Malicious code executed during init!")

            def step(self, action):
                return 0, 0, True, False, {}

            def reset(self, *, seed=None, options=None):
                return 0, {}
        ```
    2. **Environment File Replacement and Modification:** Replace the `sim.py` file in `examples/getting-started-on-aml/src/` with the newly created `malicious_sim.py`. Modify `examples/getting-started-on-aml/src/main.py` to import and use `MaliciousSim` instead of `SimpleAdder`:
        ```python
        # examples/getting-started-on-aml/src/main.py
        from ray.tune.registry import register_env
        from ray_on_aml.core import Ray_On_AML
        from malicious_sim import MaliciousSim  # Import malicious environment

        # Register the malicious simulation as an RLlib environment.
        register_env("sim_env", lambda config: MaliciousSim(config)) # Use MaliciousSim
        ```
    3. **Run Training Job on Azure ML:** Execute the training job on Azure ML using the modified `examples/getting-started-on-aml` example, following the instructions provided in `examples/getting-started-on-aml/README.md`:
        ```bash
        az ml job create -f job.yml --workspace-name $YOUR_WORKSPACE --resource-group $YOUR_RESOURCE_GROUP
        ```
    4. **Verification of Code Execution:** After the job starts running, access the Azure ML compute instance where the job is executing (if possible and permissions allow) or examine the job logs for output from the malicious code (specifically, look for the "Malicious code executed during init!" print statement). Check for the creation of the file `/tmp/pwned_by_plato.txt` on the compute instance.
    5. **Confirmation of Vulnerability:** Successful creation of `/tmp/pwned_by_plato.txt` or the observation of malicious code execution in the job logs definitively confirms the arbitrary code execution vulnerability. This demonstrates that malicious code embedded within a custom simulation environment can be executed within the Azure ML environment when a Plato training job is run.