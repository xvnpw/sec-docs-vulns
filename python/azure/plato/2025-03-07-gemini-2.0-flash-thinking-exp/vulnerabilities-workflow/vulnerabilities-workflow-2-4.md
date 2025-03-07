### Vulnerability List

- Vulnerability Name: Arbitrary Code Execution via Malicious Custom Simulation Environment
- Description:
    - A user can integrate a custom simulation environment with Plato for reinforcement learning tasks on Azure ML.
    - An attacker can craft a malicious custom simulation environment containing arbitrary code.
    - When a user uses this malicious environment with Plato and runs a training job on Azure ML, the malicious code is executed within the Azure ML environment.
    - Step-by-step trigger:
        1.  Attacker creates a malicious custom simulation environment (e.g., Python script). This environment contains code designed to perform malicious actions like data exfiltration or system command execution.
        2.  Attacker makes the malicious environment available to potential Plato users (e.g., via a public repository or social engineering).
        3.  Unsuspecting user downloads or obtains the malicious custom simulation environment.
        4.  User integrates the malicious environment into their Plato project, following the project's documentation for custom environment integration (e.g., as shown in `examples/getting-started-on-aml`).
        5.  User configures and runs a reinforcement learning training job on Azure ML using Plato, which loads and utilizes the integrated malicious simulation environment.
        6.  During the initialization or execution of the simulation environment within the Azure ML compute environment, the malicious code embedded in the environment is executed.
- Impact: Arbitrary code execution on the user's Azure ML environment. This can lead to:
    - Data exfiltration from the Azure ML workspace or connected resources.
    - Unauthorized access and manipulation of Azure resources.
    - Denial of Service (DoS) attacks against Azure ML resources.
    - Lateral movement within the user's Azure infrastructure if credentials are compromised.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations: None
- Missing Mitigations:
    - Input validation for custom simulation environments to detect and prevent malicious code. (Technically challenging for general code)
    - Sandboxing or isolation of custom simulation environments during execution to limit the impact of potentially malicious code. (Significant architectural change)
    - Clear and prominent documentation warning users about the risks of using untrusted custom simulation environments and advising them to only use environments from trusted sources and to review the code.
- Preconditions:
    - Attacker must be able to provide or convince a user to use a malicious custom simulation environment.
    - User must integrate the malicious environment into Plato and run a training job on Azure ML.
- Source Code Analysis:
    - The project examples (`examples/getting-started-on-aml`, `examples/getting-started-anylogic-sim`, `examples/curriculum-learning`, `examples/custom-assessments`) demonstrate the process of integrating custom simulation environments.
    - The `register_env` function from `ray.tune.registry` is used to register these custom environments, making them available for use with RLlib algorithms.
    - When a training job is launched, Plato and Ray RLlib load and instantiate the registered environment, executing any code within the environment's Python files or related components (e.g., Anylogic simulations).
    - There is no mechanism within Plato to validate, inspect, or restrict the code execution of these custom environments. The system inherently trusts the code provided by the user as the simulation environment.
    - Example code snippet from `examples/getting-started-on-aml/src/main.py`:
    ```python
    from ray.tune.registry import register_env
    from sim import SimpleAdder as SimEnv # User-provided simulation environment

    # Register the simulation as an RLlib environment.
    register_env("sim_env", lambda config: SimEnv(config))
    ```
    - This code directly registers and uses the `SimEnv` class, which is defined in a user-provided file (`sim.py`). If `sim.py` contains malicious code, it will be executed when the environment is instantiated during training.

- Security Test Case:
    - Step 1: Create a malicious simulation environment file (e.g., `malicious_sim.py`) with code that executes a system command upon initialization:
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
    - Step 2: Replace the `sim.py` file in `examples/getting-started-on-aml/src/` with `malicious_sim.py`. Modify `examples/getting-started-on-aml/src/main.py` to import and use `MaliciousSim`:
        ```python
        # examples/getting-started-on-aml/src/main.py
        from ray.tune.registry import register_env
        from ray_on_aml.core import Ray_On_AML
        from malicious_sim import MaliciousSim  # Import malicious environment

        # Register the malicious simulation as an RLlib environment.
        register_env("sim_env", lambda config: MaliciousSim(config)) # Use MaliciousSim
        ```
    - Step 3: Run the training job on Azure ML using the modified `examples/getting-started-on-aml` example, following the instructions in `examples/getting-started-on-aml/README.md`.
        ```bash
        az ml job create -f job.yml --workspace-name $YOUR_WORKSPACE --resource-group $YOUR_RESOURCE_GROUP
        ```
    - Step 4: After the job starts running, access the Azure ML compute instance where the job is running (if possible and permissions allow) or check the job logs for output from the malicious code (e.g., the "Malicious code executed during init!" print statement). Verify if the file `/tmp/pwned_by_plato.txt` has been created on the compute instance.
    - Step 5: Successful creation of `/tmp/pwned_by_plato.txt` or observation of malicious code execution in logs confirms arbitrary code execution vulnerability.