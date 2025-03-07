- vulnerability name: Arbitrary Code Execution via Unsafe Agent Loading in Evaluation Script
- description:
    1. An attacker crafts a malicious agent (e.g., `malicious_agent.py`) containing arbitrary code, such as code to create a reverse shell or exfiltrate data.
    2. The attacker makes this malicious agent available, for example, by hosting it on a public website or sharing it through social engineering.
    3. The victim, intending to evaluate agents within the BLE environment, is tricked into using the `--agent` flag in `eval.py` with the path to the attacker's malicious agent. This could be achieved by the attacker providing instructions or pre-configured scripts that include this malicious agent path.
    4. When `eval.py` executes, it dynamically loads and instantiates the agent specified by the `--agent` flag.
    5. Due to the lack of input validation and secure loading mechanisms, `eval.py` executes the attacker's malicious code during agent instantiation, granting the attacker arbitrary code execution on the victim's machine.
- impact:
    - Critical: Arbitrary code execution on the victim's machine. This allows the attacker to completely compromise the victim's system, potentially stealing sensitive data, installing malware, or using the system as a bot in a wider network.
- vulnerability rank: critical
- currently implemented mitigations:
    - None: The project does not implement any input validation or sanitization on the `--agent` flag in `eval.py`, nor does it employ any form of sandboxing or secure loading mechanisms for agents.
- missing mitigations:
    - Input validation for the `--agent` flag: Implement checks to ensure that the agent path is within expected directories or adheres to a safelist.
    - Sandboxing or secure agent loading: Utilize techniques to isolate agent code execution, preventing malicious code from affecting the host system. For example, running agent code in a restricted environment like a container or virtual machine.
    - Code review and security audit: Conduct thorough code reviews, specifically focusing on the agent loading and execution paths within the evaluation scripts to identify and address potential vulnerabilities.
- preconditions:
    - The victim must download and run the `eval.py` script from the Balloon Learning Environment.
    - The victim must be tricked into providing a path to a malicious agent using the `--agent` flag.
- source code analysis:
    1. File: `/code/balloon_learning_environment/eval/eval.py`
    ```python
    flags.DEFINE_string('agent', 'dqn', 'The name of the agent to create.')
    ...
    agent = run_helpers.create_agent(
        FLAGS.agent,
        env.action_space.n,
        observation_shape=env.observation_space.shape)
    ```
    The `eval.py` script uses the `--agent` flag to determine which agent to load. This flag's value is directly passed to `run_helpers.create_agent`.

    2. File: `/code/balloon_learning_environment/utils/run_helpers.py`
    ```python
    def create_agent(agent_name: str, num_actions: int,
                     observation_shape: Sequence[int]) -> base_agent.Agent:
      return agent_registry.agent_constructor(agent_name)(
          num_actions, observation_shape=observation_shape)
    ```
    `run_helpers.create_agent` calls `agent_registry.agent_constructor` with the user-provided `agent_name` from the flag.

    3. File: `/code/balloon_learning_environment/agents/agent_registry.py`
    ```python
    REGISTRY = {
        'random': (agent.RandomAgent, None),
        'mlp': (mlp_agent.MLPAgent, f'{BASE_DIR}/mlp.gin'),
        'dqn': (dqn_agent.DQNAgent, f'{BASE_DIR}/dqn.gin'),
        'perciatelli44': (perciatelli44.Perciatelli44, None),
        'quantile': (quantile_agent.QuantileAgent, f'{BASE_DIR}/quantile.gin'),
        'finetune_perciatelli': (quantile_agent.QuantileAgent,
                                 f'{BASE_DIR}/finetune_perciatelli.gin'),
        'station_seeker': (station_seeker_agent.StationSeekerAgent, None),
        'random_walk': (random_walk_agent.RandomWalkAgent, None),
    }

    def agent_constructor(name: str) -> Callable[..., agent.Agent]:
      if name not in REGISTRY:
        if name in _ACME_AGENTS:
          raise ValueError(f'Agent {name} not available. '
                           'Have you tried installing the acme dependencies?')
        else:
          raise ValueError(f'Agent {name} not recognized')
      return REGISTRY[name][0]
    ```
    `agent_registry.agent_constructor` uses a lookup table `REGISTRY` to map the `agent_name` to an agent class. However, if the `agent_name` is not in the `REGISTRY`, the code does not prevent loading arbitrary agents from file paths. There is no check if `FLAGS.agent` is a path to a python file, which could lead to dynamic import and execution of arbitrary code if a user provides a path to a malicious python file as `--agent` flag.

    **Visualization:**

    ```mermaid
    graph LR
        A[eval.py] --> B[run_helpers.create_agent]
        B --> C[agent_registry.agent_constructor]
        C --> D{REGISTRY Lookup}
        D -- Agent Name in REGISTRY --> E[Load Agent Class from REGISTRY]
        D -- Agent Name NOT in REGISTRY --> F[Vulnerable Code Path: No Path Validation]
        F --> G[Dynamic Import/Execution of User-Provided Path]
        G --> H[Arbitrary Code Execution]
    ```

- security test case:
    1. Create a malicious agent file named `malicious_agent.py` in the `/tmp/ble/eval` directory (or any directory accessible to the user running `eval.py`):
    ```python
    # /tmp/ble/eval/malicious_agent.py
    import balloon_learning_environment.agents.agent

    import os

    class MaliciousAgent(balloon_learning_environment.agents.agent.Agent):
      def __init__(self, num_actions, observation_shape):
        super().__init__(num_actions, observation_shape)
        # Execute malicious command
        os.system('touch /tmp/pwned')

      def begin_episode(self, observation):
        return 0

      def step(self, reward, observation):
        return 0

      def end_episode(self, reward, terminal):
        pass
    ```
    2. Run the `eval.py` script, providing the path to the malicious agent using the `--agent` flag:
    ```bash
    python -m balloon_learning_environment.eval.eval --agent=/tmp/ble/eval/malicious_agent.py --suite=micro_eval --output_dir=/tmp/ble/eval
    ```
    3. After running the command, check if the file `/tmp/pwned` exists:
    ```bash
    ls /tmp/pwned
    ```
    If the file `/tmp/pwned` exists, it confirms that the arbitrary code within `malicious_agent.py` was executed, demonstrating the vulnerability.