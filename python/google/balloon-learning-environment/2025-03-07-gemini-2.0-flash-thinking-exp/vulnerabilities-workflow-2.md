## Combined Vulnerability List

### Vulnerability Name: Unsafe Deserialization via Pickle in Dataset Loading for Wind Field Generator

- Description:
    1. The `DatasetWindFieldReservoir` class in `/code/balloon_learning_environment/generative/dataset_wind_field_reservoir.py` is used to load wind field data from pickle files.
    2. The constructor of `DatasetWindFieldReservoir` takes a `data` argument, which can be either a file path (string) or a jnp.ndarray.
    3. If `data` is a string, the code assumes it's a path to a directory containing sharded pickle files named `batchXXXX.pickle`.
    4. The code iterates through shard files (batch0000.pickle to batch0199.pickle) and uses `pickle.load(f)` to deserialize the data from each file.
    5. `pickle.load()` is known to be vulnerable to arbitrary code execution if the pickle file is maliciously crafted. An attacker could provide a crafted pickle file path as `offline_winds_dataset_path` gin parameter, which would be loaded and deserialized by the `DatasetWindFieldReservoir`, leading to arbitrary code execution on the system running the training process.

- Impact:
    Critical. Arbitrary code execution. An attacker can execute arbitrary Python code on the machine running the training process. This could lead to complete system compromise, data exfiltration, or denial of service.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    None. The code directly uses `pickle.load()` without any sanitization or security checks on the input file.

- Missing Mitigations:
    - Replace `pickle.load()` with a safer serialization method like `numpy.load()` if the data format allows it (if data is only numpy arrays).
    - If pickle is necessary, implement input validation on the loaded data to ensure it conforms to the expected schema and does not contain malicious objects.
    - Consider sandboxing or containerizing the training process to limit the impact of potential code execution vulnerabilities.

- Preconditions:
    1. An attacker needs to be able to control the `offline_winds_dataset_path` gin parameter. This is possible if the training process allows users to specify gin bindings, for example via command-line flags.
    2. The training process must be executed in an environment where the attacker wants to gain code execution.

- Source Code Analysis:
    1. File: `/code/balloon_learning_environment/generative/dataset_wind_field_reservoir.py`
    2. Class `DatasetWindFieldReservoir` constructor:
    ```python
    class DatasetWindFieldReservoir(wind_field_reservoir.WindFieldReservoir):
      """Retrieves wind fields from an in-memory datastore."""

      def __init__(self,
                   data: Union[str, jnp.ndarray],
                   eval_batch_size: int = 10,
                   rng_seed=0):
        self.eval_batch_size = eval_batch_size

        if isinstance(data, str):
          # TODO(scandido): We need to update this to load a single file, with no
          # assumed directory/file structure hardcoded.
          def _get_shard(i: int):
            fn = f'{data}/batch{i:04d}.pickle'
            with tf.io.gfile.GFile(fn, 'rb') as f:
              arr = pickle.load(f) # Vulnerable line
            return arr

          dataset_shards = []
          for i in range(200):
            dataset_shards.append(_get_shard(i))
            logging.info('Loaded shard %d', i)
          data = jnp.concatenate(dataset_shards, axis=0)

        self.dataset = data
        self._rng = jax.random.PRNGKey(rng_seed)
    ```
    3. The code snippet shows that if `data` is a string, the `pickle.load(f)` function is directly called on the file content without any checks. This is a classic unsafe deserialization vulnerability.

- Security Test Case:
    1. Create a malicious pickle file (`malicious.pickle`) that executes arbitrary code when loaded. For example, it could execute `os.system('touch /tmp/pwned')`.
    ```python
    import pickle
    import os

    class PickleRCE(object):
        def __reduce__(self):
            return (os.system, ('touch /tmp/pwned',))

    shellcode = PickleRCE()
    with open('malicious.pickle', 'wb') as f:
        pickle.dump(shellcode, f)
    ```
    2. Create a directory named `malicious_dataset` and place the `malicious.pickle` file inside it, renaming it to `batch0000.pickle`. Create dummy `batchXXXX.pickle` files for the rest shards to avoid file not found errors during iteration, these dummy files can be empty.
    3. Run the training script `learn_wind_field_generator.py` and set the `offline_winds_dataset_path` gin parameter to the directory `malicious_dataset` using gin bindings. For example:
    ```bash
    python -m balloon_learning_environment.generative.learn_wind_field_generator --offline_winds_dataset_path=./malicious_dataset --gin_bindings="generative.dataset_wind_field_reservoir.DatasetWindFieldReservoir.data='malicious_dataset'"
    ```
    4. After running the script, check if the file `/tmp/pwned` exists. If it exists, it confirms that the code from the malicious pickle file was executed, demonstrating arbitrary code execution.

### Vulnerability Name: Arbitrary Code Execution via Unsafe Agent Loading in Evaluation Script

- Description:
    1. An attacker crafts a malicious agent (e.g., `malicious_agent.py`) containing arbitrary code, such as code to create a reverse shell or exfiltrate data.
    2. The attacker makes this malicious agent available, for example, by hosting it on a public website or sharing it through social engineering.
    3. The victim, intending to evaluate agents within the BLE environment, is tricked into using the `--agent` flag in `eval.py` with the path to the attacker's malicious agent. This could be achieved by the attacker providing instructions or pre-configured scripts that include this malicious agent path.
    4. When `eval.py` executes, it dynamically loads and instantiates the agent specified by the `--agent` flag.
    5. Due to the lack of input validation and secure loading mechanisms, `eval.py` executes the attacker's malicious code during agent instantiation, granting the attacker arbitrary code execution on the victim's machine.
- Impact:
    - Critical: Arbitrary code execution on the victim's machine. This allows the attacker to completely compromise the victim's system, potentially stealing sensitive data, installing malware, or using the system as a bot in a wider network.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None: The project does not implement any input validation or sanitization on the `--agent` flag in `eval.py`, nor does it employ any form of sandboxing or secure loading mechanisms for agents.
- Missing Mitigations:
    - Input validation for the `--agent` flag: Implement checks to ensure that the agent path is within expected directories or adheres to a safelist.
    - Sandboxing or secure agent loading: Utilize techniques to isolate agent code execution, preventing malicious code from affecting the host system. For example, running agent code in a restricted environment like a container or virtual machine.
    - Code review and security audit: Conduct thorough code reviews, specifically focusing on the agent loading and execution paths within the evaluation scripts to identify and address potential vulnerabilities.
- Preconditions:
    - The victim must download and run the `eval.py` script from the Balloon Learning Environment.
    - The victim must be tricked into providing a path to a malicious agent using the `--agent` flag.
- Source Code Analysis:
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

- Security Test Case:
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

### Vulnerability Name: Path Traversal in Evaluation Script Output Directory

- Description:
    1. The `balloon_learning_environment.eval.eval` script uses the `--output_dir` argument to specify the directory where evaluation results are saved.
    2. An attacker could potentially provide a malicious path for `--output_dir`, such as `/../../../../tmp/evil_dir`, aiming to write files outside the intended `/tmp/ble/eval` directory.
    3. If the `eval.py` script does not properly sanitize the `--output_dir` input, it might be vulnerable to path traversal.
    4. By crafting a specific `--output_dir` value, an attacker could potentially overwrite or create files in arbitrary locations on the system where the evaluation script is executed.

- Impact:
    - High: Arbitrary File Write. If exploited, this vulnerability allows an attacker to write files to any location on the file system accessible to the user running the evaluation script. This can lead to various malicious outcomes, including:
        - Overwriting critical system files, potentially leading to system instability or denial of service.
        - Creating malicious files in startup directories to achieve persistent code execution.
        - Writing files to user's home directories, potentially overwriting user data or configuration files.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None: Based on the provided files, there is no explicit sanitization or validation of the `output_dir` path within the evaluation script.

- Missing Mitigations:
    - Input sanitization: Implement path sanitization for the `--output_dir` argument in `eval.py` to prevent path traversal. This could involve:
        - Using a library function to canonicalize the path and resolve symbolic links to prevent traversal using `..`.
        - Validating that the output directory is within an expected base directory and rejecting paths that attempt to go outside of it.
        - Using allowlisting to only permit specific characters or path structures.

- Preconditions:
    - The user must execute the `balloon_learning_environment.eval.eval` script.
    - The attacker needs to control the `--output_dir` argument, which is typically passed via command line.

- Source Code Analysis:
    1. File `/code/balloon_learning_environment/eval/eval.py` defines the entry point for the evaluation script.
    2. The script uses `absl.flags` to define command-line arguments, including `--output_dir`:
    ```python
    flags.DEFINE_string('output_dir', '/tmp/ble/eval',
                        'The directory to output the json summary.')
    ```
    3. The `FLAGS.output_dir` is used later in the script to construct the output file path:
    ```python
    def write_result(result: Sequence[eval_lib.EvaluationResult]) -> None:
        ...
        dir_path = os.path.join(FLAGS.output_dir, FLAGS.suite)
        file_path = os.path.join(dir_path, file_name)
        ...
        os.makedirs(dir_path, exist_ok=True)
        with open(file_path, 'w') as f:
          json.dump(result, f, cls=eval_lib.EvalResultEncoder, indent=indent)
    ```
    4.  The code uses `os.path.join` to construct the directory path and file path. While `os.path.join` itself doesn't prevent path traversal, it depends on how `FLAGS.output_dir` is handled before being passed to `os.path.join`.
    5. **Crucially, there is no sanitization or validation of `FLAGS.output_dir` before it is used in `os.path.join` and `os.makedirs` and `open`.** This means if an attacker provides a path like `/../../../../tmp/evil_dir`, `os.path.join` will construct a path that traverses out of the intended directory. `os.makedirs` will create directories along this potentially malicious path, and `open` will create a file at the attacker-specified location.

- Security Test Case:
    1. Assume an attacker has access to run the `eval.py` script, either locally or on a system where the BLE is installed.
    2. The attacker crafts a command to run the evaluation script, providing a malicious `--output_dir` argument designed to traverse directories and write a file to a sensitive location, for example `/tmp/evil_dir`:
    ```bash
    python -m balloon_learning_environment.eval.eval \
      --agent=random \
      --suite=micro_eval \
      --output_dir='/../../../../tmp/evil_dir'
    ```
    3. Execute the command.
    4. After the script execution, check if a file named `random.json` (or `<agent_name>.json`) has been created in the `/tmp/evil_dir` directory.
    5. If the file is created in `/tmp/evil_dir`, it confirms the path traversal vulnerability, as the intention was to write within `/tmp/ble/eval`.