- Vulnerability name: Insecure Deserialization/Input Validation in Custom Simulation Environments
- Description:
    - An attacker exploits a vulnerability in a user-created custom simulation environment integrated with Plato.
    - The custom environment accepts external configuration parameters, for example, via the `options` argument in the `reset()` method, environment variables, or configuration files.
    - The attacker crafts a malicious input for these configuration parameters. This input is designed to exploit insecure deserialization (e.g., using `pickle.loads`) or insufficient input validation in the custom environment.
    - When Plato trains or assesses an agent, it passes configurations to the custom environment. If the custom environment mishandles these configurations, the malicious input gets executed.
    - For example, if the custom environment uses `pickle.loads` without sanitization to deserialize a configuration string from the `options` in `reset()`, a malicious pickled object could be provided, leading to code execution.
- Impact:
    - Remote code execution on the Azure Machine Learning compute cluster or local machine.
    - Data exfiltration from the AML workspace or local machine.
    - Compromise of the reinforcement learning training process, leading to poisoned agents or unreliable results.
- Vulnerability rank: High
- Currently implemented mitigations:
    - None. Plato toolkit itself does not enforce security measures on custom simulation environments, as their security is the responsibility of the user developing them.
- Missing mitigations:
    - **Documentation and best practices:**  Enhance Plato documentation to explicitly warn users about the security risks of integrating custom simulation environments. Provide comprehensive guidelines and best practices for secure development, emphasizing input validation and avoidance of insecure deserialization practices.
    - **Input validation examples and helper functions:** Include example code snippets and potentially helper functions in Plato to demonstrate and facilitate common input validation tasks within custom environments. Focus on validating data types, ranges, formats, and sanitizing inputs to prevent injection attacks.
    - **Security scanning and testing recommendations:** Advise users to conduct security scanning and penetration testing on their custom simulation environments before deploying them with Plato, to identify and rectify potential vulnerabilities.
- Preconditions:
    - A user must integrate a custom-built simulation environment with the Plato toolkit.
    - The custom environment must be designed to accept external configuration parameters without proper input validation and sanitization.
    - An attacker needs to be able to control or influence these configuration parameters, possibly through job configurations or external data sources used by the environment.
- Source code analysis:
    - The core Plato toolkit code does not contain inherent insecure deserialization vulnerabilities.
    - The risk stems from the design of custom simulation environments by users, where vulnerabilities like insecure deserialization or insufficient input validation can be introduced.
    - For instance, a user might modify the `reset()` method of their custom environment (similar to the example in `examples/custom-assessments/src/sim.py`) to process configurations from the `options` argument using insecure functions like `pickle.loads` without proper input sanitization.
    - Plato's design prioritizes flexibility, allowing integration of arbitrary Python environments, but this places the burden of security on the users of the toolkit to secure their custom components.
- Security test case:
    1. Generate a malicious pickled object designed to execute arbitrary code upon deserialization. For a simplified test, this could be a command to create a file in the `/tmp` directory:
    ```python
    import pickle
    import os

    malicious_code = lambda: os.system('touch /tmp/plato_pwned') # Simplified malicious payload
    malicious_object = pickle.dumps(malicious_code)
    ```
    2. Modify the `reset()` method in the example custom simulation environment (`examples/custom-assessments/src/sim.py`) to include insecure deserialization of configuration data from the `options` argument:
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
    3. Modify the `run_episodes` function in `examples/custom-assessments/src/main.py` to inject the malicious pickled object as a configuration parameter within the `initial_conditions`:
    ```python
    initial_conditions = [{"value": 10}, {"config_string": malicious_object}] # Inject malicious payload
    ```
    4. Execute `examples/custom-assessments/src/main.py` locally using the `--test-local` flag: `python main.py --test-local`.
    5. After execution, check for the existence of the file `/tmp/plato_pwned`. If this file is created, it confirms successful code execution due to insecure deserialization within the custom simulation environment, demonstrating the vulnerability. This test case validates the risk associated with user-implemented custom environments and the importance of secure coding practices when integrating with Plato.