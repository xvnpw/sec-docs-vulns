- Vulnerability name: Docker Command Injection via Environment Variable Name
- Description:
    - An attacker can inject arbitrary Docker command-line arguments by controlling the key (name) of the environment variable passed to the `add_environment_variable` method of `CommandSpec` or `ExecSpec`.
    - The `_get_docker_args` function in `src/tugboat/client_interface.py` constructs Docker commands by directly incorporating the environment variable names into the `docker create` or `docker exec` command without proper sanitization or quoting.
    - If an application using the `tugboat` library allows user-controlled input to be used as the environment variable name, an attacker can exploit this vulnerability.
    - For example, by providing an environment variable name like `--rm`, the attacker can inject the `--rm` option into the `docker create` command, causing the created container to be immediately removed after execution.
- Impact:
    - Arbitrary command execution on the Docker host.
    - An attacker could gain control of the Docker host by injecting malicious Docker commands.
    - Potential impacts include unauthorized access to sensitive data, modification of system configurations, denial of service, or complete system takeover, depending on the injected commands and Docker host configuration.
- Vulnerability rank: Critical
- Currently implemented mitigations:
    - None. The code does not perform any sanitization, validation, or encoding of environment variable names before including them in Docker commands.
- Missing mitigations:
    - Input sanitization or validation for environment variable names.
    - Implement proper quoting or escaping of environment variable names when constructing Docker commands to prevent interpretation of injected arguments.
    - Consider restricting allowed characters in environment variable names to a safe subset.
    - Explore using alternative methods to pass environment variables to Docker that are less susceptible to command injection, if available.
- Preconditions:
    - An application must be using the `tugboat` library.
    - The application must allow user-controlled input to be used as the environment variable name when creating a `ContainerSpec` or `ExecSpec` object, specifically when calling `add_environment_variable`.
- Source code analysis:
    - File: `src/tugboat/client_interface.py`
    - Function: `_get_docker_args(spec: CommandSpec)`
    - Vulnerable code snippet:
      ```python
      def _get_docker_args(spec: CommandSpec) -> List[str]:
          docker_args: List[str] = []
          # ... other arguments ...
          for name, value in spec.environment.items():
              if value is not None:
                  docker_args += ["--env", f"{name}={value}"]
              else:
                  docker_args += ["--env", name]
          # ... other arguments ...
          return docker_args
      ```
    - The code iterates through the `spec.environment` dictionary.
    - For each key-value pair, it adds `--env name=value` or `--env name` to the `docker_args` list.
    - The `name` variable, taken directly from the dictionary key (user-provided input), is incorporated into the Docker command without any sanitization or quoting.
    - Visualization:
      ```
      UserInput (env_name) --> spec.add_environment_variable(env_name, value) --> spec.environment (dict) --> _get_docker_args() --> docker_args (list) --> docker command (string) --> process.run/open_() --> docker execution
      ```
- Security test case:
    - Step 1: Prepare test environment with Docker installed.
    - Step 2: Create a Python file named `test_exploit.py` with the following code:
      ```python
      import tugboat
      import subprocess

      spec = tugboat.ContainerSpec(image="busybox")
      spec.add_environment_variable("--rm", "test_value")
      tugboat.run_sync(spec)

      output = subprocess.run(["docker", "ps", "-a"], capture_output=True, text=True)
      print("Docker containers after running tugboat:")
      print(output.stdout)
      ```
    - Step 3: Execute the script from the command line: `python test_exploit.py`
    - Step 4: Analyze the output. The `docker ps -a` output should not list any newly created container from the script, indicating the `--rm` option was injected successfully, and the container was removed immediately after running.
    - Step 5: If a container related to the script execution is listed in the output, the vulnerability is not effectively demonstrated by this test, or the test itself needs review. The expected outcome is the absence of the container in the list, confirming the command injection leading to `--rm` being executed.