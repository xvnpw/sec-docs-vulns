### Vulnerability List

- Vulnerability Name: Command Injection via Container Specification Parameters

- Description:
    - An attacker can inject malicious commands into the Docker command line by manipulating parameters within the `ContainerSpec` or `ExecSpec` if user-provided input is used to define these specifications.
    - Step 1: An application using the Tugboat library allows users to provide input that is used to construct a `ContainerSpec` or `ExecSpec`. This input could be for parameters like `image` name, `args`, `entrypoint`, `extra_docker_args`, `environment` variables, `bind_mounts`, or `published_ports`.
    - Step 2: The Tugboat library uses these specifications to construct Docker commands using functions like `create` and `exec_` in `client_interface.py`.
    - Step 3:  Specifically, the `create` function in `client_interface.py` directly incorporates the `image` and `args` attributes of `ContainerSpec` into the `docker create` command. Similarly, the `exec_` function incorporates `args` and `extra_docker_args` from `ExecSpec` into the `docker exec` command. The `_get_docker_args` function in `client_interface.py` also directly includes `extra_docker_args` without sanitization.
    - Step 4: If the user-provided input is not properly sanitized or validated before being used in these parameters, an attacker can inject arbitrary Docker commands or even host system commands by crafting malicious input.
    - Step 5: When Tugboat executes these Docker commands using `process.run` or `process.run_sync`, the injected commands will be executed by the Docker daemon.

- Impact:
    - **High**: Successful command injection can lead to:
        - **Unauthorized Container Execution**: An attacker can control the execution of Docker containers, potentially running containers with malicious images or configurations.
        - **Container Escape and Host System Compromise**: In certain scenarios, especially with misconfigured Docker setups or through techniques like bind mount abuse, an attacker might be able to escape the container and compromise the host system.
        - **Data Exfiltration or Manipulation**: Attackers could use injected commands to access sensitive data within the container or on the host, or to modify data and system configurations.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None: The code does not implement any input validation or sanitization for parameters in `ContainerSpec` or `ExecSpec` that are used to construct Docker commands. The `_get_docker_args` function in `client_interface.py` quotes some arguments for `--env` and `--workdir`, but this is not sufficient to prevent command injection through other parameters like `image`, `args`, or `extra_docker_args`.

- Missing Mitigations:
    - **Input Validation and Sanitization**: Implement strict validation and sanitization of all user-provided inputs that are used to construct `ContainerSpec` and `ExecSpec`. This should include:
        - **Image Name Validation**: Validate that the image name conforms to expected formats and does not contain malicious characters or commands. Consider using a whitelist of allowed image repositories or a strict regex to validate image names.
        - **Argument Sanitization**: Sanitize container `args` and `extra_docker_args` to prevent command injection.  This is complex for arbitrary command arguments. A safer approach would be to avoid directly passing user-provided strings as command arguments when possible. If necessary, use a safe command parsing and argument quoting library, or restrict allowed characters and formats severely.
        - **Environment Variable Name and Value Sanitization**: Sanitize environment variable names and values to prevent injection. While the code quotes environment variable values, injection might still be possible through variable names or combined attacks.
        - **Bind Mount Path Validation**: If user-provided paths are used for `host_path` in `BindMountSpec`, validate and sanitize these paths to prevent access to sensitive host system areas. Restrict allowed paths to a predefined whitelist or use path canonicalization and validation to ensure paths are within expected boundaries.
        - **Port Number Validation**: While basic port number validation exists, ensure that port configurations are handled securely and do not introduce unintended side effects.

- Preconditions:
    - An application must be using the Tugboat library and allow user-provided input to define or influence `ContainerSpec` or `ExecSpec` parameters.
    - The application must then use Tugboat's functions like `run`, `run_sync`, or `start` with these user-influenced specifications to create or execute containers.

- Source Code Analysis:
    - File: `/code/src/tugboat/client_interface.py`
    - Function: `create`
    ```python
    async def create(
        image: str, # User-controlled input directly used
        *,
        entrypoint: Optional[str] = None,
        args: Optional[Sequence[str]] = None, # User-controlled input directly used
        bind_mounts: Optional[Sequence[BindMountSpec]] = None,
        network: Optional[Network] = None,
        publish_ports: Optional[Sequence[PortSpec]] = None,
        init: bool = False,
        labels: Optional[Mapping[str, Optional[str]]] = None,
        docker_host_path_mapping: Optional[Mapping[pathlib.PurePath, pathlib.Path]] = None,
        spec: Optional[CommandSpec] = None,
        docker_client_wrapper: Optional[Callable[[List[str]], List[str]]] = None,
    ) -> str:
        # ...
        docker_command = ["docker", "create"]
        # ...
        docker_command += _get_docker_args(spec or CommandSpec())
        docker_command += [image] # Directly using user-controlled 'image'
        docker_command += args or [] # Directly using user-controlled 'args'
        # ...
        return _register_container_id(await process.run(docker_command)) # Executes command
    ```
    - In the `create` function, the `image` and `args` parameters, which can be influenced by user input via `ContainerSpec`, are directly appended to the `docker create` command list without any sanitization. This allows for command injection if a malicious image name or arguments are provided.

    - File: `/code/src/tugboat/client_interface.py`
    - Function: `exec_`
    ```python
    async def exec_(
        container: str,
        spec: ExecSpec, # Contains user-controlled 'args' and 'extra_docker_args'
        docker_client_wrapper: Optional[Callable[[List[str]], List[str]]] = None,
    ) -> process.CompletedProcess:
        # ...
        cmd = ["docker", "exec", *_get_docker_args(spec), container, *spec.args] # Directly using user-controlled 'spec.args' and 'spec.extra_docker_args' via _get_docker_args
        # ...
        async with process.open_( # Executes command
            cmd,
            stdout=stdout_stream.stream,
            stderr=stderr_stream.stream,
        ) as rc_fut:
            # ...
    ```
    - Similarly, in the `exec_` function, `spec.args` and `spec.extra_docker_args` from `ExecSpec` are directly incorporated into the `docker exec` command, creating a command injection vulnerability if these are derived from user input.

    - File: `/code/src/tugboat/client_interface.py`
    - Function: `_get_docker_args`
    ```python
    def _get_docker_args(spec: CommandSpec) -> List[str]:
        docker_args: List[str] = []
        # ...
        docker_args += spec.extra_docker_args # Directly using user-controlled 'extra_docker_args'
        return docker_args
    ```
    - The `_get_docker_args` function takes `extra_docker_args` from `CommandSpec` and directly adds them to the Docker command arguments without any sanitization, further contributing to the command injection vulnerability.

- Security Test Case:
    - Step 1: Set up a test application or script that uses the Tugboat library. This application should take user input to define the `image` name and `args` for a `ContainerSpec`. For simplicity, assume the user input is directly passed to the `ContainerSpec` constructor.
    - Step 2: As an attacker, provide a malicious image name and arguments designed to execute a command on the host system or within the container. For example, set the image name to `ubuntu:latest` and arguments to `["sh", "-c", "echo 'ATTACKED' > /tmp/attack.txt"]`. This attempts to write a file to `/tmp/attack.txt` inside the container. A more dangerous attack could attempt to mount a host directory and write to it to achieve host system compromise.
    - Step 3: Run the test application with the malicious input.
    - Step 4: After the application runs (or attempts to run), check for the execution of the injected command. In the example above, check if the file `/tmp/attack.txt` is created inside the container (or on the host if a more sophisticated injection is used).
    - Step 5: Verify that the injected command was successfully executed, demonstrating the command injection vulnerability.

    **Example Test Code (Conceptual - requires Tugboat usage context):**

    ```python
    import tugboat
    import anyio
    import pathlib

    async def test_command_injection_image_name():
        malicious_image_name = "ubuntu:latest; touch /tmp/pwned" # Attempt to create file on host (might fail due to container isolation, but illustrates injection)

        spec = tugboat.ContainerSpec(
            image=malicious_image_name, # Malicious image name from user input
            args=[],
            stdout=tugboat.PIPE,
            stderr=tugboat.PIPE,
        )

        try:
            await tugboat.run(spec)
        except Exception:
            pass # Expecting potential Docker error due to malformed image name if direct host command fails

        # Check if '/tmp/pwned' exists on the HOST system (this might need adjustments based on actual exploit scenario and container isolation)
        host_pwned_file = pathlib.Path("/tmp/pwned")
        assert host_pwned_file.exists() # Vulnerability is present if file is created (adjust check based on actual exploit)
        host_pwned_file.unlink() # Cleanup

    anyio.run(test_command_injection_image_name)
    ```

    **More Robust Test Case (Command Injection in `args` - safer and more reliable for demonstration within container context):**

    ```python
    import tugboat
    import anyio
    import pathlib

    async def test_command_injection_args():
        malicious_args = ["sh", "-c", "echo 'PWNED' > /tmp/container_pwned.txt"] # Malicious args to execute command inside container

        spec = tugboat.ContainerSpec(
            image="ubuntu:latest",
            args=malicious_args, # Malicious args from user input
            stdout=tugboat.PIPE,
            stderr=tugboat.PIPE,
        )

        result = await tugboat.run(spec)
        assert result.returncode == 0

        exec_spec = tugboat.ExecSpec(["cat", "/tmp/container_pwned.txt"]).set_stdout(tugboat.PIPE)
        verify_result = await tugboat.run(tugboat.ContainerSpec("ubuntu:latest").run_indefinitely()) # Start a container to exec in

        container_pwned_check = await verify_result.container.exec(exec_spec)
        assert "PWNED" in container_pwned_check.stdout # Vulnerability is present if 'PWNED' file is created inside container

    anyio.run(test_command_injection_args)
    ```
    This test case demonstrates command injection through the `args` parameter, which is more directly exploitable and easier to verify within the container environment. An attacker could leverage this to execute arbitrary commands inside the Docker container.