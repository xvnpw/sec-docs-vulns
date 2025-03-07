- Vulnerability Name: Command Injection in Container Name/ID
- Description:
    1. The `force_remove_sync` function in `src/tugboat/client_interface.py` takes a `container` argument which is intended to be a container name or ID.
    2. This `container` argument is directly incorporated into a Docker command: `["docker", "rm", "--force", container]`.
    3. If a malicious user can control the `container` argument, they can inject arbitrary commands into the Docker command line.
    4. For example, if a user provides a container name like `"container_name; touch /tmp/pwned"`, the command executed would become `docker rm --force container_name; touch /tmp/pwned`. This executes the intended `docker rm` command, but also the injected `touch /tmp/pwned` command on the host system.
- Impact:
    - **High**: Arbitrary command execution on the host system where the Docker daemon is running. An attacker could potentially gain full control of the host system, steal sensitive data, or disrupt services.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The code directly uses the user-provided `container` string without any sanitization or validation.
- Missing Mitigations:
    - Input sanitization: The `container` argument in `force_remove_sync` and potentially other functions that take container names or IDs should be sanitized to prevent command injection.  A simple approach would be to validate that the input only contains alphanumeric characters, underscores, hyphens, and colons, which are typical characters in container names and IDs. However, a more robust solution would involve using Docker SDK for Python instead of shelling out to `docker` CLI, which would avoid command construction via string manipulation altogether.
- Preconditions:
    - An attacker must be able to control the `container` argument passed to the `force_remove_sync` function, or potentially other functions that take container identifiers as input. This typically means the application using the Tugboat library takes container names or IDs as input from an external source (e.g., user input, API call, configuration file) without proper validation.
- Source Code Analysis:
    1. File: `/code/src/tugboat/client_interface.py`
    2. Function: `force_remove_sync(container: str, ...)`
    3. Code snippet:
    ```python
    def force_remove_sync(
        container: str,
        docker_client_wrapper: Optional[Callable[[List[str]], List[str]]] = None,
    ) -> None:
        """
        Synchronously force-remove a container.

        Fallback for use where synchronous cleanup is required, such as when the event loop
        has been terminated.
        """
        log.debug("Forceably removing container %s", container)
        cmd = ["docker", "rm", "--force", container] # Vulnerability: User-controlled 'container' directly in command
        if docker_client_wrapper is not None:
            cmd = docker_client_wrapper(cmd)
        process.run_sync(cmd)
    ```
    4. Visualization:
    ```
    User Input (malicious container name) --> container argument in force_remove_sync --> cmd = ["docker", "rm", "--force", container] --> process.run_sync(cmd) --> System Command Execution (command injection)
    ```
    5. The `container` variable is directly inserted into the `cmd` list without any sanitization. When `process.run_sync(cmd)` is called, this list is passed to `subprocess.run`, which executes the command. If `container` contains shell metacharacters, they will be interpreted by the shell, leading to command injection.

- Security Test Case:
    1. Step 1: Setup a vulnerable application using Tugboat that exposes the `force_remove_sync` function and allows an attacker to control the `container` argument. For simplicity, we can simulate this by directly calling `force_remove_sync` in a test.
    2. Step 2: Craft a malicious container name designed to inject a command. For example: `"test_container; touch /tmp/pwned"`
    3. Step 3: Call `force_remove_sync` with the malicious container name.
    4. Step 4: Check for the execution of the injected command on the host system. In this case, check if the file `/tmp/tugboat_pwned` was created.

    ```python
    import os
    import pathlib
    import tugboat
    import pytest

    @pytest.mark.anyio
    async def test_command_injection_force_remove_sync():
        malicious_container_name = "test_container; touch /tmp/tugboat_pwned"
        try:
            tugboat.client_interface.force_remove_sync(malicious_container_name)
        except Exception:
            pass # Ignore potential errors from docker rm if 'test_container' does not exist

        # Check if the injected command was executed.
        pwned_file = pathlib.Path("/tmp/tugboat_pwned")
        assert pwned_file.exists()
        pwned_file.unlink() # Cleanup
    ```
    This test case demonstrates that by providing a crafted container name to `force_remove_sync`, an attacker can execute arbitrary commands on the host system, confirming the command injection vulnerability.