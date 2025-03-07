- Vulnerability Name: Command Injection in ContainerController.run and VMController.run
- Description:
  - The `run` method in both `ContainerController` and `VMController` classes is vulnerable to command injection.
  - User-provided input for the `command` parameter is directly embedded into shell commands without proper sanitization.
  - This allows an attacker to inject arbitrary shell commands by crafting malicious input.
  - For `ContainerController`, the command is executed within a Docker container.
  - For `VMController`, the command is executed on a remote virtual machine via SSH.
- Impact:
  - Arbitrary command execution on the host system (in the case of `VMController`) or within the container (in the case of `ContainerController`).
  - This can lead to severe security breaches, including:
    - Unauthorized access to sensitive data.
    - Modification or deletion of critical files.
    - Installation of malware.
    - Complete system compromise.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
  - None. The code directly uses f-strings to construct shell commands without any input sanitization or parameterization.
- Missing Mitigations:
  - Input sanitization: Implement robust input validation and sanitization to remove or escape any characters that could be used for command injection.
  - Parameterized commands: Utilize libraries or methods that support parameterized command execution to separate commands from arguments, preventing injection.
  - Principle of least privilege: Ensure that the user running the container or VM operations has the minimum necessary privileges to reduce the impact of potential command injection.
- Preconditions:
  - The attacker must be able to control the `command` argument passed to the `run` method of either `ContainerController` or `VMController`.
  - This typically occurs when the `command` argument is derived from user input or external data sources without proper validation.
- Source Code Analysis:
  - Vulnerable code snippet from `darmstadt/remote_controller.py` (ContainerController.run):
    ```python
    def run(
        self, command: str, pty: bool = False, **kwargs: Any
    ) -> Optional[invoke.runners.Result]:
        """Run a command in the running container."""
        docker_options = "--interactive --tty" if pty else ""
        docker_cmd = f"docker exec --user root {docker_options} {self.name}" # [VULNERABLE LINE] command is not sanitized
        return self.context.run(f"{docker_cmd} {command}", pty=pty, **kwargs) # [VULNERABLE LINE] command is not sanitized
    ```
    - The `command` variable, which is directly passed as an argument to the `run` method, is incorporated into the shell command using an f-string without any sanitization.
    - This allows an attacker to inject malicious shell commands by providing a crafted string as the `command` argument.
  - Vulnerable code snippet from `darmstadt/remote_controller.py` (VMController.run):
    ```python
    def run(
        self, command: str, pty: bool = False, **kwargs: Any
    ) -> invoke.runners.Result:
        """
        Run a command on VM.
        """
        try:
            return self.ssh_connection.run(command, warn=True, pty=pty, **kwargs) # [VULNERABLE LINE] command is not sanitized
        except AttributeError as error:
            raise ConnectionError(
                "Couldn't connect to " + self.name + " VM."
            ) from error
    ```
    - Similar to `ContainerController.run`, the `command` variable in `VMController.run` is also directly passed to `ssh_connection.run` without sanitization, leading to command injection vulnerability.
- Security Test Case:
  - Step 1: Set up a local testing environment with Docker installed.
  - Step 2: Instantiate `LocalHost` to simulate a local jump host:
    ```python
    from darmstadt.jump_host import LocalHost
    local_host = LocalHost()
    ```
  - Step 3: Instantiate `ContainerController` with a test container name ("vuln-test-container"), the "alpine" image, and the `local_host`:
    ```python
    from darmstadt.remote_controller import ContainerController
    container = ContainerController("vuln-test-container", "alpine", jump_host=local_host)
    ```
  - Step 4: Start the container:
    ```python
    container.start()
    ```
  - Step 5: Define a malicious command injection payload. This payload will create a file named `pwned` in the `/tmp` directory inside the container:
    ```python
    malicious_command = "$(touch /tmp/pwned)"
    ```
  - Step 6: Execute the malicious command using the `run` method:
    ```python
    container.run(malicious_command, in_stream=False)
    ```
  - Step 7: Verify command injection by checking for the file `pwned` in `/tmp` inside the container. Run `ls /tmp` and check the output:
    ```python
    check_result = container.run("ls /tmp", in_stream=False)
    ```
  - Step 8: Assert that `pwned` is present in the standard output of the check command:
    ```python
    assert "pwned" in check_result.stdout
    ```
  - Step 9: Clean up by removing the test container:
    ```python
    container.remove()
    ```
  - Step 10: Run this test case. If the assertion in Step 8 passes, it confirms the command injection vulnerability in `ContainerController.run`. A similar test case can be constructed for `VMController.run` if a test VM environment is available.