### Vulnerability List

- Vulnerability Name: Command Injection in `ContainerController.run`
- Description:
  1. The `ContainerController.run` function in `darmstadt/remote_controller.py` takes a `command` string as input.
  2. This `command` is directly embedded into a `docker exec` command string without proper sanitization.
  3. The `docker exec` command is then executed using `self.context.run`, which by default executes commands via a shell (e.g., `/bin/bash`).
  4. An attacker can inject arbitrary shell commands by crafting a malicious `command` string containing shell metacharacters (e.g., backticks, semicolons, command substitution).
  5. When `ContainerController.run` is called with the malicious `command`, the injected commands will be executed within the Docker container with root privileges due to `--user root` in the `docker exec` command.
- Impact:
  - High: Arbitrary command execution within the Docker container.
  - An attacker can gain complete control over the container, potentially leading to data breaches, malware installation, or further attacks on the host system or network.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
  - None: There is no input sanitization or validation applied to the `command` argument in `ContainerController.run`.
- Missing Mitigations:
  - Input sanitization: Sanitize the `command` input to remove or escape shell metacharacters before passing it to `docker exec`.
  - Parameterized execution: Use a method to execute commands without shell interpretation, if possible with `invoke.Context.run` or `docker SDK`.
  - Least privilege: Avoid running `docker exec` as root if possible. While the code uses `--user root`, it might be necessary for intended functionalities but should be reviewed.
- Preconditions:
  - An attacker must be able to control or influence the `command` argument passed to the `ContainerController.run` function. This is likely if the `darmstadt` library is used to process external input or user-provided commands.
- Source Code Analysis:
  - File: `/code/darmstadt/remote_controller.py`
  - Function: `ContainerController.run`
  ```python
  def run(
      self, command: str, pty: bool = False, **kwargs: Any
  ) -> Optional[invoke.runners.Result]:
      """Run a command in the running container."""
      docker_options = "--interactive --tty" if pty else ""
      docker_cmd = f"docker exec --user root {docker_options} {self.name}"

      return self.context.run(f"{docker_cmd} {command}", pty=pty, **kwargs)
  ```
  - The code directly concatenates `docker_cmd` and `command` into a single string and executes it using `self.context.run`.
  - `invoke.Context.run` by default uses a shell to execute commands, making it vulnerable to command injection if `command` is not sanitized.
- Security Test Case:
  1. Instantiate `ContainerController` with a test container name and image (e.g., "alpine").
  2. Start the container using `container.start()`.
  3. Construct a malicious command string to inject, for example: `injection_command = "echo Hello && touch /tmp/pwned"`. This command attempts to execute `echo Hello` and then create a file named `pwned` in `/tmp` inside the container.
  4. Call `container.run(injection_command, in_stream=False, shell=True)` to execute the injected command. `shell=True` is crucial to enable shell interpretation of the injected metacharacters.
  5. Verify the command injection by checking if the `/tmp/pwned` file was created inside the container. Run `check_pwned = container.run("ls /tmp/pwned", in_stream=False, shell=True)`.
  6. Assert that `"pwned"` is present in the output of `check_pwned.stdout`, confirming successful command injection.
  7. Repeat steps 3-6 with different injection techniques, such as using semicolons (`;`) or command substitution (`$(...)`), to ensure comprehensive testing.
  8. Finally, remove the test container using `container.remove()`.

- Vulnerability Name: Potential Directory Traversal in `ContainerController.put`
- Description:
  1. The `ContainerController.put` function in `darmstadt/remote_controller.py` takes a `remote` argument which specifies the destination path within the container for file uploads.
  2. The code extracts `remote_path` from the `remote` argument using `os.path.split(remote)`.
  3. This `remote_path` is directly used in a `tar` command executed inside the container: `docker exec ... tar x -C {remote_path} -f -`.
  4. If the `remote` argument (and consequently `remote_path`) is not properly validated and contains directory traversal characters like `../`, an attacker can control the extraction directory of the tar archive.
  5. This can allow writing files to arbitrary locations within the container's filesystem, potentially overwriting critical system files or sensitive data.
- Impact:
  - Medium: Potential for directory traversal and arbitrary file write within the Docker container.
  - An attacker could potentially overwrite configuration files, libraries, or other sensitive files within the container, leading to container compromise or privilege escalation if improperly configured services are running in the container.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations:
  - None: There is no validation or sanitization of the `remote` path in `ContainerController.put`.
- Missing Mitigations:
  - Path validation: Validate the `remote` path to ensure it does not contain directory traversal characters (e.g., `../`) or restrict the target directory to a safe and expected location.
  - Path canonicalization: Canonicalize the `remote_path` to resolve symbolic links and `../` components before using it in the `tar` command.
- Preconditions:
  - An attacker must be able to control or influence the `remote` argument passed to the `ContainerController.put` function. This is likely if the `darmstadt` library is used to handle user-provided file paths or external input for file uploads.
- Source Code Analysis:
  - File: `/code/darmstadt/remote_controller.py`
  - Function: `ContainerController.put`
  ```python
  def put(
      self, local: Union[str, TextIO, BinaryIO], remote: Optional[str] = None
  ) -> Optional[invoke.runners.Result]:
      """Upload a file from the local filesystem to the container."""
      # Builds a tar archive in memory before uploading

      if remote is not None:
          remote_path, remote_name = os.path.split(remote)
      else:
          remote_path, remote_name = ("", "")
      # ...
      return self.context.run(
          f"docker exec --interactive {self.name} tar x -C {remote_path} -f -",
          in_stream=pw_tarstream,
      )
  ```
  - The code extracts `remote_path` and directly uses it in the `-C` option of the `tar` command.
  - If `remote` contains `../`, the `tar` command will extract the archive to a directory outside of the intended target, leading to directory traversal.
- Security Test Case:
  1. Instantiate `ContainerController` with a test container name and image (e.g., "alpine").
  2. Start the container using `container.start()`.
  3. Construct a malicious `remote` path using directory traversal, for example: `injection_path = "../../../tmp/pwned_traversal"`. This path attempts to write the uploaded file to `/tmp/pwned_traversal` by traversing up three directories from the default location.
  4. Call `container.put(StringIO("pwned"), remote=injection_path)` to upload a file with the malicious `remote` path.
  5. Verify the directory traversal by checking if the `pwned_traversal` file was created in the `/tmp` directory inside the container. Run `check_pwned_traversal = container.run("ls /tmp/pwned_traversal", in_stream=False)`.
  6. Assert that `"pwned_traversal"` is present in the output of `check_pwned_traversal.stdout`, confirming successful directory traversal.
  7. Repeat steps 3-6 with different traversal techniques, such as using absolute paths starting with `/` (e.g. `/../../../tmp/pwned_root`) to ensure comprehensive testing.
  8. Finally, remove the test container using `container.remove()`.