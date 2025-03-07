### Combined Vulnerability List

This document outlines the identified security vulnerabilities, combining information from multiple vulnerability reports and removing duplicates, while adhering to the specified criteria for inclusion and severity.

#### 1. Command Injection in `ContainerController.run` and `VMController.run`

- **Vulnerability Name:** Command Injection in `ContainerController.run` and `VMController.run`
- **Description:**
    - The `run` method in both `ContainerController` and `VMController` classes, located in `darmstadt/remote_controller.py`, is vulnerable to command injection.
    - In `ContainerController.run`, the function takes a `command` string as input, which is intended to be executed within a Docker container. This `command` is directly embedded into a `docker exec` command string using an f-string without any sanitization: `f"docker exec --user root {docker_options} {self.name} {command}"`. The resulting command is then executed using `self.context.run`, which by default interprets commands via a shell like `/bin/bash`.
    - Similarly, in `VMController.run`, the function takes a `command` string intended for execution on a remote virtual machine via SSH. This `command` is directly passed to `self.ssh_connection.run(command, ...)` without sanitization.
    - An attacker can inject arbitrary shell commands by crafting a malicious `command` string containing shell metacharacters (e.g., backticks, semicolons, command substitution). When the `run` method is called with this malicious input, the injected commands will be executed on the host system (for `VMController`) or within the Docker container (for `ContainerController`) with root privileges where applicable.

- **Impact:**
    - **Critical:** Arbitrary command execution on the host system (in the case of `VMController`) or within the Docker container (in the case of `ContainerController`).
    - This vulnerability can lead to severe security breaches, including:
        - **Complete System Compromise:** Attackers can gain full control over the container or the VM host.
        - **Unauthorized Access to Sensitive Data:** Attackers can access and exfiltrate sensitive data stored within the container or on the host system.
        - **Data Manipulation and Deletion:** Attackers can modify or delete critical data, configurations, and application files.
        - **Malware Installation:** Attackers can install malware, backdoors, or other malicious software.
        - **Lateral Movement:** Attackers might be able to pivot to other systems or resources accessible from the compromised container or VM.

- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    - None. The code directly uses f-strings and string concatenation to construct shell commands in both `ContainerController.run` and `VMController.run` without any input sanitization, validation, or parameterization.
- **Missing Mitigations:**
    - **Input Sanitization:** Implement robust input validation and sanitization for the `command` argument in both `run` methods. This should involve removing or escaping any characters that could be used for command injection, such as shell metacharacters.
    - **Parameterized Commands:** Utilize libraries or methods that support parameterized command execution to separate commands from arguments. For Docker commands, consider using the Docker SDK for Python (`docker-py`) to execute commands in containers in a safer manner. For SSH commands, ensure the SSH library used supports secure command execution without shell interpretation when possible.
    - **Principle of Least Privilege:** Ensure that the user running the container or VM operations has the minimum necessary privileges. While the code uses `--user root` in Docker commands, this should be reviewed and minimized if possible. For VM operations, ensure the SSH user has restricted permissions.
    - **Direct API Usage:** For Docker operations, consider using the Docker API directly via the Docker SDK for Python instead of relying on shell commands, which reduces the risk of command injection.

- **Preconditions:**
    - The attacker must be able to control or influence the `command` argument passed to the `run` method of either `ContainerController` or `VMController`.
    - This typically occurs when the `command` argument is derived from user input or external data sources without proper validation within applications using the `darmstadt` library.
    - The `ContainerController` or `VMController` must be properly initialized and the container or VM must be running or accessible.

- **Source Code Analysis:**
    - **File:** `/code/darmstadt/remote_controller.py`
    - **Vulnerable Code Snippet (ContainerController.run):**
        ```python
        def run(
            self, command: str, pty: bool = False, **kwargs: Any
        ) -> Optional[invoke.runners.Result]:
            """Run a command in the running container."""
            docker_options = "--interactive --tty" if pty else ""
            docker_cmd = f"docker exec --user root {docker_options} {self.name}" # [VULNERABLE LINE] command is not sanitized
            return self.context.run(f"{docker_cmd} {command}", pty=pty, **kwargs) # [VULNERABLE LINE] command is not sanitized
        ```
        - The `command` variable is directly concatenated into the shell command string without any sanitization.
    - **Vulnerable Code Snippet (VMController.run):**
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
        - Similarly, the `command` variable is directly passed to `ssh_connection.run` without sanitization.
    - **Vulnerability Flow Visualization:**
        ```mermaid
        graph LR
            A[User Input: command] --> B(ContainerController.run() / VMController.run());
            B --> C{String Concatenation: f"{docker_cmd} {command}" / ssh_connection.run(command)};
            C --> D[invoke.context.run() / SSH Execution];
            D --> E[Shell Execution within Container/VM Host];
            E --> F[Compromised Container/VM Host];
        ```

- **Security Test Case:**
    - **Step 1:** Set up a local testing environment with Docker installed. For `VMController` testing, a test VM environment would be needed.
    - **Step 2:** Instantiate `LocalHost` to simulate a local jump host:
        ```python
        from darmstadt.jump_host import LocalHost
        local_host = LocalHost()
        ```
    - **Step 3:** Instantiate `ContainerController` with a test container name and image (e.g., "vuln-test-container", "alpine"):
        ```python
        from darmstadt.remote_controller import ContainerController
        container = ContainerController("vuln-test-container", "alpine", jump_host=local_host)
        ```
    - **Step 4:** Start the container:
        ```python
        container.start()
        ```
    - **Step 5:** Define a malicious command injection payload. This payload will create a file named `pwned` in the `/tmp` directory inside the container:
        ```python
        malicious_command = "$(touch /tmp/pwned)"
        ```
    - **Step 6:** Execute the malicious command using the `run` method:
        ```python
        container.run(malicious_command, in_stream=False)
        ```
    - **Step 7:** Verify command injection by checking for the file `pwned` in `/tmp` inside the container. Run `ls /tmp` and check the output:
        ```python
        check_result = container.run("ls /tmp", in_stream=False)
        ```
    - **Step 8:** Assert that `pwned` is present in the standard output of the check command:
        ```python
        assert "pwned" in check_result.stdout
        ```
    - **Step 9:** Clean up by removing the test container:
        ```python
        container.remove()
        ```
    - **Step 10:** Run this test case. If the assertion in Step 8 passes, it confirms the command injection vulnerability in `ContainerController.run`. A similar test case can be constructed for `VMController.run` by replacing `ContainerController` with `VMController` and setting up a test VM environment and `SSHJumpHost`.

#### 2. Path Traversal in `ContainerController.put`

- **Vulnerability Name:** Path Traversal in `ContainerController.put`
- **Description:**
    - The `ContainerController.put` function in `darmstadt/remote_controller.py` is susceptible to a path traversal vulnerability.
    - This function is designed to upload files to a Docker container. It takes a `remote` argument to specify the destination path within the container.
    - The vulnerability arises because the `remote_path`, derived from the `remote` argument using `os.path.split(remote)`, is used directly in a `tar` command executed inside the container: `docker exec --interactive {self.name} tar x -C {remote_path} -f -`.
    - If the `remote` argument is not properly validated and contains directory traversal sequences like `../`, an attacker can control the extraction directory of the tar archive.
    - By crafting a malicious `remote` path with `../` sequences, an attacker can force the `tar` command to extract the uploaded file to arbitrary locations within the container's filesystem, potentially overwriting critical system files or placing files in unintended directories.
    - Step-by-step trigger:
        1. An attacker provides a malicious input to the `remote` parameter of the `put` function, including path traversal characters (e.g., `remote="/tmp/../../evil_dir/evil_file.txt"`).
        2. The `ContainerController.put` function is called with this attacker-controlled `remote` path.
        3. The code extracts `remote_path` but does not sanitize it for traversal characters.
        4. The `docker exec ... tar x -C {remote_path} -f -` command is executed within the container, using the unsanitized `remote_path`.
        5. The `tar` command extracts the uploaded file to the directory specified by the malicious `remote_path`, effectively writing files outside the intended target directory.

- **Impact:**
    - **High:** Path traversal and arbitrary file write within the Docker container.
    - Successful exploitation can lead to:
        - **Arbitrary File Write:** Attackers can write files to any location within the container's filesystem.
        - **Container Compromise:** Overwriting configuration files, libraries, or other sensitive files can lead to container compromise.
        - **Privilege Escalation (Potentially):** If the container is running with elevated privileges or if the attacker can overwrite files used by privileged processes, this could lead to privilege escalation within the container.
        - **Data Exfiltration/Modification:** Attackers could potentially overwrite application data or configuration files, leading to data corruption or unauthorized data access.

- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - None. There is no validation or sanitization of the `remote` path in `ContainerController.put`.
- **Missing Mitigations:**
    - **Path Validation and Sanitization:** Implement strict validation and sanitization of the `remote_path` parameter.
        - Validate that the `remote_path` does not contain directory traversal sequences like `../`.
        - Restrict the target directory to a safe and expected location within the container.
        - Use path canonicalization (e.g., `os.path.normpath`) to resolve symbolic links and `../` components and then check if the normalized path is within an allowed base directory.
    - **Restrict Target Directory:** Design the `put` function to only allow writing files within a predefined, safe directory within the container, preventing writes to system-critical paths.

- **Preconditions:**
    - The attacker must be able to control or influence the `remote` argument passed to the `ContainerController.put` function. This could occur if the `darmstadt` library is used to handle user-provided file paths or external input for file uploads.

- **Source Code Analysis:**
    - **File:** `/code/darmstadt/remote_controller.py`
    - **Function:** `ContainerController.put`
    ```python
    def put(
        self, local: Union[str, TextIO, BinaryIO], remote: Optional[str] = None
    ) -> Optional[invoke.runners.Result]:
        """Upload a file from the local filesystem to the container."""
        # Builds a tar archive in memory before uploading

        if remote is not None:
            remote_path, remote_name = os.path.split(remote) # [VULNERABLE CODE 1] Path is split but not sanitized
        else:
            remote_path, remote_name = ("", "")

        # ... (Tar archive creation) ...

        return self.context.run(
            f"docker exec --interactive {self.name} tar x -C {remote_path} -f -", # [VULNERABLE CODE 2] Unsanitized remote_path is used in 'tar x -C' command
            in_stream=pw_tarstream,
        )
    ```
    - **VULNERABLE CODE 1:** The code splits the `remote` path but does not sanitize `remote_path` to prevent path traversal.
    - **VULNERABLE CODE 2:** The unsanitized `remote_path` is directly used in the `tar x -C` command, making it vulnerable to path traversal.

- **Security Test Case:**
    - **Step 1:** Setup a testing environment with Docker. Create a test file named `test_file.txt` with content in `/tmp` on the host. Instantiate and start a `ContainerController` (e.g., using image `alpine`).
    - **Step 2:** Exploit Attempt: Call the `put` function with a path traversal payload in the `remote` parameter:
        ```python
        container.put("/tmp/test_file.txt", remote="/tmp/../../evil_file.txt")
        ```
        This attempts to write `test_file.txt` to `/evil_file.txt` in the container, traversing up from `/tmp`.
    - **Step 3:** Verification: Execute a command inside the container to check if the file was written to the traversed path `/evil_file.txt`:
        ```python
        result = container.run("ls -l /evil_file.txt", in_stream=False)
        ```
    - **Step 4:** Assert that the command execution is successful and the file `/evil_file.txt` exists.
    - **Step 5:** Cleanup: Remove the container using `container.remove()`.
    - If the assertion in Step 4 passes, it confirms the path traversal vulnerability in `ContainerController.put`.