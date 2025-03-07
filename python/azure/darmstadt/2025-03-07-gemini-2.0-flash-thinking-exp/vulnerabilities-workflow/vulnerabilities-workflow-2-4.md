### Vulnerability List:

* Vulnerability Name: Path Traversal in `ContainerController.put` function

* Description:
    * A path traversal vulnerability exists in the `ContainerController.put` function.
    * This function is intended to upload a file from the local filesystem or a file-like object to a specified location within a Docker container.
    * The vulnerability occurs because the `remote_path` parameter, which determines the destination directory inside the container, is not properly sanitized.
    * An attacker who can control the `remote` parameter in the `put` function can inject path traversal sequences like `..` into the path.
    * When the `put` function executes `tar x -C {remote_path} -f -` within the container, the `tar` command will extract the uploaded file to a location outside the intended directory, potentially overwriting critical system files or placing files in arbitrary locations within the container's filesystem.
    * Step-by-step trigger:
        1. An attacker submits a pull request to modify code that uses `darmstadt` library and specifically the `ContainerController.put` function.
        2. The attacker crafts a malicious input to the `remote` parameter of the `put` function, including path traversal characters (e.g., `remote="/tmp/../../evil_dir/evil_file.txt"`).
        3. A user of the library incorporates this malicious code into their project.
        4. When the vulnerable code is executed, the `ContainerController.put` function will be called with the attacker-controlled `remote` path.
        5. The `tar x -C` command inside the container will extract the uploaded file to the directory specified by the malicious `remote_path`, effectively writing files outside the intended target directory.

* Impact:
    * **Arbitrary File Write:** Successful exploitation allows an attacker to write files to arbitrary locations within the Docker container's filesystem.
    * **Container Compromise:** Overwriting system files or placing malicious files in sensitive directories can lead to container compromise, potentially allowing for further malicious activities within the container.
    * **Privilege Escalation (Potentially):** If the container is running with elevated privileges or if the attacker can overwrite files used by privileged processes within the container, this could lead to privilege escalation.
    * **Data Exfiltration/Modification:** The attacker could potentially overwrite application data or configuration files, leading to data corruption or unauthorized data access.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    * None. The code does not perform any sanitization or validation of the `remote_path` parameter in the `ContainerController.put` function.

* Missing Mitigations:
    * **Input Validation and Sanitization:** Implement strict validation and sanitization of the `remote_path` parameter in the `ContainerController.put` function.
        *  The `remote_path` should be restricted to a specific allowed directory within the container.
        *  Path traversal sequences like `..` should be removed or rejected.
        *  Consider using functions like `os.path.normpath` and checking if the normalized path is still within the allowed base directory.
    * **Restrict Target Directory:**  The `put` function should be designed to only allow writing files within a predefined, safe directory within the container, preventing writes to system-critical paths.

* Preconditions:
    * The attacker must be able to influence the `remote` parameter passed to the `ContainerController.put` function. This is achievable through a malicious pull request that introduces or modifies code using this function.
    * The user of the `darmstadt` library must execute the vulnerable code path with attacker-controlled input.

* Source Code Analysis:
    * File: `/code/darmstadt/remote_controller.py`
    * Function: `ContainerController.put`
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

        if remote_name == "" and isinstance(local, str):
            remote_name = os.path.basename(local)
        if remote_path == "":
            remote_path = "." # [DEFAULT PATH] Defaults to current directory, but still unsanitized if 'remote' was provided with traversal chars.

        # ... (Tar archive creation) ...

        return self.context.run(
            f"docker exec --interactive {self.name} tar x -C {remote_path} -f -", # [VULNERABLE CODE 2] Unsanitized remote_path is used in 'tar x -C' command
            in_stream=pw_tarstream,
        )
    ```
    * **VULNERABLE CODE 1:** The code splits the `remote` path into `remote_path` and `remote_name` using `os.path.split`, but it does not sanitize or validate `remote_path` to prevent path traversal.
    * **DEFAULT PATH:** If `remote_path` is empty (either `remote` is None or only filename is provided), it defaults to ".", which is the current working directory inside the container. While this seems safe in isolation, if the user *does* provide a `remote` with traversal characters, those are still used and are not mitigated by this default.
    * **VULNERABLE CODE 2:** The unsanitized `remote_path` is directly used in the `docker exec` command with `tar x -C`. The `-C` option of `tar` changes the directory to which files are extracted, and if `remote_path` contains `..`, it will traverse up the directory structure.

* Security Test Case:
    1. **Setup:**
        * Create a test file named `test_file.txt` with some content in the `/tmp` directory on the host system.
        * Instantiate a `ContainerController` object named `container` (e.g., using image `alpine`).
        * Start the container using `container.start()`.
    2. **Exploit Attempt:**
        * Call the `put` function with a path traversal payload in the `remote` parameter: `container.put("/tmp/test_file.txt", remote="/tmp/../../evil_file.txt")`. This attempts to write `test_file.txt` to `/evil_file.txt` in the container, traversing up from `/tmp`.
    3. **Verification:**
        * Execute a command inside the container to check if the file was written to the intended path (`/evil_file.txt`) instead of the intended target directory under `/tmp`. Run: `result = container.run("ls -l /evil_file.txt", in_stream=False)`
        * Assert that the command execution is successful (no errors) and that the file `/evil_file.txt` exists and contains the content of `test_file.txt`.
        * Optionally, you can also check that the file does *not* exist in the intended relative path, although the successful creation at `/evil_file.txt` is sufficient to demonstrate the vulnerability.
    4. **Cleanup:**
        * Remove the container using `container.remove()`.

    This test case demonstrates that an attacker can use path traversal in the `remote` parameter of the `put` function to write files to arbitrary locations outside the intended directory within the container, confirming the path traversal vulnerability.