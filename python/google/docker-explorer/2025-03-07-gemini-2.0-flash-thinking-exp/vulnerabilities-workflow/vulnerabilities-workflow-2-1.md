### Vulnerability List

- Vulnerability Name: Path Traversal in Docker Directory Argument (`-r`)
- Description:
    1. The user executes `de.py` with the `-r` argument, intending to specify the Docker directory path.
    2. A malicious user can provide a crafted path like `-r /../../../../` or `-r /mnt/hostfs/` as the `docker_directory` argument.
    3. The `de.py` tool, without proper validation, uses this user-supplied path to construct file paths to access Docker container configurations and layer files.
    4. By manipulating the `-r` argument, an attacker can traverse directories outside the intended Docker directory on the host system.
    5. When functions like `list running_containers`, `mount`, or `history` are executed, the tool attempts to access files based on the manipulated path.
    6. If successful, the attacker can read sensitive files or potentially manipulate files on the host system, depending on the tool's operations and file permissions.
- Impact:
    - **Information Disclosure:** An attacker can read sensitive files outside the Docker image by traversing the host filesystem. This could include configuration files, logs, or even user data, depending on the permissions of the user running `de.py`.
    - **File Manipulation (Potentially):** Although the tool primarily focuses on read operations, if there are any functionalities that involve writing or modifying files based on the `-r` path (which is not evident in the current code but is a potential future risk), a path traversal could lead to arbitrary file manipulation on the host system.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The code directly uses the provided `-r` argument to construct file paths without any sanitization or validation.
- Missing Mitigations:
    - **Input Validation and Sanitization:** The tool should validate and sanitize the `docker_directory` path provided by the user. This should include:
        - **Path Canonicalization:** Convert the input path to its canonical form to resolve symbolic links and remove redundant components like `..`.
        - **Path Restriction:** Ensure that the resolved path is within an expected base directory or matches a predefined allowed path pattern.
        - **Permissions Check:** Verify that the user running the tool has the necessary permissions to access the specified Docker directory.
- Preconditions:
    - The attacker must be able to execute the `de.py` script with the `-r` argument. This typically means having access to a system where the `docker-explorer` tool is installed or being able to run it directly from the source code.
- Source Code Analysis:
    1. **`tools/de.py` ParseArguments:**
        ```python
        def AddBasicOptions(self, argument_parser):
            # ...
            argument_parser.add_argument(
                '-r', '--docker-directory',
                help=(
                    'Set the root docker directory. '
                    f'Default is {docker_explorer.DEFAULT_DOCKER_DIRECTORY}'),
                action='store', default=docker_explorer.DEFAULT_DOCKER_DIRECTORY)
        ```
        - The `AddBasicOptions` function in `tools/de.py` defines the `-r` or `--docker-directory` argument. It takes a string as input and defaults to `/var/lib/docker`.  No input validation is performed here.

    2. **`tools/de.py` Main and Explorer Initialization:**
        ```python
        def Main(self):
            options = self.ParseArguments()
            # ...
            self._explorer = explorer.Explorer()
            self._explorer.SetDockerDirectory(options.docker_directory)
            # ...
        ```
        - In the `Main` function, after parsing arguments, the `options.docker_directory` value (directly from user input) is passed to `self._explorer.SetDockerDirectory()`.

    3. **`docker_explorer/explorer.py` SetDockerDirectory:**
        ```python
        def SetDockerDirectory(self, docker_path):
            """Sets the Docker main directory.

            Args:
              docker_path(str): the absolute path to the docker directory.
            Raises:
              errors.BadStorageException: if the path doesn't point to a Docker
                directory.
            """
            self.docker_directory = docker_path
            if not os.path.isdir(self.docker_directory): # [POINT-A] Directory existence check
              msg = f'{self.docker_directory} is not a Docker directory'
              raise errors.BadStorageException(msg)

            self.containers_directory = os.path.join(
                self.docker_directory, 'containers')
        ```
        - `SetDockerDirectory` in `explorer.py` receives the `docker_path` from `de.py`.
        - **[POINT-A]**: It checks if the provided path is a directory using `os.path.isdir()`. This is the *only* validation. It does **not** sanitize or restrict the path. A malicious path like `/../../../../` will pass this check if the user running `de.py` has access to the root directory and it exists.
        - Subsequently, `self.containers_directory` is constructed using `os.path.join()`. Even if `docker_path` is malicious, `os.path.join()` will merely join the paths, not prevent traversal.

    4. **File Path Construction in Explorer and Storage Classes:**
        - Throughout `explorer.py` and `storage.py`, `self.docker_directory` and `self.containers_directory` are used to construct file paths for accessing container configurations, layers, and other Docker-related files. Because `self.docker_directory` can be controlled by the user via the `-r` argument, all file operations based on these constructed paths are vulnerable to path traversal.
        - For example, in `explorer.py`:
            ```python
            def GetAllContainersIDs(docker_root_directory):
                # ...
                containers_directory = os.path.join(docker_root_directory, 'containers') # Path construction

            class Container:
                def __init__(self, docker_directory, container_id, docker_version=2):
                    # ...
                    container_info_json_path = os.path.join(
                        self.docker_directory, 'containers', container_id, # Path construction using self.docker_directory
                        self.container_config_filename)
                    # ...
        ```
        - And in `storage.py` (e.g., `AufsStorage.MakeMountCommands`):
            ```python
            class AufsStorage(BaseStorage):
                def MakeMountCommands(self, container_object, mount_dir):
                    # ...
                    mountpoint_path = os.path.join(
                        self.docker_directory, self.STORAGE_METHOD, 'diff', layer_id) # Path construction using self.docker_directory
                    # ...
            ```
        - These examples show how user-controlled `self.docker_directory` is directly used in `os.path.join()` to build paths, leading to path traversal if a malicious path is provided as `-r`.

- Security Test Case:
    1. **Setup:**
        - Assume you have a Linux system where you can run the `docker-explorer` tool.
        - Create a sensitive file on the host system outside of the Docker directories, for example, `/tmp/sensitive_file.txt` with content "This is a sensitive file.".
    2. **Execution:**
        - Run the `de.py` tool with a crafted `-r` argument to traverse to the `/tmp` directory and attempt to list its contents. For example:
            ```bash
            ./tools/de.py -r /../../../../tmp/ list running_containers
            ```
            or, to be more explicit and potentially bypass some checks if any are added later, you could try to target a specific file directly:
            ```bash
            ./tools/de.py -r /../../../../tmp/ history sensitive_file.txt
            ```
            While `history` might not be the correct command to list files, the goal is to trigger file access using the manipulated `-r` path. A more direct test would be to try to mount a container with the manipulated `-r` and see if you can access `/tmp/sensitive_file.txt` within the mount point, if the mount command itself performs file operations based on `-r`. However, listing containers is a simpler starting point.

        - A more targeted command, focusing on listing repositories which involves file access based on `-r`:
            ```bash
            ./tools/de.py -r /../../../../ list repositories
            ```
        - If the tool attempts to read repository files based on the manipulated `-r` and traversal is successful, this command might throw errors but potentially reveal directory contents or error messages that confirm path traversal.

    3. **Verification:**
        - Observe the output of the command. If the tool attempts to access files under `/tmp` (or any directory outside the intended Docker directory) based on the manipulated `-r` argument, and if you can observe error messages indicating file access attempts in `/tmp` or if the tool behaves unexpectedly due to the path manipulation, it confirms the path traversal vulnerability.
        - Specifically, if you can make the tool try to access `/tmp/sensitive_file.txt` (even if it results in an error because it's not a valid Docker file), it demonstrates the ability to influence file paths outside the intended Docker directory.
        - For the `list repositories` test, if you get errors related to files in `/tmp` or if the tool tries to interpret `/tmp` as a Docker directory, it indicates successful path traversal.

This test case demonstrates how a malicious user can use the `-r` argument to potentially access files outside of the intended Docker directory, confirming the path traversal vulnerability.