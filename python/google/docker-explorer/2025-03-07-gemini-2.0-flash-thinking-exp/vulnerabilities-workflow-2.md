### Combined Vulnerability List

#### 1. Path Traversal in Docker Directory Argument (`-r`)

- **Description:**
    1.  A user executes `de.py` with the `-r` argument to specify the Docker directory path.
    2.  A malicious user provides a crafted path like `-r /../../../../` or `-r /mnt/hostfs/` as the `docker_directory` argument.
    3.  The `de.py` tool, lacking proper validation, utilizes this user-supplied path to construct file paths for accessing Docker container configurations and layer files.
    4.  By manipulating the `-r` argument, an attacker can traverse directories outside the intended Docker directory on the host system.
    5.  When functions like `list running_containers`, `mount`, or `history` are executed, the tool attempts to access files based on the manipulated path.
    6.  If successful, the attacker can read sensitive files or potentially manipulate files on the host system, depending on the tool's operations and file permissions.

- **Impact:**
    - **Information Disclosure:** An attacker can read sensitive files outside the Docker image by traversing the host filesystem. This includes configuration files, logs, or user data, depending on the permissions of the user running `de.py`.
    - **File Manipulation (Potentially):**  If functionalities are added in the future that involve writing or modifying files based on the `-r` path, a path traversal could lead to arbitrary file manipulation on the host system.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - None. The code directly uses the provided `-r` argument to construct file paths without any sanitization or validation.

- **Missing Mitigations:**
    - **Input Validation and Sanitization:** Validate and sanitize the `docker_directory` path provided by the user.
        - **Path Canonicalization:** Convert the input path to its canonical form to resolve symbolic links and remove redundant components like `..`.
        - **Path Restriction:** Ensure the resolved path is within an expected base directory or matches a predefined allowed path pattern.
        - **Permissions Check:** Verify that the user running the tool has the necessary permissions to access the specified Docker directory.

- **Preconditions:**
    - The attacker must be able to execute the `de.py` script with the `-r` argument, requiring access to a system with `docker-explorer` installed or the ability to run it from source.

- **Source Code Analysis:**
    1.  **`tools/de.py` ParseArguments:**
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
        - The `-r` or `--docker-directory` argument is defined in `AddBasicOptions`. It accepts a string input with a default value of `/var/lib/docker`, but no input validation is performed.

    2.  **`tools/de.py` Main and Explorer Initialization:**
        ```python
        def Main(self):
            options = self.ParseArguments()
            # ...
            self._explorer = explorer.Explorer()
            self._explorer.SetDockerDirectory(options.docker_directory)
            # ...
        ```
        - In `Main`, `options.docker_directory` (directly from user input) is passed to `self._explorer.SetDockerDirectory()`.

    3.  **`docker_explorer/explorer.py` SetDockerDirectory:**
        ```python
        def SetDockerDirectory(self, docker_path):
            """Sets the Docker main directory.
            ...
            """
            self.docker_directory = docker_path
            if not os.path.isdir(self.docker_directory): # [POINT-A] Directory existence check
              msg = f'{self.docker_directory} is not a Docker directory'
              raise errors.BadStorageException(msg)

            self.containers_directory = os.path.join(
                self.docker_directory, 'containers')
        ```
        - `SetDockerDirectory` receives `docker_path` from `de.py`.
        - **[POINT-A]**: Only checks if the path is a directory using `os.path.isdir()`. No sanitization or restriction of the path is in place. Malicious paths like `/../../../../` pass this check if accessible and existing.
        - `self.containers_directory` is constructed using `os.path.join()`, which does not prevent traversal from a malicious `docker_path`.

    4.  **File Path Construction:**
        - `self.docker_directory` is used throughout `explorer.py` and `storage.py` to construct file paths. User control over `self.docker_directory` via `-r` makes all file operations based on these paths vulnerable to path traversal.
        - Example in `explorer.py`:
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
        - Example in `storage.py` (`AufsStorage.MakeMountCommands`):
            ```python
            class AufsStorage(BaseStorage):
                def MakeMountCommands(self, container_object, mount_dir):
                    # ...
                    mountpoint_path = os.path.join(
                        self.docker_directory, self.STORAGE_METHOD, 'diff', layer_id) # Path construction using self.docker_directory
                    # ...
            ```

- **Security Test Case:**
    1.  **Setup:** Assume a Linux system where `docker-explorer` can be run. Create `/tmp/sensitive_file.txt` with content "This is a sensitive file.".
    2.  **Execution:** Run `de.py` with a crafted `-r` argument to traverse to `/tmp`:
        ```bash
        ./tools/de.py -r /../../../../tmp/ list repositories
        ```
    3.  **Verification:** Observe the output. If the tool attempts to access files under `/tmp` based on the manipulated `-r` argument, or produces errors related to files in `/tmp`, it confirms path traversal. Success is indicated if the tool tries to interpret `/tmp` as a Docker directory or throws errors related to file access in `/tmp`.

#### 2. Path Traversal via Malicious Docker Image Mount Points

- **Description:**
    1.  A forensic analyst uses Docker Explorer on an offline Docker filesystem via `-r`.
    2.  An attacker crafts a malicious Docker image.
    3.  In the malicious image's `config.v2.json`, a crafted "bind" mount point with path traversal sequences (e.g., `../..`) in the `Source` field is injected. Example: `../../../../../../tmp/evil_file`.
    4.  The analyst analyzes the offline filesystem using Docker Explorer, parsing the container's configuration.
    5.  `GetMountpoints` in `container.py` extracts the `Source` path without validation.
    6.  `MakeMountCommands` in `storage.py` uses this traversal path in `mount --bind` commands.
    7.  When the analyst mounts the container or uses features processing mount points, the malicious `mount --bind` command is executed.
    8.  Path traversal in `mount --bind` targets files outside the Docker filesystem, potentially granting analyst access to arbitrary host files when interacting with the mounted container through Docker Explorer.

- **Impact:**
    - Arbitrary file access on the forensic analyst's system. A malicious Docker image can bypass Docker Explorer's intended scope, granting read access to sensitive files outside the Docker filesystem during offline analysis. This can lead to disclosure of confidential information from the analyst's system.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - No mitigations. Paths from container configurations are used directly without sanitization.

- **Missing Mitigations:**
    - **Input validation and sanitization:** Validate paths from container config files, especially in `GetMountpoints` in `container.py`. `Source` paths in "bind" mounts should be validated to be within expected boundaries and without traversal sequences.
    - **Secure path handling:** Use secure path handling functions to resolve and canonicalize paths, preventing traversal.
    - **Principle of least privilege:** Mount operations should be performed with minimal privileges to limit potential damage.

- **Preconditions:**
    1.  Analyst uses Docker Explorer on an offline Docker filesystem.
    2.  The filesystem contains a malicious Docker image.
    3.  Analyst attempts to mount the malicious container or use features processing mount points.
    4.  Analyst's system has mount tools (`mount`, `aufs-tools`).

- **Source Code Analysis:**
    1.  **File:** `/code/container.py`
    2.  **Function:** `Container.GetMountpoints`
    3.  **Code:**
        ```python
        def GetMountpoints(self):
            ...
            elif self.docker_version == 2:
              if self.mount_points:
                for dst_mount_ihp, storage_info in self.mount_points.items():
                  ...
                  if storage_info.get('Type') == 'bind':
                    src_mount_ihp = storage_info['Source'] # [POINT OF VULNERABILITY] - Attacker controlled path
                    ...
                  elif storage_info.get('Type') == 'volume':
                    ...
                    src_mount_ihp = os.path.join('volumes', volume_name, '_data')
                  ...
                  src_mount = src_mount_ihp.lstrip(os.path.sep) # Removes leading slash only
                  dst_mount = dst_mount_ihp.lstrip(os.path.sep)
                  mount_points.append((src_mount, dst_mount)) # Malicious src_mount is used later
            return mount_points
        ```
        - `GetMountpoints` reads `MountPoints` from `config.v2.json`. For "bind" mounts, it directly uses the attacker-controlled `Source` value. Only leading slashes are stripped, not traversal sequences.

    4.  **File:** `/code/storage.py`
    5.  **Function:** `AufsStorage.MakeMountCommands` (similar in other storage classes)
    6.  **Code (Example from AufsStorage):**
        ```python
        class AufsStorage(BaseStorage):
            ...
            def _MakeVolumeMountCommands(self, container_object, mount_dir):
                extra_commands = []
                mount_points = container_object.GetMountpoints() # Calls GetMountpoints, including malicious ones
                if self.docker_version == 2:
                  for source, destination in mount_points: # source is attacker controlled
                    storage_path = os.path.join(self.docker_directory, source) # Potentially vulnerable path construction
                    volume_mountpoint = os.path.join(mount_dir, destination) # safe
                    extra_commands.append(
                        ['/bin/mount', '--bind', '-o', 'ro', storage_path, # storage_path is vulnerable to traversal
                         volume_mountpoint])
                return extra_commands
        ```
        - `_MakeVolumeMountCommands` gets mount points via `GetMountpoints`. `os.path.join(self.docker_directory, source)` attempts to make `storage_path` safe, but `os.path.join` does not prevent traversal if `source` starts with `../..`.

- **Security Test Case:**
    1.  **Prepare Environment:** Set up Docker Explorer and test data.
    2.  **Create Malicious Docker Filesystem:**
        - Extract `test_data/overlay2.v2.tgz` to `test_data/docker`.
        - Edit `test_data/docker/overlay2/containers/8e8b7f23eb7cbd4dfe7e91646ddd0e0f524218e25d50113559f078dfb2690206/config.v2.json`.
        - Add a malicious "bind" mount point in `"MountPoints"`:
            ```json
            "/tmp/evil_mount": {
                "Type": "bind",
                "Source": "../../../../../tmp/evil_file",
                "Destination": "/container_path",
                "Mode": "ro",
                "RW": false,
                "Propagation": "rprivate"
            },
            ```
        - Create `/tmp/evil_file` with content "This is an evil file outside docker".
    3.  **Run Docker Explorer Mount:**
        ```bash
        ./tools/de.py -r test_data/docker mount 8e8b7f23eb7cbd4dfe7e91646ddd0e0f524218e25d50113559f078dfb2690206 /tmp/test_mount
        ```
    4.  **Verify Path Traversal:**
        ```bash
        ls -l /tmp/test_mount/container_path
        cat /tmp/test_mount/container_path
        ```
        Check if `/tmp/test_mount/container_path` points to `/tmp/evil_file` and if `cat` displays "This is an evil file outside docker".
    5.  **Cleanup:**
        ```bash
        sudo umount /tmp/test_mount
        rmdir /tmp/test_mount
        ```

#### 3. Command Injection via Container ID in Mount Command

- **Description:**
    1.  `de.py mount` command takes container ID as user input.
    2.  Container ID passed to `Mount` in `DockerExplorerTool` in `tools/de.py`.
    3.  `Mount` calls `_explorer.GetContainer(container_id)`.
    4.  `GetContainer` uses `_GetFullContainerID` to resolve short IDs.
    5.  `_GetFullContainerID` iterates directories in `/var/lib/docker/containers` and checks if directory name starts with user input `short_id`.
    6.  `Mount` calls `container_object.Mount(mountpoint)`.
    7.  `Mount` in `container.py` calls `self.storage_object.MakeMountCommands(self, mount_dir)`.
    8.  `MakeMountCommands` in storage classes constructs shell commands for mounting.
    9.  Commands are built by string concatenation, embedding `container_id` (or derived parts) without sanitization.
    10. In `AufsStorage.MakeMountCommands`, `mountpoint_path` (derived from `layer_id`, from `container_id`) is embedded in `-o br=` of `mount`.
    11. Attacker controlling `container_id` can inject commands into the `mount` command.

- **Impact:**
    - **Critical**
    - Arbitrary command execution on the host system running `docker-explorer`.
    - Crafted container ID allows injection of shell commands executed by `de.py mount`.
    - Full system compromise, data exfiltration, or further malicious activities.

- **Vulnerability Rank:** critical

- **Currently implemented mitigations:**
    - None. Container ID is directly used in shell commands without sanitization.

- **Missing mitigations:**
    - Input sanitization for `container_id`.
    - Input validation to ensure `container_id` format and length.
    - Use parameterized commands or shell command builders.

- **Preconditions:**
    - Attacker can provide container ID to `de.py mount`.
    - User running `docker-explorer` has privileges to execute `mount` (root or sudo).

- **Source code analysis:**
    ```python
    # tools/de.py - DockerExplorerTool.Mount
    def Mount(self, container_id, mountpoint):
        container_object = self._explorer.GetContainer(container_id) # container_id is user input
        container_object.Mount(mountpoint)

    # docker_explorer/explorer.py - Explorer.GetContainer
    def GetContainer(self, container_id_part): # container_id_part is user input
        container_id = self._GetFullContainerID(container_id_part) # container_id_part is passed to _GetFullContainerID
        return container.Container(...)

    # docker_explorer/explorer.py - Explorer._GetFullContainerID
    def _GetFullContainerID(self, short_id): # short_id is container_id_part
        for container_dirs in sorted(os.listdir(containers_dir)): # listdir on containers_dir
            possible_cid = os.path.basename(container_dirs) # possible_cid is directory name
            if possible_cid.startswith(short_id): # check if directory name starts with user input
                possible_cids.append(possible_cid)
        return possible_cids[0] # returns full container ID

    # docker_explorer/container.py - Container.Mount
    def Mount(self, mount_dir): # mount_dir is user input
        commands = self.storage_object.MakeMountCommands(self, mount_dir) # calls MakeMountCommands
        for c in commands:
            subprocess.call(c, shell=False) # executes commands

    # docker_explorer/storage.py - AufsStorage.MakeMountCommands
    def MakeMountCommands(self, container_object, mount_dir): # container_object, mount_dir is user input
        mountpoint_path = os.path.join(
            self.docker_directory, self.STORAGE_METHOD, 'diff', layer_id) # layer_id from container_id
        commands.append(
            ['/bin/mount', '-t', 'aufs', '-o',
             f'ro,br={mountpoint_path}=ro+wh', 'none', mount_dir]) # mountpoint_path and mount_dir embedded in command
        return commands
    ```

- **Security test case:**
    1. Create a directory to inject command:
       ```bash
       sudo mkdir -p /var/lib/docker/containers/'$(touch /tmp/pwned)'
       ```
    2. Execute `de.py mount` with crafted container ID:
       ```bash
       sudo tools/de.py -r /var/lib/docker mount '$(touch /tmp/pwned)' /tmp/test_mount
       ```
    3. Check for command injection:
       ```bash
       ls /tmp/pwned
       ```
       If `/tmp/pwned` exists, injection is successful.
    4. Cleanup:
       ```bash
       sudo rm -rf /var/lib/docker/containers/'$(touch /tmp/pwned)'
       sudo rm -rf /tmp/test_mount
       sudo rm -f /tmp/pwned
       ```

#### 4. Command Injection via Mount Point in Mount Command

- **Description:**
    1.  `de.py mount` takes mount point as user input.
    2.  Mount point passed to `Mount` in `DockerExplorerTool` in `tools/de.py`.
    3.  Mount point passed to `container_object.Mount(mountpoint)`.
    4.  Mount point passed to `MakeMountCommands` in storage classes.
    5.  `AufsStorage.MakeMountCommands` and similar directly embed `mount_dir` (user-provided mount point) in `mount` command.
    6.  Malicious mount point with command injection characters can inject commands.
    7.  Example: `/tmp/test_mount; touch /tmp/pwned`.

- **Impact:**
    - **Critical**
    - Arbitrary command execution, similar to previous vulnerability.
    - Crafted mount point allows injecting shell commands.

- **Vulnerability Rank:** critical

- **Currently implemented mitigations:**
    - None. Mount point directly used in shell commands.

- **Missing mitigations:**
    - Input sanitization for `mountpoint`.
    - Input validation for valid path and no malicious characters.
    - Parameterized commands or shell command builders.

- **Preconditions:**
    - Attacker provides mount point to `de.py mount`.
    - User running `docker-explorer` has privileges to execute `mount`.

- **Source code analysis:**
    - Similar to Vulnerability 3, focus is on how `mount_dir` is used in `MakeMountCommands`:
        ```python
        # docker_explorer/storage.py - AufsStorage.MakeMountCommands
        commands.append(
            ['/bin/mount', '-t', 'aufs', '-o',
             f'ro,br={mountpoint_path}=ro+wh', 'none', mount_dir]) # mount_dir is directly used here

        # docker_explorer/storage.py - OverlayStorage.MakeMountCommands
        commands = [[
            '/bin/mount', '-t', 'overlay', 'overlay', '-o',
            f'ro,lowerdir={upper_dir}:{lower_dir}', mount_dir]] # mount_dir is directly used here
        ```

- **Security test case:**
    1. Test system with Docker and `docker-explorer`.
    2. Execute `de.py mount` with crafted mount point:
       ```bash
       sudo tools/de.py -r /var/lib/docker mount 7b02fb3e8a66 /tmp/test_mount'; touch /tmp/pwned'
       ```
    3. Check for command injection:
       ```bash
       ls /tmp/pwned
       ```
       If `/tmp/pwned` exists, injection is successful.
    4. Cleanup:
       ```bash
       sudo rm -rf /tmp/test_mount*
       sudo rm -f /tmp/pwned