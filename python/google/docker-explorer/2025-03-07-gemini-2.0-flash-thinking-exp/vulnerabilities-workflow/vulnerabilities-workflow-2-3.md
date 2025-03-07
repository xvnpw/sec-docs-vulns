### 1. Command Injection via Container ID in Mount Command

* Description:
    1. The `de.py` tool takes a container ID as user input in the `mount` command.
    2. This container ID is passed to the `Mount` function in `DockerExplorerTool` class in `tools/de.py`.
    3. The `Mount` function calls `_explorer.GetContainer(container_id)` to retrieve the container object.
    4. `GetContainer` in `explorer.py` uses `_GetFullContainerID` to resolve potentially short container IDs to full IDs.
    5. `_GetFullContainerID` in `explorer.py` iterates through directories in `/var/lib/docker/containers` and checks if directory name starts with user provided `short_id`.
    6. If a container is found, the `Mount` function in `DockerExplorerTool` then calls `container_object.Mount(mountpoint)`.
    7. The `Mount` function in `container.py` calls `self.storage_object.MakeMountCommands(self, mount_dir)`.
    8. The `MakeMountCommands` function in the storage classes (e.g., `AufsStorage`, `OverlayStorage`, `Overlay2Storage`) constructs shell commands to mount the container's filesystem.
    9. These commands are built by string concatenation, directly embedding the `container_id` (or parts derived from it like `mount_id` or `layer_id`) into the command without proper sanitization.
    10. Specifically, in `AufsStorage.MakeMountCommands`, the `mountpoint_path` which is derived from `layer_id` (and ultimately from `container_id`) is embedded in the `-o br=` option of the `mount` command.
    11. If an attacker can control the `container_id` to include malicious characters, they can inject arbitrary commands into the `mount` command.

* Impact:
    * Critical
    * An attacker can achieve arbitrary command execution on the host system running `docker-explorer`.
    * By crafting a malicious container ID, an attacker can inject shell commands that will be executed when the `de.py mount` command is used with this crafted ID.
    * This allows for full system compromise, data exfiltration, or further malicious activities.

* Vulnerability Rank: critical

* Currently implemented mitigations:
    * None. The code directly uses the container ID in shell commands without any sanitization or validation.

* Missing mitigations:
    * Input sanitization for `container_id` before using it in shell commands.
    * Input validation to ensure `container_id` conforms to expected format and length.
    * Use of parameterized commands or shell command builders to avoid direct string concatenation of user inputs into shell commands.

* Preconditions:
    * The attacker needs to be able to provide a container ID to the `de.py mount` command. This could be through a command-line argument or potentially through other input mechanisms if the tool is integrated into a larger system.
    * The user running `docker-explorer` must have sufficient privileges to execute the `mount` command (typically root or sudo).

* Source code analysis:

    ```python
    # tools/de.py - DockerExplorerTool.Mount function
    def Mount(self, container_id, mountpoint):
        """Mounts the specified container's filesystem.
        ...
        """
        container_object = self._explorer.GetContainer(container_id) # container_id is user input
        ...
        container_object.Mount(mountpoint) # mountpoint is user input

    # docker_explorer/explorer.py - Explorer.GetContainer function
    def GetContainer(self, container_id_part): # container_id_part is user input (container_id from Mount function)
        """Returns a Container object given the first characters of a container_id.
        ...
        """
        container_id = self._GetFullContainerID(container_id_part) # container_id_part is passed to _GetFullContainerID
        return container.Container(
            self.docker_directory, container_id, docker_version=self.docker_version)

    # docker_explorer/explorer.py - Explorer._GetFullContainerID function
    def _GetFullContainerID(self, short_id): # short_id is container_id_part from GetContainer function
        """Searches for a container ID from its first characters.
        ...
        """
        ...
        for container_dirs in sorted(os.listdir(containers_dir)): # listdir on containers_dir which is based on docker_directory (user provided via -r option, but typically /var/lib/docker/containers)
            possible_cid = os.path.basename(container_dirs) # possible_cid is directory name from containers_dir
            if possible_cid.startswith(short_id): # check if directory name starts with user input
                possible_cids.append(possible_cid)
        ...
        return possible_cids[0] # returns full container ID

    # docker_explorer/container.py - Container.Mount function
    def Mount(self, mount_dir): # mount_dir is user input (mountpoint from Mount function in de.py)
        """Mounts the specified container's filesystem.
        ...
        """
        commands = self.storage_object.MakeMountCommands(self, mount_dir) # calls MakeMountCommands of storage_object, passing self (Container object) and mount_dir
        for c in commands:
            subprocess.call(c, shell=False) # executes commands without sanitization

    # docker_explorer/storage.py - AufsStorage.MakeMountCommands function (example, similar in other storage drivers)
    def MakeMountCommands(self, container_object, mount_dir): # container_object is Container object, mount_dir is user input
        """Generates the required shell commands to mount a container given its ID.
        ...
        """
        ...
        mountpoint_path = os.path.join(
            self.docker_directory, self.STORAGE_METHOD, 'diff', layer_id) # layer_id is derived from container_id
        commands.append(
            ['/bin/mount', '-t', 'aufs', '-o',
             f'ro,br={mountpoint_path}=ro+wh', 'none', mount_dir]) # mount_dir (user input) and mountpoint_path (derived from container_id) are directly embedded in command
        ...
        return commands
    ```

* Security test case:

    1. On a test system with Docker and `docker-explorer` installed, create a directory that will be interpreted as a container directory.
    ```bash
    sudo mkdir -p /var/lib/docker/containers/'$(touch /tmp/pwned)'
    ```
    This creates a directory with a name that, when processed by `_GetFullContainerID`, will be used in a shell command. In this case, we are trying to inject `touch /tmp/pwned`.
    2. Execute the `de.py mount` command with the crafted container ID.
    ```bash
    sudo tools/de.py -r /var/lib/docker mount '$(touch /tmp/pwned)' /tmp/test_mount
    ```
    3. Check if the command injection was successful.
    ```bash
    ls /tmp/pwned
    ```
    If the file `/tmp/pwned` exists, the command injection was successful, and arbitrary code execution was achieved.
    4. Cleanup the test environment.
    ```bash
    sudo rm -rf /var/lib/docker/containers/'$(touch /tmp/pwned)'
    sudo rm -rf /tmp/test_mount
    sudo rm -f /tmp/pwned
    ```

### 2. Command Injection via Mount Point in Mount Command

* Description:
    1. Similar to the previous vulnerability, the `de.py` tool also takes a mount point as user input in the `mount` command.
    2. This mount point is passed as `mountpoint` argument to the `Mount` function in `DockerExplorerTool` class in `tools/de.py`.
    3. The `mountpoint` is then passed down to `container_object.Mount(mountpoint)`.
    4. Finally, the `mountpoint` is passed to `MakeMountCommands` functions in storage classes.
    5. In `AufsStorage.MakeMountCommands` and similar functions, the `mount_dir` (which is the user-provided mount point) is directly embedded as the destination in the `mount` command.
    6. If an attacker provides a malicious mount point containing command injection characters, they can inject arbitrary commands into the `mount` command.
    7. For instance, a mount point like `/tmp/test_mount; touch /tmp/pwned` could be used to inject the `touch /tmp/pwned` command.

* Impact:
    * Critical
    * Similar to the previous vulnerability, this allows for arbitrary command execution on the host system.
    * By crafting a malicious mount point, an attacker can inject shell commands that will be executed when the `de.py mount` command is used.

* Vulnerability Rank: critical

* Currently implemented mitigations:
    * None. The code directly uses the mount point in shell commands without any sanitization or validation.

* Missing mitigations:
    * Input sanitization for `mountpoint` before using it in shell commands.
    * Input validation to ensure `mountpoint` is a valid path and does not contain malicious characters.
    * Use of parameterized commands or shell command builders to avoid direct string concatenation of user inputs into shell commands.

* Preconditions:
    * The attacker needs to be able to provide a mount point to the `de.py mount` command, which is always the case as it's a mandatory argument.
    * The user running `docker-explorer` must have sufficient privileges to execute the `mount` command (typically root or sudo).

* Source code analysis:
    The source code analysis is very similar to Vulnerability 1, with the focus being on how `mount_dir` (user-provided mount point) is used in `MakeMountCommands` functions, particularly in lines like:

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

* Security test case:

    1. On a test system with Docker and `docker-explorer` installed.
    2. Execute the `de.py mount` command with a crafted mount point.
    ```bash
    sudo tools/de.py -r /var/lib/docker mount 7b02fb3e8a66 /tmp/test_mount'; touch /tmp/pwned'
    ```
    Here, we are injecting `; touch /tmp/pwned` into the mount point argument.
    3. Check if the command injection was successful.
    ```bash
    ls /tmp/pwned
    ```
    If the file `/tmp/pwned` exists, the command injection was successful.
    4. Cleanup the test environment.
    ```bash
    sudo rm -rf /tmp/test_mount*
    sudo rm -f /tmp/pwned
    ```