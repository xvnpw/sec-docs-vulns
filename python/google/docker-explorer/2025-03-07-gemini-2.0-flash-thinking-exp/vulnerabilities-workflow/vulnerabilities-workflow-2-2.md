*   #### Vulnerability Name: Path Traversal via Malicious Docker Image Mount Points

    *   Description:
        1.  A forensic analyst uses Docker Explorer to investigate an offline Docker filesystem by providing the path to the Docker directory using the `-r` option.
        2.  An attacker crafts a malicious Docker image.
        3.  Within the malicious Docker image's configuration files (e.g., `config.v2.json`), the attacker injects a crafted "bind" mount point in the `MountPoints` section. This malicious mount point contains a path using path traversal sequences like `../..` in the `Source` field. For example, the `Source` can be set to `../../../../../../tmp/evil_file`.
        4.  The forensic analyst, unaware of the malicious nature of the image, analyzes the offline Docker filesystem using Docker Explorer, which parses the container's configuration.
        5.  When Docker Explorer processes the malicious container configuration, specifically in the `GetMountpoints` function in `container.py`, it extracts the `Source` path from the `MountPoints` configuration without proper validation.
        6.  Subsequently, when Docker Explorer generates mount commands (e.g., in `AufsStorage.MakeMountCommands` in `storage.py`), it incorporates the attacker-controlled, traversal path directly into the `mount --bind` command.
        7.  If the analyst attempts to mount the container's filesystem using Docker Explorer's `mount` command or if other functionalities of Docker Explorer process the mount points, the `mount --bind` command with the malicious path is executed.
        8.  Due to the path traversal sequences, the `mount --bind` command can target a file or directory outside of the intended Docker filesystem, potentially giving the analyst access to arbitrary files on their own system when they interact with the mounted container filesystem through Docker Explorer.

    *   Impact:
        An attacker can achieve arbitrary file access on the forensic analyst's system. By crafting a malicious Docker image, an attacker can bypass the intended scope of Docker Explorer and gain read access to sensitive files outside the Docker filesystem when the analyst uses Docker Explorer to examine the malicious image offline. This could lead to the disclosure of confidential information from the analyst's system.

    *   Vulnerability Rank: High

    *   Currently Implemented Mitigations:
        No mitigations are currently implemented in the project to prevent this vulnerability. The code directly uses the paths from the container configuration without sanitization.

    *   Missing Mitigations:
        *   Input validation and sanitization for paths extracted from container configuration files, specifically in the `GetMountpoints` function in `container.py`. The `Source` paths in "bind" mount points should be validated to ensure they are within the expected Docker filesystem boundaries and do not contain path traversal sequences.
        *   Consider using secure path handling functions to resolve and canonicalize paths, preventing traversal outside the intended directories.
        *   Principle of least privilege: While mounting, ensure that the mount operations are performed with the minimum necessary privileges to limit the potential damage from path traversal.

    *   Preconditions:
        1.  The forensic analyst must use Docker Explorer to analyze an offline Docker filesystem.
        2.  The offline Docker filesystem must contain a malicious Docker image crafted by the attacker.
        3.  The analyst must attempt to mount the malicious container or use a Docker Explorer feature that processes container mount points.
        4.  The analyst's system must have the necessary tools installed for mounting filesystems (e.g., `mount`, `aufs-tools`).

    *   Source Code Analysis:
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
                        src_mount_ihp = storage_info['Source'] # [POINT OF VULNERABILITY] - Attacker controlled path from container config
                        ...
                      elif storage_info.get('Type') == 'volume':
                        ...
                        src_mount_ihp = os.path.join('volumes', volume_name, '_data')
                      ...
                      src_mount = src_mount_ihp.lstrip(os.path.sep) # Removes leading slash only, not traversal sequences
                      dst_mount = dst_mount_ihp.lstrip(os.path.sep)
                      mount_points.append((src_mount, dst_mount)) # Malicious src_mount is used later
                return mount_points
            ```
        4.  **Explanation:** The `GetMountpoints` function in `container.py` reads the `MountPoints` configuration from the container's `config.v2.json` file. For "bind" mounts, it directly takes the `Source` value, which is attacker-controlled within a malicious Docker image. The code only strips leading path separators using `lstrip(os.path.sep)` but does not sanitize or validate for path traversal sequences like `../..`.
        5.  **File:** `/code/storage.py`
        6.  **Function:** `AufsStorage.MakeMountCommands` (and similar functions in other storage classes like `OverlayStorage`, `Overlay2Storage`)
        7.  **Code (Example from AufsStorage):**
            ```python
            class AufsStorage(BaseStorage):
                ...
                def MakeMountCommands(self, container_object, mount_dir):
                    ...
                    commands = []
                    mountpoint_path = os.path.join(
                        self.docker_directory, self.STORAGE_METHOD, 'diff', layer_id)
                    commands.append(
                        ['/bin/mount', '-t', 'aufs', '-o',
                         f'ro,br={mountpoint_path}=ro+wh', 'none', mount_dir]) # Safe path

                    ...
                    commands.extend(self._MakeVolumeMountCommands(container_object, mount_dir)) # Calls _MakeVolumeMountCommands

                    return commands

                def _MakeVolumeMountCommands(self, container_object, mount_dir):
                    extra_commands = []
                    mount_points = container_object.GetMountpoints() # Calls GetMountpoints to get mount points, including malicious ones
                    if self.docker_version == 2:
                      for source, destination in mount_points: # source can be attacker controlled
                        storage_path = os.path.join(self.docker_directory, source) # But here it prepends docker_directory, making it seem safe? NO, because source can be "../../../../tmp/evil_file"
                        volume_mountpoint = os.path.join(mount_dir, destination) # destination is within mount_dir, safe
                        extra_commands.append(
                            ['/bin/mount', '--bind', '-o', 'ro', storage_path, # storage_path is still vulnerable to traversal if source starts with ".."
                             volume_mountpoint])
                    return extra_commands
            ```
        8.  **Explanation:** The `_MakeVolumeMountCommands` function in `AufsStorage` (and similar storage classes) retrieves the mount points using `container_object.GetMountpoints()`. It then constructs `mount --bind` commands. While it uses `os.path.join(self.docker_directory, source)` seemingly to make the `storage_path` safe, if the `source` from `GetMountpoints` starts with path traversal sequences (`../..`), `os.path.join` will not prevent the traversal. For example, if `source` is `../../../../tmp/evil_file` and `self.docker_directory` is `/var/lib/docker`, `os.path.join('/var/lib/docker', '../../../../tmp/evil_file')` will result in `/var/lib/docker/../../../../tmp/evil_file`, which simplifies to `/tmp/evil_file`, escaping the intended Docker directory.

    *   Security Test Case:
        1.  **Prepare Environment:** Set up a test environment with Docker Explorer code and test data. Ensure you have necessary permissions to create directories and files in `/tmp`.
        2.  **Create Malicious Docker Filesystem (Manual Modification):**
            *   Extract the `test_data/overlay2.v2.tgz` archive to the `test_data/docker` directory within the project.
                ```bash
                cd test_data
                tar -xzf overlay2.v2.tgz
                cd ..
                ```
            *   Navigate to the container configuration directory: `test_data/docker/overlay2/containers/8e8b7f23eb7cbd4dfe7e91646ddd0e0f524218e25d50113559f078dfb2690206`.
            *   Edit the `config.v2.json` file in a text editor.
            *   Locate the `"MountPoints": { ... }` section. If it doesn't exist, create it.
            *   Add a malicious "bind" mount point with a path traversal `Source`. For example, insert the following within the `MountPoints` section:
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
            *   Create a file at the target of the traversal on the host system. For example:
                ```bash
                echo "This is an evil file outside docker" > /tmp/evil_file
                ```
        3.  **Run Docker Explorer to Mount the Malicious Container:**
            *   Execute the `de.py mount` command, targeting the modified container and a mount point in `/tmp`:
                ```bash
                ./tools/de.py -r test_data/docker mount 8e8b7f23eb7cbd4dfe7e91646ddd0e0f524218e25d50113559f078dfb2690206 /tmp/test_mount
                ```
            *   You might need to install `aufs-tools` if you don't have it already:
                ```bash
                sudo apt-get install aufs-tools # If on Debian/Ubuntu based system
                ```
        4.  **Verify Path Traversal:**
            *   Check the contents of the mounted directory. If the path traversal is successful, you should be able to see the content of `/tmp/evil_file` within the mounted container filesystem at `/tmp/test_mount/container_path`.
                ```bash
                ls -l /tmp/test_mount/container_path
                cat /tmp/test_mount/container_path
                ```
                You should see that `/tmp/test_mount/container_path` points to `/tmp/evil_file` and `cat` should display "This is an evil file outside docker". This confirms that the bind mount operation escaped the intended Docker directory and accessed a file from the host filesystem due to path traversal.
        5.  **Cleanup:** Unmount the directory:
            ```bash
            sudo umount /tmp/test_mount
            rmdir /tmp/test_mount
            ```

This test case demonstrates that a malicious Docker image can indeed cause Docker Explorer to perform a path traversal attack, allowing access to arbitrary files on the analyst's system via crafted container configurations.