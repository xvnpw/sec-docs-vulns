- Vulnerability Name: Argument Injection in `mount.efs` via `nfsvers` option
- Description:
  - An attacker can inject arbitrary commands into the `mount.efs` command line by crafting a malicious `nfsvers` mount option.
  - The `efs-utils` script passes the `nfsvers` option, among others, directly to the `mount.nfs4` or `mount_nfs` command.
  - By injecting shell-escaped characters within the `nfsvers` option, an attacker can break out of the intended option value and append arbitrary commands.
  - When `mount.efs` executes the `mount.nfs4` or `mount_nfs` command via `subprocess.Popen`, the injected commands will be executed by the shell.
  - Since `mount.efs` is typically executed with sudo privileges, the injected commands will also be executed with elevated privileges.
- Impact:
  - Arbitrary command execution with root privileges.
  - An attacker can gain full control of the system by injecting malicious commands.
  - Data exfiltration, system compromise, and denial of service are possible impacts.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
  - None. The code directly passes user-supplied options to the `mount.nfs4` or `mount_nfs` command without sanitization.
- Missing Mitigations:
  - Input sanitization and validation for all user-provided mount options, especially those passed to external commands.
  - Instead of directly passing options, construct the `mount.nfs4` or `mount_nfs` command arguments programmatically, ensuring each option and value is properly escaped and validated.
  - Consider using safer alternatives to shell execution when possible, or implement robust input validation to prevent command injection.
- Preconditions:
  - The attacker must be able to control the mount options passed to the `mount.efs` utility. This could be achieved if a higher-level application or script uses `mount.efs` and allows users to specify mount options, or if a user is directly executing the mount command.
  - The `mount.efs` utility must be executed with sudo privileges, which is the typical setup for mounting file systems.
- Source Code Analysis:
  - In `src/mount_efs/__init__.py`, the function `mount_nfs` constructs the `mount.nfs4` or `mount_nfs` command.
  - The `get_nfs_mount_options` function is called to generate the options string.
  - The `to_nfs_option` function directly formats the key and value using string concatenation without any sanitization or escaping.
  - The `get_nfs_mount_options` function then joins these options with commas and passes the entire string as the `-o` option to `mount.nfs4` or `mount_nfs`.
  - In the `mount_nfs` function, `subprocess.Popen` is used to execute the command, where user controlled options are directly passed.
  - An attacker can inject malicious code by providing an `nfsvers` option containing shell metacharacters.
- Security Test Case:
  - Prepare a test environment with `efs-utils` installed and configured.
  - Create a mount point directory, e.g., `/tmp/efs_test_mount`.
  - As a non-root user, attempt to mount an EFS file system using the `mount` command with a malicious `nfsvers` option:
    ```bash
    sudo mount -t efs -o nfsvers='4.1,$(touch /tmp/pwned),nosuid' file-system-id /tmp/efs_test_mount
    ```
  - Check if the file `/tmp/pwned` has been created.
  - If the file `/tmp/pwned` is created, it indicates that the argument injection vulnerability is present.

- Vulnerability Name: Argument Injection in `mount.efs` via `rsize` option
- Description:
  - Similar to the `nfsvers` vulnerability, an attacker can inject arbitrary commands via the `rsize` mount option.
  - The `rsize` option is also passed to `mount.nfs4` or `mount_nfs` without proper sanitization, allowing for command injection using shell-escaped characters.
- Impact:
  - Arbitrary command execution with root privileges, same as the `nfsvers` vulnerability.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
  - None.
- Missing Mitigations:
  - Same as the `nfsvers` vulnerability: input sanitization, programmatic argument construction, safer execution methods.
- Preconditions:
  - Similar to the `nfsvers` vulnerability: attacker control over mount options and `mount.efs` executed with sudo.
- Source Code Analysis:
  - The vulnerability lies in the same code sections as the `nfsvers` vulnerability, specifically in `get_nfs_mount_options` and `mount_nfs` functions.
- Security Test Case:
  - Prepare a test environment with `efs-utils`.
  - Create a mount point directory.
  - As a non-root user, attempt to mount an EFS file system with a malicious `rsize` option:
    ```bash
    sudo mount -t efs -o rsize='1048576,$(touch /tmp/pwned),nosuid' file-system-id /tmp/efs_test_mount
    ```
  - Check if `/tmp/pwned` is created.

- Vulnerability Name: Argument Injection in `mount.efs` via `wsize` option
- Description:
  -  An attacker can inject arbitrary commands via the `wsize` mount option, similar to `nfsvers` and `rsize`.
- Impact:
  - Arbitrary command execution with root privileges.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
  - None.
- Missing Mitigations:
  - Same as previous vulnerabilities: input sanitization, programmatic argument construction, safer execution methods.
- Preconditions:
  - Same as previous vulnerabilities.
- Source Code Analysis:
  - The vulnerability is in the same code sections as the previous vulnerabilities, affecting `wsize` option.
- Security Test Case:
  - Prepare a test environment.
  - Create a mount point directory.
  - Mount with a malicious `wsize` option:
    ```bash
    sudo mount -t efs -o wsize='1048576,$(touch /tmp/pwned),nosuid' file-system-id /tmp/efs_test_mount
    ```
  - Check if `/tmp/pwned` is created.

- Vulnerability Name: Argument Injection in `mount.efs` via `timeo` option
- Description:
  - An attacker can inject arbitrary commands via the `timeo` mount option.
- Impact:
  - Arbitrary command execution with root privileges.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
  - None.
- Missing Mitigations:
  - Same as previous vulnerabilities.
- Preconditions:
  - Same as previous vulnerabilities.
- Source Code Analysis:
  - The vulnerability is in the same code sections as the previous vulnerabilities, affecting `timeo` option.
- Security Test Case:
  - Prepare a test environment.
  - Create a mount point directory.
  - Mount with a malicious `timeo` option:
    ```bash
    sudo mount -t efs -o timeo='600,$(touch /tmp/pwned),nosuid' file-system-id /tmp/efs_test_mount
    ```
  - Check if `/tmp/pwned` is created.

- Vulnerability Name: Argument Injection in `mount.efs` via `retrans` option
- Description:
  - An attacker can inject arbitrary commands via the `retrans` mount option.
- Impact:
  - Arbitrary command execution with root privileges.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
  - None.
- Missing Mitigations:
  - Same as previous vulnerabilities.
- Preconditions:
  - Same as previous vulnerabilities.
- Source Code Analysis:
  - The vulnerability is in the same code sections as the previous vulnerabilities, affecting `retrans` option.
- Security Test Case:
  - Prepare a test environment.
  - Create a mount point directory.
  - Mount with a malicious `retrans` option:
    ```bash
    sudo mount -t efs -o retrans='2,$(touch /tmp/pwned),nosuid' file-system-id /tmp/efs_test_mount
    ```
  - Check if `/tmp/pwned` is created.

- Vulnerability Name: Argument Injection in `mount.efs` via `port` option (for non-TLS mounts)
- Description:
  - For non-TLS mounts, the `port` option is also vulnerable to argument injection.
- Impact:
  - Arbitrary command execution with root privileges.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
  - None.
- Missing Mitigations:
  - Same as previous vulnerabilities.
- Preconditions:
  - Same as previous vulnerabilities, but for non-TLS mounts.
- Source Code Analysis:
  - The vulnerability is in the same code sections as the previous vulnerabilities, affecting `port` option for non-TLS mounts.
- Security Test Case:
  - Prepare a test environment.
  - Create a mount point directory.
  - Mount with a malicious `port` option for non-TLS mount:
    ```bash
    sudo mount -t efs -o notls,port='2049,$(touch /tmp/pwned),nosuid' file-system-id /tmp/efs_test_mount
    ```
  - Check if `/tmp/pwned` is created.