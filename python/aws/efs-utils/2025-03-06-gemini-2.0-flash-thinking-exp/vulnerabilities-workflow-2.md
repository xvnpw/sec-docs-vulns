## Vulnerability List

- [Argument Injection Vulnerability via Multiple Mount Options](#argument-injection-vulnerability-via-multiple-mount-options)
- [Command Injection via `netns` Mount Option](#command-injection-via-netns-mount-option)

### Argument Injection Vulnerability via Multiple Mount Options

- **Vulnerability Name:** Argument Injection Vulnerability via Multiple Mount Options (`nfsvers`, `rsize`, `wsize`, `timeo`, `retrans`, `port`)
    - **Description:**
        1. An attacker can inject arbitrary commands into the `mount.efs` command line by crafting a malicious mount option such as `nfsvers`, `rsize`, `wsize`, `timeo`, `retrans`, or `port`.
        2. The `efs-utils` script passes these options directly to the underlying `mount.nfs4` or `mount_nfs` command without proper sanitization.
        3. By injecting shell-escaped characters within the option value, an attacker can break out of the intended option value and append arbitrary commands.
        4. When `mount.efs` executes the `mount.nfs4` or `mount_nfs` command via `subprocess.Popen`, the injected commands will be executed by the shell.
        5. Since `mount.efs` is typically executed with `sudo` privileges, the injected commands will also be executed with elevated (root) privileges.

    - **Impact:**
        *   Arbitrary command execution with root privileges.
        *   An attacker can gain full control of the system by injecting malicious commands.
        *   Data exfiltration, system compromise, and denial of service are possible impacts.

    - **Vulnerability Rank:** Critical

    - **Currently Implemented Mitigations:**
        *   None. The code directly passes user-supplied options to the `mount.nfs4` or `mount_nfs` command without sanitization.

    - **Missing Mitigations:**
        *   **Input sanitization and validation:** Implement strict input sanitization and validation for all user-provided mount options, especially those passed to external commands.  This should include escaping shell metacharacters or using a safer method to pass arguments.
        *   **Programmatic argument construction:** Instead of directly passing options, construct the `mount.nfs4` or `mount_nfs` command arguments programmatically, ensuring each option and value is properly escaped and validated.
        *   **Safer execution methods:** Consider using safer alternatives to shell execution when possible, such as using `subprocess.Popen` with argument lists instead of shell strings, or implement robust input validation to prevent command injection.

    - **Preconditions:**
        *   The attacker must be able to control the mount options passed to the `mount.efs` utility. This could be achieved if a higher-level application or script uses `mount.efs` and allows users to specify mount options, or if a user is directly executing the mount command.
        *   The `mount.efs` utility must be executed with `sudo` privileges, which is the typical setup for mounting file systems.

    - **Source Code Analysis:**
        1. In `src/mount_efs/__init__.py`, the function `mount_nfs` constructs the `mount.nfs4` or `mount_nfs` command.
        2. The `get_nfs_mount_options` function is called to generate the options string.
        3. The `to_nfs_option` function directly formats the key and value using string concatenation without any sanitization or escaping.
        4. The `get_nfs_mount_options` function then joins these options with commas and passes the entire string as the `-o` option to `mount.nfs4` or `mount_nfs`.
        5. In the `mount_nfs` function, `subprocess.Popen` is used to execute the command, where user controlled options are directly passed as part of a shell command.
        6. An attacker can inject malicious code by providing any of the vulnerable options (`nfsvers`, `rsize`, `wsize`, `timeo`, `retrans`, `port`) containing shell metacharacters.

    - **Security Test Case:**
        1. Prepare a test environment with `efs-utils` installed and configured.
        2. Create a mount point directory, e.g., `/tmp/efs_test_mount`.
        3. As a non-root user, attempt to mount an EFS file system using the `mount` command with a malicious `nfsvers` option (you can test with other vulnerable options as well, like `rsize`, `wsize`, `timeo`, `retrans`, or `port`):
        ```bash
        sudo mount -t efs -o nfsvers='4.1,$(touch /tmp/pwned),nosuid' file-system-id /tmp/efs_test_mount
        ```
        Replace `file-system-id` with a placeholder EFS file system ID (it does not need to be a valid ID for this test, as the goal is to test command injection before the mount attempt).
        4. Check if the file `/tmp/pwned` has been created:
        ```bash
        ls /tmp/pwned
        ```
        If the file `/tmp/pwned` is created, it indicates that the argument injection vulnerability is present.

### Command Injection via `netns` Mount Option

- **Vulnerability Name:** Command Injection via `netns` Mount Option
    - **Description:**
        1. An attacker can craft a malicious mount command using the `mount.efs` utility.
        2. This command includes the `-o netns=<malicious_path>` option, where `<malicious_path>` contains a command injection payload.
        3. When `mount.efs` is executed with this crafted command, it attempts to use the provided `netns` path in conjunction with `nsenter`.
        4. Due to insufficient sanitization in the `mount.efs` script, the malicious payload within the `netns` option is executed as part of the `nsenter` command.
        5. This results in arbitrary command execution on the system with the privileges of the `mount.efs` utility, typically root.

    - **Impact:**
        *   Arbitrary command execution with elevated privileges (root) on the system.
        *   This could lead to complete system compromise, including data theft, malware installation, and denial of service.

    - **Vulnerability Rank:** Critical

    - **Currently Implemented Mitigations:**
        *   None. The code does not sanitize or validate the `netns` mount option value before using it in shell commands.

    - **Missing Mitigations:**
        *   **Input validation:** Implement strict validation and sanitization of the `netns` mount option to prevent command injection.
        *   **Use safer alternatives to shell commands:** Refactor the code to avoid using shell commands for network namespace manipulation, if possible, or use parameterized commands to prevent injection.
        *   **Principle of least privilege:** While `mount.efs` likely needs root privileges for mounting, ensure that any external command execution is performed with the minimal privileges necessary, if refactoring to avoid shell commands is not feasible.

    - **Preconditions:**
        *   The attacker must have the ability to execute the `mount` command, which is typically restricted to users with `sudo` privileges or root.
        *   The `efs-utils` package must be installed, making the `mount.efs` utility available.

    - **Source Code Analysis:**
        1. In `/code/src/mount_efs/__init__.py`, the `mount_nfs` function constructs the mount command.
        2. When the `netns` option is provided, the script prepends the `nsenter` command with the user-supplied `netns` path to the mount command:
        ```python
        if "netns" in options:
            command = ["nsenter", "--net=" + options["netns"]] + command
        ```
        3. The `options["netns"]` value, which is directly derived from user input via the `-o netns=` mount option, is concatenated into the shell command without any sanitization.
        4. This allows for command injection. For example, if an attacker provides `-o netns="/path/to/netns; whoami > /tmp/pwned"`, the resulting command becomes:
        ```bash
        nsenter --net=/path/to/netns; whoami > /tmp/pwned /sbin/mount.nfs4 ...
        ```
        5. This will execute `whoami > /tmp/pwned` before the intended `nsenter` and `mount.nfs4` commands, leading to arbitrary command execution.
        ```mermaid
        graph LR
            A[mount command with -o netns=/malicious/path] --> B(mount.efs script);
            B --> C{parse_arguments()};
            C --> D[Extract netns option value];
            D --> E[Construct nsenter command with user-supplied path];
            E --> F[subprocess.Popen(nsenter command)];
            F --> G[mount.nfs4 executed (command injection happened before)];
            G --> H[Arbitrary Command Execution];
        ```

    - **Security Test Case:**
        1. Prepare a test environment with `efs-utils` installed and a writable temporary directory (`/tmp/efs_test_mount`).
        2. As a non-root user, execute the following mount command to attempt command injection:
        ```bash
        sudo mount -t efs -o netns='/tmp/pwned; touch /tmp/efs_pwned_file' <file_system_id> /tmp/efs_test_mount
        ```
        Replace `<file_system_id>` with a placeholder EFS file system ID (it does not need to be a valid ID for this test, as the goal is to test command injection before the mount attempt).
        3. Check if the file `/tmp/efs_pwned_file` has been created:
        ```bash
        ls /tmp/efs_pwned_file
        ```
        If the file exists, it confirms that the command injection was successful.
        4. Examine the file permissions of `/tmp/efs_pwned_file`. It should be owned by `root` because `mount.efs` is executed with root privileges via `sudo`.