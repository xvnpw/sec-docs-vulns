- Vulnerability Name: Incomplete Rollback of vhost Configuration Changes on Failure
- Description:
    - An attacker cannot directly trigger this vulnerability, but it can be exposed during normal operation if an unexpected error occurs during the HTTPS setup process.
    - The `https-rewrite.py` script modifies the Apache virtual host configuration file (`wordpress-vhost.conf`) to enable HTTP to HTTPS redirection.
    - Before modifying the file, the script creates a backup.
    - During the modification process, if an error occurs (e.g., disk full, permission issues, or any exception during file writing), the script attempts to rollback the changes by copying the backup file back to the original location.
    - However, the rollback mechanism is not atomic. If the error occurs after the script has already started writing changes to `wordpress-vhost.conf` (potentially truncating or partially modifying it), but before the new configuration is fully written, the rollback might not fully restore the original configuration.
    - This can happen if the `open(file_path, "w")` operation succeeds in truncating the file, but subsequent `fh.writelines()` operations fail.
    - If the rollback (`cp {file_path}.backup {file_path}`) also fails, or if the backup itself was somehow corrupted or incomplete prior to the initial write operation, the `wordpress-vhost.conf` file could be left in an inconsistent state.
    - An inconsistent `wordpress-vhost.conf` might not correctly enforce HTTP to HTTPS redirection.
    - Consequently, users accessing the website via HTTP might not be redirected to HTTPS, leaving them vulnerable to man-in-the-middle attacks.
- Impact:
    - Failed rollback can lead to a misconfigured Apache virtual host, where HTTP to HTTPS redirection is not properly enabled.
    - Users accessing the website over HTTP will not be automatically redirected to HTTPS, resulting in unencrypted communication.
    - This allows man-in-the-middle attackers to intercept sensitive data transmitted over HTTP, such as login credentials, personal information, or session cookies.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations:
    - The script attempts to create a backup of the `wordpress-vhost.conf` file before modification:
        ```python
        returncode, stdout, stderr = run_cmd(f'cp {vhost_full_path} {vhost_full_path}.backup')
        ```
    - The script attempts to rollback changes by copying the backup file back in case of an exception during modification:
        ```python
        except Exception as ex:
            log_error(ex)
            log_info(f"Rolling back the vhost file: {vhost_full_path}")
            run_cmd(f'cp {vhost_full_path}.backup {vhost_full_path}')
            return 1
        ```
    - Error logging is implemented to record exceptions and rollback attempts.
- Missing Mitigations:
    - Atomic file operations for modifying `wordpress-vhost.conf` to minimize the risk of leaving the file in an inconsistent state during errors. Instead of directly writing to the original file, the script could write to a temporary file and then atomically replace the original file with the temporary file.
    - More robust error handling for file operations, specifically checking the return code of the `cp` command used for rollback to ensure the rollback operation itself was successful. If rollback fails, more aggressive error handling or administrative alerts should be considered.
    - Integrity checks (e.g., checksums) for the backup file to ensure it's a valid copy before attempting rollback.
    - Automated tests specifically designed to simulate failure scenarios during vhost file modification and verify the effectiveness of the rollback mechanism.
- Preconditions:
    - The `https-rewrite.py` script must be executed to enable HTTPS redirection.
    - An error condition must occur during the `modify_vhost_conf` function while writing to `wordpress-vhost.conf`. This could be due to various system-level issues like disk full, write permission restrictions, or other unexpected exceptions during file I/O.
- Source Code Analysis:
    - The `modify_vhost_conf` function in `/code/https-rewrite.py` is responsible for updating the Apache vhost configuration.
    - The function starts by reading the content of the `wordpress-vhost.conf` file:
        ```python
        with open(file_path, "r") as fh:
            while True:
                line = fh.readline()
                if not line:
                    break
                # ... processing lines ...
        ```
    - Then, it opens the same file in write mode (`"w"`):
        ```python
        with open(file_path, "w") as fh:
            # ... writing modified content ...
            fh.writelines(f"{line}{NEWLINE}")
        ```
        - Opening a file in `"w"` mode in Python truncates the file immediately upon opening. If an error occurs during the subsequent `fh.writelines()` operations, the original content is already lost, and the new content is only partially written.
    - If an exception occurs within the `try` block during file writing, the `except` block is executed:
        ```python
        except Exception as ex:
            log_error(ex)
            log_info(f"Rolling back the vhost file: {file_path}")
            run_cmd(f'cp {file_path}.backup {file_path}')
            return 1
        ```
        - The rollback is attempted by copying the backup file (`{file_path}.backup`) back to the original file path (`{file_path}`).
        - However, there's no check to ensure that the `cp` command in the rollback was successful. If the rollback itself fails (e.g., due to similar issues that caused the initial write to fail, or new issues), the `wordpress-vhost.conf` file could remain in a broken state.
        - The generic exception handling might catch various errors, but the core vulnerability lies in the non-atomic file modification and the potential for rollback failure, leading to inconsistent vhost configuration.

- Security Test Case:
    1. Precondition: Ensure HTTP to HTTPS redirection is disabled. Access the WordPress site via both HTTP and HTTPS and confirm that HTTP does *not* redirect to HTTPS.
    2. Simulate a write error: Before running the `https-rewrite.py` script, make the `wordpress-vhost.conf` file temporarily read-only for the user executing the script. For example, use `sudo chmod a-w /opt/bitnami/apache/conf/vhosts/wordpress-vhost.conf`.
    3. Execute the script: Run the HTTPS rewrite script: `sudo python3 /opt/bitnami/lightsail/scripts/https-rewrite.py <your_certificate_name>`.
    4. Check for errors: Observe the output of the script and check the log file (`/opt/bitnami/lightsail/https_rewrite_<datetime>.log`) for error messages. You should see errors related to file write operations and the script attempting a rollback.
    5. Verify vhost configuration: Inspect the content of `/opt/bitnami/apache/conf/vhosts/wordpress-vhost.conf`. Check if the file is empty, partially modified, or contains corrupted data, indicating an incomplete write and potentially failed rollback.
    6. Test HTTP access: Attempt to access the WordPress website using HTTP (`http://your_domain.com`).
    7. Expected Outcome: If the rollback was incomplete or failed, HTTP to HTTPS redirection will likely not be functional. The website should be accessible over HTTP without being redirected to HTTPS. This confirms the vulnerability, as it demonstrates that a failure during the script execution can lead to a state where HTTP traffic is not secured by automatic redirection, making it susceptible to man-in-the-middle attacks.
    8. Clean up: Restore write permissions to `wordpress-vhost.conf` using `sudo chmod a+w /opt/bitnami/apache/conf/vhosts/wordpress-vhost.conf`. You might need to manually restore the `wordpress-vhost.conf.backup` to `wordpress-vhost.conf` if the script left it in a broken state, or re-run the `https-rewrite.py` script after fixing the permission issue to attempt a successful HTTPS setup.