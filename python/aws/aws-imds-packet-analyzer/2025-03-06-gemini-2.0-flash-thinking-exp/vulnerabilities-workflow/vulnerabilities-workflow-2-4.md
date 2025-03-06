### Vulnerability List:

- Vulnerability Name: Insecure Permissions on Log Directory
- Description:
    - Step 1: The `imds_snoop.py` script is executed, typically by root, to start tracing IMDS calls.
    - Step 2: The script checks if the log directory `/var/log/imds` exists. If it doesn't exist, it creates the directory using `os.makedirs(LOG_IMDS_FOLDER)`.
    - Step 3: After creation (or if the directory already exists), the script attempts to set directory permissions to `0o600` using `os.chmod(LOG_IMDS_FOLDER, 0o600)`. However, `0o600` for a directory is overly restrictive as it prevents even the owner (root) from listing the directory contents. The intended behavior is likely to restrict access to the log files to root user only, but the directory permission setting is incorrect for this purpose.
    - Step 4: Due to potential race conditions during directory creation or misconfiguration, the directory might be created with more permissive default permissions or the `chmod` operation might fail, resulting in a log directory accessible by non-root users.
    - Step 5: If the log directory permissions are more permissive than intended (e.g., `drwxr-xr-x` or `drwxrwxr-x`), a local attacker (non-root user) can list the contents of the `/var/log/imds` directory and potentially read the log files, such as `imds-trace.log`.
    - Step 6: By reading the log files, a local attacker can gain information about processes making IMDS calls, including process names, command-line arguments, and the type of IMDS calls (v1 or v2). This information can be used to identify potential targets for SSRF attacks or to understand system behavior.
- Impact:
    - Information Disclosure: A local attacker can gain unauthorized access to log files containing information about processes making IMDS calls. This information, while not directly sensitive credentials, can reveal details about running applications and their potential vulnerabilities related to IMDSv1 usage, aiding in further reconnaissance and potential exploitation by the attacker.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations:
    - The `imds_snoop.py` script attempts to set the permissions of the log directory `/var/log/imds` to `0o600` using `os.chmod`.
    - The script checks existing permissions and attempts to reset them if they are not as intended.
- Missing Mitigations:
    - Correct Directory Permissions: The script should use `os.makedirs(LOG_IMDS_FOLDER, mode=0o700, exist_ok=True)` to create the directory with the intended permissions (root-only access and allow directory listing for root). `0o700` ensures that only the owner (root) has read, write, and execute permissions on the directory, which is necessary for root to access the log files within.
    - Robust Permission Setting: Ensure that directory and file permissions are set atomically during creation to minimize race conditions.
    - Regular Permission Checks: Implement periodic checks to verify and enforce the correct permissions on the log directory and log files, ensuring they remain restricted to root access.
- Preconditions:
    - Local access to the EC2 instance as a non-root user.
    - The `/var/log/imds` directory must have insecure permissions that allow read or execute access to non-root users. This could occur due to race conditions during directory creation, manual misconfiguration, or if the `chmod` command fails to execute correctly.
- Source Code Analysis:
    - File: `/code/src/imds_snoop.py`
    ```python
    LOG_IMDS_FOLDER = "/var/log/imds"
    ...
    if not os.path.exists(LOG_IMDS_FOLDER):
        os.makedirs(LOG_IMDS_FOLDER)

    st = os.stat(LOG_IMDS_FOLDER)
    if bool(st.st_mode & 0o00077):
        print("Setting log folder to root RW access only, permission was: " + str(oct(st.st_mode & 0o00777)))
        os.chmod(LOG_IMDS_FOLDER, 0o600)
    ```
    - The code first checks if the log directory exists and creates it if not.
    - It then retrieves the directory's status using `os.stat` and checks if any permissions are set for the group or others (`0o00077`).
    - If group or other permissions are detected, it attempts to set the directory mode to `0o600`.
    - **Vulnerability**: The use of `0o600` for directory permissions is incorrect. It should be `0o700` to allow root to list and access files within the directory while restricting access to other users. Also, there is a potential race condition between directory creation and setting permissions. Additionally, the check `bool(st.st_mode & 0o00077)` is broad and might not reliably detect if permissions are insecure in a way that allows listing and reading by non-root users.
- Security Test Case:
    - Step 1: On an EC2 instance where the tool is intended to be deployed, log in as a non-root user (e.g., `ec2-user` on Amazon Linux).
    - Step 2: Ensure that the `/var/log/imds` directory does not exist. If it exists, remove it as root using `sudo rm -rf /var/log/imds`.
    - Step 3: Execute the `imds_snoop.py` script as root using `sudo python3 src/imds_snoop.py`. Let it run for approximately one minute to ensure the log directory is created and potentially populated with logs. Then, stop the script by pressing `Ctrl+C`.
    - Step 4: As the non-root user, check the permissions of the `/var/log/imds` directory using the command `ls -ld /var/log/imds`.
    - Step 5: **Expected Secure Outcome**: The permissions should be `drwx------ root root` (or similar, indicating only root has full access).
    - Step 6: **Vulnerability Condition**: If the permissions are more permissive, such as `drwxr-xr-x root root` or `drwxrwxr-x root root`, proceed to the next step to confirm information disclosure.
    - Step 7: If the permissions are more permissive (e.g., `drwxr-xr-x`), attempt to list the contents of the directory as the non-root user using `ls /var/log/imds`. If you can successfully list the directory contents, it indicates that the directory permissions are insecure.
    - Step 8: If directory listing is successful, attempt to read the log file (e.g., `imds-trace.log`) using `cat /var/log/imds/imds-trace.log`. If you can read the log file and it contains information about IMDS calls (process names, command arguments, IMDS versions), then the vulnerability is confirmed, as a non-root user has gained unauthorized access to sensitive log information.