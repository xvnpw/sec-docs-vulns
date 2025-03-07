### Vulnerability List

- Vulnerability Name: Overly Permissive File Permissions in Deployment Instructions
- Description:
    1. The documentation for "Zero to Batch" scenario instructs users to execute `sudo chmod 777 \*` in step 7 "Give the Permission" and `sudo chmod +rx \*` in step 11 "(Optional) Give the Permission only if the user does not have permissions.".
    2. These commands, if executed in the wrong directory or without understanding the implications, set overly permissive file permissions (777 - read, write, and execute for all users, and +rx - read and execute for all users) on files and directories.
    3. An attacker could potentially leverage these overly permissive permissions to modify scripts, configuration files, or access sensitive data within the deployed environment.
- Impact:
    - Unauthorized access to sensitive data.
    - Modification of system configurations.
    - Execution of arbitrary code by unauthorized users.
    - Potential compromise of the deployed HPC environment.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The documentation explicitly instructs users to apply these commands.
- Missing Mitigations:
    - **Remove or correct the `chmod 777` and `chmod +rx` instructions from the documentation.** Provide more specific and secure permission settings if necessary.
    - **Educate users about the risks of overly permissive file permissions.** Add warnings in the documentation about using `chmod 777` and `chmod +rx` and recommend more restrictive permissions.
    - **Automate permission hardening in deployment scripts.** Ensure that deployment scripts set secure default permissions for all files and directories.
- Preconditions:
    - User follows the "Zero to Batch" documentation and executes the `chmod 777 \*` and `chmod +rx \*` commands as instructed.
- Source Code Analysis:
    - File: `/code/scenarios/batch/docs/Zero to Batch.md`
    - Step 7 and Step 11 of the "Deployment & Use" section in the "Zero to Batch.md" documentation contain the vulnerable commands:
        ```
        7.  Give the Permission

            Example: sudo chmod 777 \*

            ls -ltr

            ![](media/image19.png)

        11. (Optional) Give the Permission only if the user does not have permissions.

            Example: sudo chmod +rx \*

            ls -ltr

            ![](media/image23.png)
        ```
    - These commands are presented as part of the standard deployment procedure, encouraging users to apply overly permissive permissions.
- Security Test Case:
    1. Deploy the "Zero to Batch" scenario on Azure, following the instructions in `/code/scenarios/batch/docs/Zero to Batch.md`. In step 7 and step 11, execute the commands `sudo chmod 777 \*` and `sudo chmod +rx \*` in the specified directories as instructed.
    2. After deployment, log in to the deployed VM as a non-root user (or assume an attacker gains access to a non-root account).
    3. Navigate to the directories where `chmod 777 \*` and `chmod +rx \*` were executed (e.g., the repository root and `bin/` directory).
    4. Attempt to modify a script file (e.g., `deploy.sh` or `inject.sh`) in the `bin/` directory. Due to the `chmod 777` or `chmod +rx` permissions, the non-root user should be able to modify the file if `chmod 777` was used, or at least read and execute if `chmod +rx` was used on executable files.
    5. If the non-root user can successfully modify or execute the script, this confirms the vulnerability. An attacker could replace the script with malicious code, gaining control over the system or exfiltrating data.