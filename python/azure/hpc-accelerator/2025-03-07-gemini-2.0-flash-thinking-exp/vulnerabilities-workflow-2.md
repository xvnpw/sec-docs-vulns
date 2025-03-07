## Combined Vulnerability List

### Vulnerability Name: Overly Permissive File Permissions

- Description:
    1. The documentation for "Zero to Batch" scenario instructs users to execute `sudo chmod 777 \*` in step 7 "Give the Permission" and `sudo chmod +rx \*` in step 11 "(Optional) Give the Permission only if the user does not have permissions.". Additionally, the documentation also instructs users to run `sudo chmod 777 \*` in step 7 after cloning the repository and `sudo chmod 777 src/\*` in step 15.a if permission errors occur during script execution.
    2. These commands, if executed as instructed, set overly permissive file permissions (777 - read, write, and execute for all users, and +rx - read and execute for all users) on files and directories. This grants read, write, and execute permissions to all users on all files and directories within the current directory and `src` directory, respectively.
    3. An attacker could potentially leverage these overly permissive permissions to modify scripts, configuration files, or access sensitive data within the deployed environment. This practice weakens the security posture of the deployed environment by allowing any user within the system to modify or execute these files, potentially leading to unauthorized access or malicious modifications.

- Impact:
    - Unauthorized access to sensitive data.
    - Modification of system configurations.
    - Execution of arbitrary code by unauthorized users.
    - Potential compromise of the deployed HPC environment.
    - Any user on the VM, including potentially compromised services or accounts, can read, modify, or execute files, leading to data breaches or system compromise.
    - Privilege escalation: If scripts with overly permissive permissions are executed with elevated privileges (e.g., via cron jobs or system services), attackers could potentially escalate their privileges.
    - Data integrity compromise: Malicious users or processes can modify scripts or data files, leading to incorrect computations, data corruption, or system instability.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None. The documentation explicitly instructs users to apply these commands. No mitigations are implemented in the provided project files. The documentation actively encourages the use of overly permissive permissions.

- Missing Mitigations:
    - **Remove or correct the `chmod 777` and `chmod +rx` instructions from the documentation.** Provide more specific and secure permission settings if necessary. Remove or replace `chmod 777` commands with more restrictive permissions (e.g., `chmod 755` for scripts, `chmod 644` for data files, and appropriate ownership settings using `chown`).
    - **Educate users about the risks of overly permissive file permissions.** Add warnings in the documentation about using `chmod 777` and `chmod +rx` and recommend more restrictive permissions. Educate users against using `chmod 777` and provide secure alternatives in documentation.
    - **Automate permission hardening in deployment scripts.** Ensure that deployment scripts set secure default permissions for all files and directories. Implement proper user and group management to control access to files and directories based on the principle of least privilege.

- Preconditions:
    - User follows the "Zero to Batch" documentation and executes the `chmod 777 \*` and `chmod +rx \*` commands as instructed.
    - Successful deployment of an HPC environment using the provided scripts and following the documentation.
    - User follows the instructions in `Zero to Batch.md` and executes the `chmod 777` commands.

- Source Code Analysis:
    - File: `/code/scenarios/batch/docs/Zero to Batch.md`
        - Step 7 of the "Deployment & Use" section contains the vulnerable command:
        ```
        7.  Give the Permission

            Example: sudo chmod 777 \*
        ```
        - Step 11 of the "Deployment & Use" section contains the vulnerable command:
        ```
        11. (Optional) Give the Permission only if the user does not have permissions.

            Example: sudo chmod +rx \*
        ```
        - Step 15.a: "Note: If you get a permission error, move back to the root folder and run the following command. Example: `cd ..` `sudo chmod 777 src/\*`"
    - These instructions explicitly guide users to set overly permissive file permissions using `chmod 777` and `chmod +rx`. This command recursively sets read, write, and execute permissions for all users (owner, group, and others) on all files and directories within the specified path. These commands are presented as part of the standard deployment procedure, encouraging users to apply overly permissive permissions.

- Security Test Case:
    1. Deploy the "Zero to Batch" scenario on Azure, following the instructions in `/code/scenarios/batch/docs/Zero to Batch.md`. In step 7 and step 11, execute the commands `sudo chmod 777 \*` and `sudo chmod +rx \*` in the specified directories as instructed. In step 7 of `Zero to Batch.md`, execute the command `sudo chmod 777 \*` as instructed.
    2. After deployment, log in to the deployed VM as a non-root user (or assume an attacker gains access to a non-root account). Log in to the deployed VM as a non-administrator user (or use a different SSH session if logged in as administrator).
    3. Navigate to the directories where `chmod 777 \*` and `chmod +rx \*` were executed (e.g., the repository root and `bin/` directory). Navigate to the cloned repository directory.
    4. Attempt to modify a script file (e.g., `deploy.sh` or `inject.sh`) in the `bin/` directory. For example, `/code/hpc_azfinsim2/bin/deploy.sh` using a text editor like `nano` or `vi`. Due to the `chmod 777` or `chmod +rx` permissions, the non-root user should be able to modify the file if `chmod 777` was used, or at least read and execute if `chmod +rx` was used on executable files.
    5. If the non-root user can successfully modify or execute the script, this confirms the vulnerability. An attacker could replace the script with malicious code, gaining control over the system or exfiltrating data. Verify that the non-administrator user is able to modify and save the script file without permission errors. This confirms that the overly permissive permissions set by `chmod 777` allow unauthorized modification of system files by any user on the system.

### Vulnerability Name: SELinux Disabled

- Description:
    The provided scripts, specifically within the `/code/scenarios/deeplearning/code/slurm-ndv4/install/` directory, disable Security-Enhanced Linux (SELinux) on deployed virtual machines. SELinux is a security module for the Linux kernel that provides mandatory access control (MAC). Disabling SELinux weakens the security posture of the system by removing a critical layer of defense against various types of attacks, including malware and privilege escalation.  The scripts use `setenforce 0` to set SELinux to permissive mode (partially disabled for the current session) and modify `/etc/selinux/config` to permanently disable SELinux after reboot by setting `SELINUX=disabled`.

- Impact:
    - Increased attack surface: Disabling SELinux significantly increases the attack surface of the deployed VMs, making them more vulnerable to exploits.
    - Malware infections: Without SELinux, malware has fewer restrictions and can more easily compromise the system.
    - Privilege escalation: Exploits that might be contained by SELinux can lead to full system compromise when SELinux is disabled.
    - Compliance violations: Disabling SELinux may violate security compliance requirements in regulated environments.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - No mitigations are implemented. The scripts actively disable SELinux.

- Missing Mitigations:
    - Remove scripts that disable SELinux.
    - Configure SELinux policies to be compatible with the HPC environment requirements instead of disabling it.
    - Document the importance of keeping SELinux enabled and provide guidance on SELinux policy customization for advanced users if needed.

- Preconditions:
    - Deployment of a deep learning HPC environment using the scripts from `/code/scenarios/deeplearning/code/slurm-ndv4/`.
    - Scripts in the `install` directory are executed as part of the deployment process.

- Source Code Analysis:
    - File: `/code/scenarios/deeplearning/code/slurm-ndv4/scripts/disable-selinux.sh`
        - `setenforce 0`: Sets SELinux to permissive mode for the current session.
        - `sed -i 's/SELINUX=.*$/SELINUX=disabled/g' /etc/selinux/config`: Modifies the SELinux configuration file to disable SELinux permanently after system reboot.
    - Files: `/code/scenarios/deeplearning/code/slurm-ndv4/install/01_disable-selinux.sh`, `/code/scenarios/deeplearning/code/slurm-ndv4/install/04_disable-selinux.sh`
        - These install scripts execute the `disable-selinux.sh` script on target VMs using `pssh`. This ensures SELinux is disabled on all nodes where these install scripts are run.

- Security Test Case:
    1. Deploy a deep learning HPC environment using the scripts from `/code/scenarios/deeplearning/code/slurm-ndv4/`.
    2. SSH into one of the deployed VMs after the deployment process is complete.
    3. Run the command `getenforce` to check the current SELinux status.
    4. Verify that the output is "Permissive" or "Disabled", indicating that SELinux is not enforcing security policies.
    5. Check the content of `/etc/selinux/config` file and verify that `SELINUX=disabled` is set.
    6. This confirms that the deployment scripts successfully disable SELinux, weakening the system's security.

### Vulnerability Name: Hardcoded Password in Scripts

- Description:
    Several scripts within `/code/scenarios/deeplearning/code/slurm-ndv4/install/` directory contain a hardcoded password string `'+ODgyZjBiOWUwOWQ4'`. This password appears to be intended for CycleCloud CLI initialization and potentially other internal processes. Hardcoding passwords directly in scripts is a critical security vulnerability as it exposes sensitive credentials to anyone who can access the scripts. An attacker gaining access to these scripts can easily extract the password and potentially use it to gain unauthorized access to the CycleCloud server or other systems where this password might be reused.

- Impact:
    - Credential exposure: The hardcoded password is easily discoverable by anyone with access to the project's source code or the deployed VM if the scripts are copied there.
    - Unauthorized access: Attackers can use the exposed password to gain unauthorized access to the CycleCloud server, potentially leading to cluster compromise, data breaches, or denial of service.
    - Lateral movement: If the hardcoded password is reused across multiple systems or services, attackers can use it for lateral movement within the network.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - No mitigations are implemented. The password is directly embedded in the scripts.

- Missing Mitigations:
    - Remove the hardcoded password from all scripts.
    - Implement secure password management practices, such as using environment variables, Azure Key Vault, or other secure secret storage mechanisms to handle sensitive credentials.
    - Ensure that passwords are never stored in plaintext in scripts or configuration files.

- Preconditions:
    - Deployment of a deep learning HPC environment using the scripts from `/code/scenarios/deeplearning/code/slurm-ndv4/`.
    - Scripts in the `install` directory, specifically those related to CycleCloud CLI installation, are executed.
    - An attacker gains access to the scripts, either by accessing the source code repository or the deployed VM.

- Source Code Analysis:
    - Files: `/code/scenarios/deeplearning/code/slurm-ndv4/install/09_cyclecli_install.sh`, `/code/scenarios/deeplearning/code/slurm-ndv4/install/08_cyclecli_install.sh`, `/code/scenarios/deeplearning/code/slurm-ndv4/install/07_cc_install_managed_identity.sh`
        - These scripts contain the following command pattern:
          `scripts/cyclecli_install.sh '10.21.1.5' 'hpcadmin' '+ODgyZjBiOWUwOWQ4' '8'`
          or
          `scripts/cc_install_managed_identity.sh 'cycleserver' 'hpcadmin' '+ODgyZjBiOWUwOWQ4' 'jrs02' '8'`
        - In these commands, `'+ODgyZjBiOWUwOWQ4'` is a hardcoded password string passed as an argument to the `cyclecli_install.sh` or `cc_install_managed_identity.sh` scripts.
    - File: `/code/scenarios/deeplearning/code/slurm-ndv4/scripts/cyclecli_install.sh`
        - This script receives the hardcoded password as the `$3` argument and uses it in the `cyclecloud initialize` command:
          `~/bin/cyclecloud initialize --force --batch ... --password="${password}"`
        - This confirms that the hardcoded string is indeed used as a password for CycleCloud CLI initialization.

- Security Test Case:
    1. Access the file `/code/scenarios/deeplearning/code/slurm-ndv4/install/09_cyclecli_install.sh` or any of the scripts mentioned above.
    2. Open the file and examine its content.
    3. Locate the hardcoded password string `'+ODgyZjBiOWUwOWQ4'` within the script in the `scripts/cyclecli_install.sh` or `scripts/cc_install_managed_identity.sh` command execution.
    4. Decode the base64 encoded password `'+ODgyZjBiOWUwOWQ4'` using a base64 decoder. The decoded value is `Password1`.
    5. Attempt to log in to the CycleCloud UI using the username `hpcadmin` (or `cycleserver` depending on the script) and the decoded password `Password1`.
    6. Verify that login is successful using the hardcoded password.
    7. This confirms that the hardcoded password can be extracted from the scripts and used for unauthorized access to the CycleCloud server.

### Vulnerability Name: Hardcoded Default Password in VM Setup Documentation

- Description:
    The documentation for "Zero to Batch" and "HPC Skilling Hands-On Lab NDv4" provides instructions that include setting up a Virtual Machine (VM) with a default password "Password1". If users follow these instructions without changing the password, the VM will be vulnerable to unauthorized access.

- Impact:
    - Unauthorized access to the deployed VM. An attacker could gain complete control over the VM, potentially accessing sensitive data, modifying configurations, or using it as a stepping stone for further attacks.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None in the project itself. The documentation mentions best practices for securing Azure Batch in `/code/scenarios/batch/docs/Zero to Batch.md`, but these are general recommendations, not specific mitigations for this vulnerability.

- Missing Mitigations:
    - The documentation should explicitly warn against using default passwords and instruct users to set strong, unique passwords during VM deployment.
    - The deployment scripts should ideally enforce password complexity or provide mechanisms to generate and securely manage passwords.

- Preconditions:
    - User follows the documentation and deploys the VM without changing the default password.

- Source Code Analysis:
    - File: `/code/scenarios/batch/docs/Zero to Batch.md` and `/code/scenarios/deeplearning/docs/HPC Skilling Hands-On Lab NDv4.md`
        1.  The documentation guides users to deploy a VM using ARM templates.
        2.  Step 2c in "Zero to Batch.md" and similar steps in "HPC Skilling Hands-On Lab NDv4.md" instruct users to "change the password if you need", implying that a default password exists and is acceptable to use.
        3.  The provided images in the documentation (e.g., `media/image9.png`) show a default username and password field, suggesting a default password is set or expected.
        4.  The documentation examples use `Password1` as the password.

- Security Test Case:
    1. Deploy the "Zero to Batch" or "HPC Skilling Hands-On Lab NDv4" lab environment following the documentation *exactly*, including using the default password "Password1" when prompted during VM deployment.
    2. Once the VM is deployed, attempt to SSH into the VM using the username `deployeradmin` (from documentation) and the password `Password1`.
    3. If the SSH login is successful, the vulnerability is confirmed.