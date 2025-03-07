- Vulnerability Name: Insecure Default Symphony Administrator Password

- Description:
  - The IBM Spectrum Symphony master installation script `010_install_symphony_master.sh` automatically sets the Symphony administrator password to a weak default value "Admin" using the command `egoconfig setpassword -x Admin`.
  - An attacker with network access to the deployed IBM Spectrum Symphony web interface or command-line tools can attempt to log in using the default username "Admin" and the password "Admin".
  - If successful, the attacker gains administrative access to the IBM Spectrum Symphony cluster.

- Impact:
  - **Critical.** Full administrative access to the IBM Spectrum Symphony cluster.
  - An attacker can manage workloads, access sensitive data processed by Symphony, potentially pivot to other systems within the network, and disrupt cluster operations.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
  - None. The script explicitly sets a weak default password.

- Missing Mitigations:
  - **Enforce Strong Password Policy:** The deployment scripts should enforce the setting of a strong, non-default administrator password during the automated deployment process.
    - This could be achieved by:
      - Generating a random password and securely storing it (e.g., in Azure Key Vault or CycleCloud secrets).
      - Prompting the user to provide a strong password during deployment setup.
      - Integrating with a password management system.
  - **Password Complexity Requirements:** Implement password complexity requirements (minimum length, character types) if prompting for user input.
  - **Post-Deployment Security Hardening Guidance:** Provide clear documentation and instructions on how to change the default password immediately after deployment and implement other security best practices for IBM Spectrum Symphony.

- Preconditions:
  - IBM Spectrum Symphony cluster deployed using the provided scripts.
  - Network access to the IBM Spectrum Symphony web interface or command-line tools.
  - Default username "Admin" is not changed.

- Source Code Analysis:
  - File: `/code/specs/master/cluster-init/scripts/010_install_symphony_master.sh`
  - Line: `su - -c "source /etc/profile.d/symphony.sh && yes | egoconfig setpassword -x Admin && egoconfig setentitlement ${SYM_ENTITLEMENT_FILE}" egoadmin`
  - Visualization:
    ```
    010_install_symphony_master.sh --> egoconfig setpassword -x Admin --> Sets default password to "Admin"
    ```
  - Step-by-step analysis:
    1. The script `010_install_symphony_master.sh` is executed during the master node initialization process.
    2. The script switches to the `egoadmin` user using `su - -c`.
    3. Inside the `egoadmin` user context, it sources the Symphony environment script `/etc/profile.d/symphony.sh`.
    4. The command `egoconfig setpassword -x Admin` is executed with `yes` piped to it to bypass interactive prompts.
    5. `egoconfig setpassword -x Admin` sets the Symphony administrator password to the hardcoded value "Admin".
    6. The script continues with other Symphony configuration steps, but the insecure default password remains set.

- Security Test Case:
  - Precondition: Deploy IBM Spectrum Symphony cluster using the provided scripts. Ensure the master node is publicly accessible or accessible from the attacker's network.
  - Step 1: Identify the public IP address or hostname of the deployed IBM Spectrum Symphony master node.
  - Step 2: Access the IBM Spectrum Symphony web interface (typically on port 8080 or configured port).
  - Step 3: Attempt to log in using the username "Admin" and the password "Admin".
  - Step 4: Verify successful login. If login is successful, the vulnerability is confirmed.
  - Step 5: (Optional) Use command-line tools like `soamview` or `egosh` from a machine with network access to the Symphony master node, attempting authentication with username "Admin" and password "Admin" to further validate command-line access.
  - Expected result: Attacker successfully logs in to the IBM Spectrum Symphony web interface and/or command-line tools with administrative privileges using the default credentials.