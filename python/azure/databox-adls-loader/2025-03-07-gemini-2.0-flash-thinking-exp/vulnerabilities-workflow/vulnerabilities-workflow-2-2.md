### Vulnerability List

- Vulnerability Name: Credential Exposure via Command-Line Arguments
- Description:
  - The scripts `distcp-to-databox.sh`, `copy-to-adls.py`, and `copy-acls.py` are designed to migrate data from on-premises HDFS to Azure.
  - These scripts take sensitive credentials, specifically Azure Storage Account Keys and Service Principal ID/Secrets, as command-line arguments.
  - When these scripts are executed, the credentials passed via command-line arguments can be easily exposed in several ways:
    - **Shell History:** Command-line arguments are typically logged in shell history files (e.g., `.bash_history`), which can be accessed by an attacker who compromises the user account or the system.
    - **Process Listings:** Tools like `ps` can display the command-line arguments of running processes, making the credentials visible to anyone with sufficient privileges to view process information.
    - **Monitoring and Logging Systems:** System monitoring or logging tools might capture process execution details, including command-line arguments, potentially storing credentials in logs.
  - An attacker who gains unauthorized access to the on-premises Hadoop cluster and can access shell history, process listings, or system logs can retrieve these exposed credentials.
- Impact:
  - If an attacker successfully retrieves the exposed Azure Storage Account Keys or Service Principal credentials, they can gain unauthorized access to the Azure Storage accounts.
  - With these credentials, the attacker can perform various malicious actions:
    - **Data Breach:** Access and download sensitive data stored in the Azure Storage accounts, leading to confidentiality breaches.
    - **Data Manipulation:** Modify or delete data in the Azure Storage accounts, causing data integrity issues or data loss.
    - **Resource Abuse:** Utilize the compromised credentials to perform other operations within the Azure environment, potentially leading to financial or operational damage.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
  - None. The provided scripts and documentation do not implement any mitigations to protect credentials passed as command-line arguments. The README mentions creating a service principal but does not address secure credential handling within the scripts themselves.
- Missing Mitigations:
  - **Secure Credential Storage:** Implement secure storage mechanisms for sensitive credentials instead of passing them directly as command-line arguments. Options include:
    - **Azure Key Vault:** Store credentials in Azure Key Vault and retrieve them programmatically within the scripts using managed identities or other secure authentication methods.
    - **Hadoop Credential Provider:** Utilize Hadoop's built-in Credential Provider framework to securely store and access credentials within the Hadoop environment.
  - **Environment Variables:** Pass credentials as environment variables instead of command-line arguments. While environment variables can still be exposed in process listings, they are less likely to be logged in shell history compared to command-line arguments.
  - **Input Prompt:** Prompt the user to enter sensitive credentials interactively at runtime instead of storing them in scripts or passing them as arguments. This approach reduces the risk of persistent credential exposure.
  - **Principle of Least Privilege:** Ensure that the Service Principal and Storage Account Keys are granted only the minimum necessary permissions required for the data migration process. This limits the potential impact if the credentials are compromised.
- Preconditions:
  - An attacker must gain unauthorized access to the on-premises Hadoop cluster where the migration scripts are executed. This could be achieved through various means, such as exploiting vulnerabilities in the Hadoop cluster itself, compromising user accounts, or gaining physical access to the systems.
  - The scripts must be executed with sensitive credentials provided as command-line arguments.
- Source Code Analysis:
  - **distcp-to-databox.sh:**
    - Line referencing account key: `hadoop distcp $HADOOP_OPTS -D fs.azure.account.key.$DEST_DNS_NAME=$DEST_ACCOUNT_KEY ...`
    - The script takes `$DEST_ACCOUNT_KEY` as the third command-line argument (`$3`).
    - This argument is directly used to set the Hadoop configuration property `fs.azure.account.key.$DEST_DNS_NAME` within the `hadoop distcp` command.
    - This directly exposes the storage account key in the command execution.
  - **copy-to-adls.py:**
    - Argument parsing: `parser.add_argument('-I', '--dest-spn-id', required=dest_required_flag, help="The client id for the service principal ...")`, `parser.add_argument('-S', '--dest-spn-secret', required=dest_required_flag, help="The client secret for the service principal ...")`
    - OAuth token handler initialization: `token_handler = OAuthBearerToken(args.dest_spn_id, args.dest_spn_secret)`
    - The script uses `argparse` to define `--dest-spn-id` and `--dest-spn-secret` as command-line arguments.
    - These arguments are directly passed to the `OAuthBearerToken` class constructor, making them visible in the command execution.
  - **copy-acls.py:**
    - Argument parsing: `parser = AdlsCopyUtils.createCommandArgsParser("Apply ACLs to ADLS account", False, (True, False))`, `parser.add_argument('-I', '--dest-spn-id', required=dest_required_flag, help="The client id for the service principal ...")`, `parser.add_argument('-S', '--dest-spn-secret', required=dest_required_flag, help="The client secret for the service principal ...")`
    - OAuth token handler initialization: `token_handler = OAuthBearerToken(args.dest_spn_id, args.dest_spn_secret)`
    - Similar to `copy-to-adls.py`, this script also uses command-line arguments `--dest-spn-id` and `--dest-spn-secret` for service principal credentials, exposing them in command execution.
  - **adls_copy_utils.py:**
    - `getSasToken` function: `sas_token_bytes = subprocess.check_output("az storage account generate-sas --account-name {0} --account-key {1} ...".format(account, key, ...), shell=True)`
    - This utility function, used by other scripts, takes `account` and `key` as arguments, which are intended to be storage account name and key. If these are passed from insecure sources (like command-line), they become vulnerable.

- Security Test Case:
  1. **Environment Setup:** Set up a minimal on-premises Hadoop environment where you can execute the provided scripts. Cloning the GitHub repository onto the edge node of this Hadoop cluster is sufficient. You do not need a fully functional Data Box or Azure setup for this test, as we are focusing on local credential exposure.
  2. **Script Preparation:**
     - Choose the `distcp-to-databox.sh` script for this test case as it directly uses the storage account key.
     - Create a dummy file `filelist.txt` (it can be empty for this test).
     - Identify a placeholder for the Data Box DNS name and container name (e.g., `databox.example.com`, `container_name`).
     - Obtain a **dummy** Azure Storage Account Key. **Do not use a real, sensitive key for testing credential exposure.** You can use a randomly generated string or a clearly marked placeholder like `dummy_account_key_for_testing`.
  3. **Script Execution (Vulnerable Command):**
     - Execute the `distcp-to-databox.sh` script from the Hadoop edge node, providing the dummy account key as a command-line argument:
       ```bash
       bash distcp-to-databox.sh filelist.txt databox.example.com dummy_account_key_for_testing container_name
       ```
  4. **Attacker Actions (Simulated):**
     - **Access Shell History:** As an attacker who has gained access to the user's account on the Hadoop edge node (e.g., via SSH), examine the shell history file (typically `.bash_history` in the user's home directory):
       ```bash
       cat ~/.bash_history | grep distcp-to-databox.sh
       ```
     - **Inspect Process Listing:** Alternatively, or if shell history is not available, inspect the running processes to find the executed `distcp-to-databox.sh` command and its arguments:
       ```bash
       ps aux | grep distcp-to-databox.sh
       ```
  5. **Verification:**
     - **Observe Exposed Credential:** In both the shell history and the process listing output, you will clearly see the command line used to execute `distcp-to-databox.sh`. This command line will include the dummy account key (`dummy_account_key_for_testing`) as a plain text argument.
     - **Demonstrate Exposure:** This observation confirms that the Azure Storage Account Key, passed as a command-line argument, is readily exposed and retrievable by an attacker with access to the system's shell history or process information. This demonstrates the vulnerability of credential exposure via command-line arguments.
  6. **Cleanup:** Ensure you remove any test files or configurations created during this test and, most importantly, remember that you used a dummy key and **did not expose any real credentials.**