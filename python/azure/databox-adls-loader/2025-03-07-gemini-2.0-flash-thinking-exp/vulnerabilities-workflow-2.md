## Combined Vulnerability List

### Vulnerability: Credential Exposure via Command-Line Arguments

- **Description:**
    - The scripts `distcp-to-databox.sh`, `copy-to-adls.py`, and `copy-acls.py` are designed to migrate data from on-premises HDFS to Azure.
    - These scripts take sensitive credentials, specifically Azure Storage Account Keys and Service Principal ID/Secrets, as command-line arguments.
    - When these scripts are executed, the credentials passed via command-line arguments can be easily exposed in several ways:
        - **Shell History:** Command-line arguments are typically logged in shell history files (e.g., `.bash_history`), which can be accessed by an attacker who compromises the user account or the system.
        - **Process Listings:** Tools like `ps` can display the command-line arguments of running processes, making the credentials visible to anyone with sufficient privileges to view process information.
        - **Monitoring and Logging Systems:** System monitoring or logging tools might capture process execution details, including command-line arguments, potentially storing credentials in logs.
    - An attacker who gains unauthorized access to the on-premises Hadoop cluster and can access shell history, process listings, or system logs can retrieve these exposed credentials.

- **Impact:**
    - High. If an attacker successfully retrieves the exposed Azure Storage Account Keys or Service Principal credentials, they can gain unauthorized access to the Azure Storage accounts.
    - With these credentials, the attacker can perform various malicious actions:
        - **Data Breach:** Access and download sensitive data stored in the Azure Storage accounts, leading to confidentiality breaches.
        - **Data Manipulation:** Modify or delete data in the Azure Storage accounts, causing data integrity issues or data loss.
        - **Resource Abuse:** Utilize the compromised credentials to perform other operations within the Azure environment, potentially leading to financial or operational damage.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - None. The provided scripts and documentation do not implement any mitigations to protect credentials passed as command-line arguments. The README mentions creating a service principal but does not address secure credential handling within the scripts themselves.

- **Missing Mitigations:**
    - **Secure Credential Storage:** Implement secure storage mechanisms for sensitive credentials instead of passing them directly as command-line arguments. Options include:
        - **Azure Key Vault:** Store credentials in Azure Key Vault and retrieve them programmatically within the scripts using managed identities or other secure authentication methods.
        - **Hadoop Credential Provider:** Utilize Hadoop's built-in Credential Provider framework to securely store and access credentials within the Hadoop environment.
        - **Environment Variables:** Pass credentials as environment variables instead of command-line arguments. While environment variables can still be exposed in process listings, they are less likely to be logged in shell history compared to command-line arguments.
        - **Input Prompt:** Prompt the user to enter sensitive credentials interactively at runtime instead of storing them in scripts or passing them as arguments. This approach reduces the risk of persistent credential exposure.
    - **Principle of Least Privilege:** Ensure that the Service Principal and Storage Account Keys are granted only the minimum necessary permissions required for the data migration process. This limits the potential impact if the credentials are compromised.

- **Preconditions:**
    - An attacker must gain unauthorized access to the on-premises Hadoop cluster where the migration scripts are executed. This could be achieved through various means, such as exploiting vulnerabilities in the Hadoop cluster itself, compromising user accounts, or gaining physical access to the systems.
    - The scripts must be executed with sensitive credentials provided as command-line arguments.

- **Source Code Analysis:**
    - **`distcp-to-databox.sh`**:
        ```bash
        DEST_ACCOUNT_KEY=$3
        ...
        hadoop distcp $HADOOP_OPTS -D fs.azure.account.key.$DEST_DNS_NAME=$DEST_ACCOUNT_KEY ...
        ```
        - The script takes `DEST_ACCOUNT_KEY` as the third command-line argument (`$3`).
        - This argument is directly used to set the Hadoop configuration property `fs.azure.account.key.$DEST_DNS_NAME` within the `hadoop distcp` command.
        - This directly exposes the storage account key in the command execution.
    - **`copy-to-adls.py`**:
        ```python
        parser = AdlsCopyUtils.createCommandArgsParser("Remaps identities on HDFS sourced data", add_dest_args=True)
        args = parser.parse_known_args()[0]
        ...
        token_handler = OAuthBearerToken(args.dest_spn_id, args.dest_spn_secret)
        ...
        sas_token = AdlsCopyUtils.getSasToken(args.source_account, args.source_key)
        ```
        - The script uses `argparse` to define `--dest-spn-id` and `--dest-spn-secret` as command-line arguments.
        - These arguments are directly passed to the `OAuthBearerToken` class constructor, making them visible in the command execution.
    - **`copy-acls.py`**:
        ```python
        parser = AdlsCopyUtils.createCommandArgsParser("Apply ACLs to ADLS account", False, (True, False))
        ...
        args = parser.parse_known_args()[0]
        ...
        token_handler = OAuthBearerToken(args.dest_spn-id, args.dest_spn-secret)
        ```
        - Similar to `copy-to-adls.py`, this script also uses command-line arguments `--dest-spn-id` and `--dest-spn-secret` for service principal credentials, exposing them in command execution.
    - **`adls_copy_utils.py`**:
        ```python
        class OAuthBearerToken:
            def __init__(self, client_id, client_secret):
                self.client_secret = client_secret # secret is stored here
                # ... potentially used in requests that could be logged by requests lib or custom logging if debug is enabled
        @staticmethod
        def getSasToken(account, key):
            ...
            sas_token_bytes = subprocess.check_output("az storage account generate-sas --account-name {0} --account-key {1} ...".format(account, key, ...), shell=True)
        ```
        - This utility function, used by other scripts, takes `account` and `key` as arguments, which are intended to be storage account name and key. If these are passed from insecure sources (like command-line), they become vulnerable.

    - **Visualization**:
        ```
        Command-line arguments --> Script (e.g., copy-acls.py) --> Parses arguments (using argparse) -->
        Uses credentials directly (e.g., OAuthBearerToken(args.dest_spn_id, args.dest_spn_secret)) -->
        Credentials exposed in command history, process lists, logs.
        ```

- **Security Test Case:**
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


### Vulnerability: Command Injection in `copy-acls.sh` via Malicious Filenames in HDFS

- **Description:**
    1. The `copy-acls.sh` script is designed to extract ACLs from HDFS and format them into a JSON file (`filelist.json`).
    2. The script uses `hadoop fs -getfacl -R $source_path` to retrieve ACL information recursively from the specified `source_path` in HDFS.
    3. The output of this `hadoop fs` command, which includes filenames, is then processed line by line within a `while read file` loop in the `process_acl_entries` function.
    4. Inside the loop, the script constructs a string using `echo "'$file'" "'$owner'" "'$group'" "${aclspec[@]}"` where `$file` is directly taken from the output of the `hadoop fs -getfacl -R` command.
    5. If an attacker can create a file in HDFS with a malicious filename that includes backticks or command substitution syntax (e.g., `test`\`touch /tmp/pwned_acl_sh.txt\``), the backticks will be interpreted by the shell during the `echo` command execution within the `copy-acls.sh` script.
    6. This allows the attacker to inject and execute arbitrary shell commands on the system where `copy-acls.sh` is run, effectively achieving command injection.

- **Impact:**
    - Critical. Successful exploitation allows an attacker to execute arbitrary commands with the privileges of the user running the `copy-acls.sh` script, which is typically the `hdfs` user. This can lead to:
        - Full control over the Hadoop cluster's head/edge node.
        - Data exfiltration from the Hadoop cluster.
        - Modification or deletion of data in HDFS.
        - Denial of service by disrupting Hadoop services.
        - Lateral movement to other systems accessible from the compromised node.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - None. The script directly processes the output of `hadoop fs -getfacl -R` without any sanitization or validation of filenames obtained from HDFS.

- **Missing Mitigations:**
    - **Input Sanitization:** The script should sanitize or validate filenames retrieved from `hadoop fs -getfacl -R` output before using them in shell commands. Specifically, it should remove or escape any characters that could be interpreted for command substitution or injection, such as backticks, `$()`, etc.
    - **Secure Coding Practices:** Avoid constructing shell commands by directly embedding user-controlled input. If shell commands are necessary, use parameterized commands or safer alternatives to `echo` for outputting data, especially when dealing with potentially untrusted input.

- **Preconditions:**
    1. Attacker must have the ability to create files with arbitrary names in the HDFS file system of the on-premises Hadoop cluster. This is often possible if the attacker has compromised an account with write permissions to HDFS or if HDFS permissions are misconfigured.
    2. The `copy-acls.sh` script must be executed by an administrator (or user with sufficient privileges like `hdfs` user) on the Hadoop cluster, targeting a directory path that includes the attacker-created malicious file.

- **Source Code Analysis:**
    ```bash
    process_acl_entries() {
        source_path=$1
        is_relative_path=$(if [[ ${source_path:0:1} == "/" ]] ; then echo 1; else echo 0; fi)

        while read file; do  # Vulnerable code starts here: Reading filename from hadoop fs output
            if (( $is_relative_path )); then
                file=$(echo $file | cut -d / -f 2-)
            else
                file=$(echo $file | cut -d / -f 4-)
            fi
            aclspec=()
            owner=""
            group=""
            while true
            do
                read identity
                if [[ ${identity:0:1} != '#' ]]
                then
                    aclentry=$identity
                    break
                fi
                ownertype=$(echo $identity | cut -d ':' -f 1 | cut -c 3-)
                identity=$(echo $identity | cut -d ':' -f 2 | sed -e 's/^[ \t]*//')
                if [[ $ownertype == "owner" ]]
                then
                    owner=$identity
                elif [[ $ownertype == "group" ]]
                then
                    group=$identity
                fi
            done
            while [[ $aclentry ]]
            do
                aclspec+=($(echo $aclentry | cut -d "#" -f 1))
                read aclentry
            done
            echo "'$file'" "'$owner'" "'$group'" "${aclspec[@]}" # Vulnerable code: Using unsanitized filename in echo
        done < <(hadoop fs -Dfs.azure.localuserasfileowner.replace.principals= -getfacl -R $source_path) # Input from hadoop fs -getfacl is not sanitized
    }
    ```
    - The vulnerability lies in the `process_acl_entries` function, specifically in the line `echo "'$file'" "'$owner'" "'$group'" "${aclspec[@]}".
    - The `$file` variable, which is derived directly from the output of `hadoop fs -getfacl -R`, is used within the `echo` command without proper sanitization.
    - If a filename from HDFS contains backticks or other command injection sequences, these will be executed when the `echo` command is processed by the shell during script execution.
    - The output of this `echo` command is then piped to `jq`, but the command injection happens before `jq` processing, during the `echo` execution itself.

- **Security Test Case:**
    1. **Precondition:** Access to an on-premises Hadoop cluster where you can create files in HDFS and execute `copy-acls.sh`. Assume you have SSH access to the head/edge node of the Hadoop cluster.
    2. **Steps:**
        a. SSH into the head/edge node of the Hadoop cluster.
        b. Become the `hdfs` user (or a user with write permissions to HDFS): `sudo su hdfs`
        c. Create a directory in HDFS for testing: `hadoop fs -mkdir /tmp/vulntest`
        d. Create a file in HDFS with a malicious filename. This filename will contain a command injection payload.
           ```bash
           malicious_filename="test`touch /tmp/pwned_acl_sh.txt`"
           hadoop fs -touchz "/tmp/vulntest/${malicious_filename}"
           ```
        e. Exit from `hdfs` user if needed, and as a user who can execute scripts (e.g., your regular user account), navigate to the directory where `copy-acls.sh` is located.
        f. Execute the `copy-acls.sh` script, targeting the directory containing the malicious file:
           ```bash
           ./copy-acls.sh -s /tmp/vulntest > output.json
           ```
        g. Check if the file `/tmp/pwned_acl_sh.txt` has been created in the `/tmp` directory on the local filesystem of the head/edge node where you executed `copy-acls.sh`.
           ```bash
           ls -l /tmp/pwned_acl_sh.txt
           ```
    3. **Expected Result:** If the file `/tmp/pwned_acl_sh.txt` exists after running the test, it confirms that the command injection vulnerability is present in `copy-acls.sh`. The `touch /tmp/pwned_acl_sh.txt` command embedded in the filename was successfully executed when `copy-acls.sh` processed the malicious filename.