* Vulnerability Name: Command Injection in `copy-acls.sh` via Malicious Filenames in HDFS

* Description:
    1. The `copy-acls.sh` script is designed to extract ACLs from HDFS and format them into a JSON file (`filelist.json`).
    2. The script uses `hadoop fs -getfacl -R $source_path` to retrieve ACL information recursively from the specified `source_path` in HDFS.
    3. The output of this `hadoop fs` command, which includes filenames, is then processed line by line within a `while read file` loop in the `process_acl_entries` function.
    4. Inside the loop, the script constructs a string using `echo "'$file'" "'$owner'" "'$group'" "${aclspec[@]}"` where `$file` is directly taken from the output of the `hadoop fs -getfacl -R` command.
    5. If an attacker can create a file in HDFS with a malicious filename that includes backticks or command substitution syntax (e.g., `test`\`touch /tmp/pwned_acl_sh.txt\``), the backticks will be interpreted by the shell during the `echo` command execution within the `copy-acls.sh` script.
    6. This allows the attacker to inject and execute arbitrary shell commands on the system where `copy-acls.sh` is run, effectively achieving command injection.

* Impact:
    - **High**. Successful exploitation allows an attacker to execute arbitrary commands with the privileges of the user running the `copy-acls.sh` script, which is typically the `hdfs` user. This can lead to:
        - Full control over the Hadoop cluster's head/edge node.
        - Data exfiltration from the Hadoop cluster.
        - Modification or deletion of data in HDFS.
        - Denial of service by disrupting Hadoop services.
        - Lateral movement to other systems accessible from the compromised node.

* Vulnerability Rank: Critical

* Currently Implemented Mitigations:
    - None. The script directly processes the output of `hadoop fs -getfacl -R` without any sanitization or validation of filenames obtained from HDFS.

* Missing Mitigations:
    - **Input Sanitization:** The script should sanitize or validate filenames retrieved from `hadoop fs -getfacl -R` output before using them in shell commands. Specifically, it should remove or escape any characters that could be interpreted for command substitution or injection, such as backticks, `$()`, etc.
    - **Secure Coding Practices:** Avoid constructing shell commands by directly embedding user-controlled input. If shell commands are necessary, use parameterized commands or safer alternatives to `echo` for outputting data, especially when dealing with potentially untrusted input.

* Preconditions:
    1. Attacker must have the ability to create files with arbitrary names in the HDFS file system of the on-premises Hadoop cluster. This is often possible if the attacker has compromised an account with write permissions to HDFS or if HDFS permissions are misconfigured.
    2. The `copy-acls.sh` script must be executed by an administrator (or user with sufficient privileges like `hdfs` user) on the Hadoop cluster, targeting a directory path that includes the attacker-created malicious file.

* Source Code Analysis:
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

* Security Test Case:
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