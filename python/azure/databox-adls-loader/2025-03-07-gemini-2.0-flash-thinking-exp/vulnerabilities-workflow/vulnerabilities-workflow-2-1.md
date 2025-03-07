- vulnerability name: Service Principal Credentials Exposure via Command-Line Arguments

- description:
    - The scripts `distcp-to-databox.sh`, `copy-to-adls.py`, and `copy-acls.py` take service principal client ID (`dest-spn-id`) and secret (`dest-spn-secret`), and storage account key (`source-key`, `dest_account_key`, `DEST_ACCOUNT_KEY`) as command-line arguments.
    - When these scripts are executed, the credentials become visible in the shell command history, process listings, and potentially in system logs.
    - An attacker with access to the system's command history, process listings, or logs can retrieve these credentials.
    - For example, after executing `copy-acls.py` with client ID and secret, an attacker can use the `history` command in the shell or inspect process details to view the command line and extract the credentials.

- impact:
    - High. If an attacker obtains the service principal credentials, they can impersonate the service principal and gain unauthorized access to the Azure Data Lake Storage Gen2 account.
    - This could allow the attacker to read, modify, or delete data in the ADLS Gen2 account, potentially leading to data breaches, data corruption, or denial of service.
    - In the context of data migration, this could compromise the migrated data in the cloud storage.

- vulnerability rank: High

- currently implemented mitigations:
    - None. The scripts directly accept and use credentials as command-line arguments without any implemented safeguards.

- missing mitigations:
    - **Secure credential storage**: Implement secure storage mechanisms for service principal credentials, such as:
        - Azure Key Vault: Store credentials in Azure Key Vault and retrieve them programmatically during script execution.
        - Environment variables: Read credentials from environment variables instead of command-line arguments. This is a slight improvement over command-line arguments, but environment variables can still be exposed.
        - Configuration files with restricted permissions: Store credentials in configuration files with restrictive file system permissions (e.g., readable only by the script's user).
    - **Input sanitization and validation**: While not directly mitigating credential exposure, input validation can help prevent injection attacks if credentials are processed further in the scripts (though not applicable in this specific case of command-line exposure).
    - **Auditing and logging**: Implement robust auditing and logging mechanisms to detect and monitor access to credentials and potential misuse. However, avoid logging the credentials themselves.

- preconditions:
    - An attacker needs to gain access to the system where the migration scripts are executed. This could be:
        - Local access to the on-premises Hadoop cluster's edge or head node.
        - Access to system logs, command history, or process listings on the Hadoop cluster's edge or head node through other vulnerabilities or misconfigurations.

- source code analysis:
    - **`distcp-to-databox.sh`**:
        ```bash
        DEST_ACCOUNT_KEY=$3
        ...
        hadoop distcp $HADOOP_OPTS -D fs.azure.account.key.$DEST_DNS_NAME=$DEST_ACCOUNT_KEY ...
        ```
        - The script takes `DEST_ACCOUNT_KEY` as the third command-line argument (`$3`) and directly uses it in the `hadoop distcp` command via `-D fs.azure.account.key.$DEST_DNS_NAME=$DEST_ACCOUNT_KEY`.
    - **`copy-to-adls.py`**:
        ```python
        parser = AdlsCopyUtils.createCommandArgsParser("Remaps identities on HDFS sourced data", add_dest_args=True)
        args = parser.parse_known_args()[0]
        ...
        token_handler = OAuthBearerToken(args.dest_spn_id, args.dest_spn_secret)
        ...
        sas_token = AdlsCopyUtils.getSasToken(args.source_account, args.source_key)
        ```
        - The script uses `AdlsCopyUtils.createCommandArgsParser` which sets up argument parsing for `--dest-spn-id`, `--dest-spn-secret`, `--source-account`, and `--source-key`.
        - `OAuthBearerToken` is initialized with `args.dest_spn_id` and `args.dest_spn_secret`.
        - `AdlsCopyUtils.getSasToken` is called with `args.source_account` and `args.source_key`.
    - **`adls_copy_utils.py`**:
        ```python
        class OAuthBearerToken:
            def __init__(self, client_id, client_secret):
                self.client_id = client_id
                self.client_secret = client_secret
                ...
        @staticmethod
        def getSasToken(account, key):
            ...
            sas_token_bytes = subprocess.check_output("az storage account generate-sas --account-name {0} --account-key {1} ...".format(
                    account,
                    key,
                    ...
        ```
        - `OAuthBearerToken` constructor takes `client_id` and `client_secret` as arguments.
        - `getSasToken` function takes `account` and `key` as arguments and uses them in a subprocess call to `az storage account generate-sas`.
    - **`identity-mapper.py`**:
        ```python
        parser = AdlsCopyUtils.createCommandArgsParser("Remaps identities on HDFS sourced data")
        parser.add_argument('-g', '--generate-identity-map', action='store_true', help="Specify this flag to generate a based identity mapping file using the unique identities in the source account. The identity map will be written to the file specified by the --identity-map argument.")
        args = parser.parse_known_args()[0]
        ...
        sas_token = AdlsCopyUtils.getSasToken(args.source_account, args.source_key)
        ```
        - Similar to `copy-to-adls.py`, it uses `AdlsCopyUtils.createCommandArgsParser` and `AdlsCopyUtils.getSasToken` which process `--source-account` and `--source-key` from command line.
    - **`copy-acls.py`**:
        ```python
        parser = AdlsCopyUtils.createCommandArgsParser("Apply ACLs to ADLS account", False, (True, False))
        ...
        args = parser.parse_known_args()[0]
        ...
        token_handler = OAuthBearerToken(args.dest_spn-id, args.dest_spn-secret)
        ```
        - Uses `AdlsCopyUtils.createCommandArgsParser` and initializes `OAuthBearerToken` with `args.dest_spn-id` and `args.dest_spn-secret` obtained from command line.

    - **Visualization**:
        ```
        Command-line arguments --> Script (e.g., copy-acls.py) --> Parses arguments (using argparse) -->
        Uses credentials directly (e.g., OAuthBearerToken(args.dest_spn_id, args.dest_spn_secret)) -->
        Credentials exposed in command history, process lists, logs.
        ```

- security test case:
    - Preconditions:
        - Access to a system where the migration scripts are installed and configured.
        - The scripts are executable.
        - You have the necessary permissions to view command history or process listings (depending on the system and user privileges).
    - Steps:
        1. Execute one of the scripts that takes credentials as command-line arguments, for example `copy-acls.py`. Replace placeholders with actual values for your environment, including a valid service principal client ID and secret.
           ```bash
           ./copy-acls.py -A <adls_gen2_account_name> -C <adls_gen2_container_name> --dest-spn-id <service_principal_client_id> --dest-spn-secret <service_principal_client_secret> -s ./filelist.json -i ./id_map.json
           ```
        2. After the script execution, check the shell command history. For bash, use the `history` command.
           ```bash
           history
           ```
        3. Observe the command you executed in the history. You should see the service principal client ID and secret in plain text as part of the command-line arguments.
        4. Alternatively, while the script is running (or immediately after), use process listing tools like `ps` or `top` to view the running processes and their command-line arguments.
           ```bash
           ps aux | grep copy-acls.py
           ```
        5. Examine the output. You should see the command line for the `copy-acls.py` process, including the service principal client ID and secret in plain text.
        6. If system logging is enabled, check system logs (e.g., `/var/log/auth.log`, `/var/log/audit/audit.log` depending on the system configuration) for entries related to command execution. The command with credentials might be logged there as well.
    - Expected result:
        - The service principal client ID and secret are visible in plain text in the shell command history and process listings, and potentially in system logs. This confirms the vulnerability of credential exposure via command-line arguments.