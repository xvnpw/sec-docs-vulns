### Vulnerability List

#### 1. Sensitive Information Exposure through Command-Line Arguments

- **Description:**
    - The `cosmos_tls_scanner.py` script is designed to accept the Azure Cosmos DB authorization key as a command-line argument via the `--authorization-key` parameter.
    - When a user executes the script with the authorization key provided directly in the command line, this command, including the sensitive key, is often logged in command history files (like `.bash_history`, `.zsh_history` on Linux/macOS or command history on Windows) and potentially in system logs.
    - An attacker who gains unauthorized access to these command history files or system logs can retrieve the plaintext authorization key. This access could be achieved through various means, such as local system access, compromised user accounts, or access to centralized logging systems.
    - Once the attacker obtains the authorization key, they can use it to authenticate against the Azure Cosmos DB account.

- **Impact:**
    - **High**. If an attacker successfully retrieves the Azure Cosmos DB authorization key, they can gain unauthorized access to the Cosmos DB account.
    - The level of access depends on the type of key exposed:
        - **Master Key:** Full read and write access to all data within the Cosmos DB account. Attackers can read, modify, delete data, and alter account configurations, leading to significant data breaches, data manipulation, and potential service disruption.
        - **Read-only Key:** Read-only access to all data within the Cosmos DB account. Attackers can exfiltrate sensitive data, potentially leading to confidentiality breaches and compliance violations.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - None. The current design of the script and the instructions in the `README.md` encourage users to pass the authorization key via command-line arguments. There are no warnings or alternative secure methods suggested within the project.

- **Missing Mitigations:**
    - **Secure Input Method:** The script should be modified to accept the authorization key through more secure methods than command-line arguments. Recommended alternatives include:
        - **Environment Variables:**  Reading the authorization key from an environment variable. This prevents the key from being directly visible in command history.
        - **Configuration File:** Loading the authorization key from a configuration file with restricted file system permissions (e.g., readable only by the user running the script).
    - **Documentation Warning:** The `README.md` file should be updated to include a prominent security warning against providing the authorization key directly in the command line. It should strongly recommend using environment variables or configuration files as secure alternatives.

- **Preconditions:**
    - The user must execute the `cosmos_tls_scanner.py` script and provide the Azure Cosmos DB authorization key using the `--authorization-key` command-line argument.
    - An attacker must gain access to the command history files or system logs where the command execution, including the key, is recorded. This could be through local access to the user's machine or remote access to systems where logs are aggregated.

- **Source Code Analysis:**
    - **File: `/code/cosmos_tls_scanner.py`**
    ```python
    def _get_parser():
        """
        Gets argparse parser object
        Args:
          --endpoint: Database account endpoint. Example https://myaccount.documents.azure.com:443/
          --authorization-key: Master or Read-only key for account of the form khYANAIiAl12n...==
          --database-name: Name of the Azure Cosmos DB database in the account.
          --collection-name: Name of the collection in the database.
        """
        parser = argparse.ArgumentParser(description="Azure Cosmos DB TLS Scanner")
        parser.add_argument(
            "--endpoint",
            "-e",
            required=True,
            help="Azure Cosmos DB database account endpoint. Example https://myaccount.documents.azure.com:443/",
        )
        parser.add_argument(
            "--authorization-key",
            "-k",
            required=True,
            help="Master or Read-only key for account of the form khYANAIiAl12n...==",
        )
        # ... other arguments
        return parser

    def main(args):
        args.endpoint = args.endpoint.strip()
        args.authorization_key = args.authorization_key.strip() # Authorization key is directly taken from command-line argument 'args'
        # ... rest of the main function where args.authorization_key is used to make requests to Cosmos DB
    ```
    - The `_get_parser` function defines the `--authorization-key` argument using `argparse`, making it a required command-line parameter.
    - In the `main` function, the authorization key is directly retrieved from the parsed arguments (`args.authorization_key`) without any security considerations.
    - This key is then passed to functions like `list_databases` and `basic_query` and used in `_get_auth_header` to generate authentication headers for requests to Azure Cosmos DB.
    - **Visualization:**
    ```
    User Command Line --> argparse.ArgumentParser --> args.authorization_key --> _get_auth_header --> HTTP Headers --> Cosmos DB
    ^
    |
    Command History/Logs
    ```
    - The diagram illustrates how the authorization key, entered in the command line, flows directly into the script's logic and potentially gets logged in command history.

- **Security Test Case:**
    1. **Prerequisites:**
        - Ensure Python 3.5+ and `requests`, `urllib3` are installed (`pip install -r requirements.txt`).
        - Obtain a valid Azure Cosmos DB endpoint and authorization key (master or read-only) for testing purposes.
    2. **Execution:**
        - Open a terminal or command prompt.
        - Execute the `cosmos_tls_scanner.py` script with the `--endpoint` and `--authorization-key` parameters, replacing `<your_cosmos_db_endpoint>` and `<your_cosmos_db_key>` with your test credentials:
          ```bash
          python3 cosmos_tls_scanner.py --endpoint <your_cosmos_db_endpoint> --authorization-key <your_cosmos_db_key>
          ```
        - The script should run and output the TLS version support information.
    3. **Verification:**
        - **Linux/macOS:** Open a new terminal and examine the command history file (usually `~/.bash_history` or `~/.zsh_history` depending on your shell). Use a command like `cat ~/.bash_history | grep "cosmos_tls_scanner.py"` or `cat ~/.zsh_history | grep "cosmos_tls_scanner.py"`.
        - **Windows:** Check the command history using the `doskey /history` command in the same command prompt or PowerShell session, or examine shell history logs if configured.
        - **Alternatively:** Check system logs if command execution logging is enabled on the system.
    4. **Expected Result:**
        - The command history file (or system logs) should contain the full command line used to execute the script, including the `--authorization-key` parameter and the plaintext Cosmos DB authorization key value.
        - This confirms that the authorization key is exposed in command history, validating the vulnerability.