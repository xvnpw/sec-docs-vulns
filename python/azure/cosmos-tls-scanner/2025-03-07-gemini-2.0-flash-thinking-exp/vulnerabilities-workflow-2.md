### Combined Vulnerability List

#### 1. Authorization Key Exposure via Command Line Argument (Modified Script)

- **Description:**
    The Cosmos TLS Scanner utility is vulnerable to authorization key exposure when a user is socially engineered into running a modified version of the `cosmos_tls_scanner.py` script.  An attacker can create a malicious script that captures the authorization key provided as a command-line argument.

    Steps to trigger the vulnerability through a modified script:
    1. An attacker creates a modified version of `cosmos_tls_scanner.py`.
    2. In the modified script, the attacker adds code to capture the value of the `--authorization-key` argument, for example by logging it to a file or sending it to a remote server.
    3. The attacker uses social engineering to trick a user into downloading and running this modified script.
    4. The user executes the modified script and provides their Azure Cosmos DB endpoint and authorization key as command-line arguments.
    5. The modified script captures the authorization key and performs a malicious action.
    6. The attacker obtains the user's Azure Cosmos DB authorization key.

- **Impact:**
    Successful exploitation leads to the complete compromise of the targeted Azure Cosmos DB account. An authorization key grants administrative privileges, allowing the attacker to:
    - Access all data within the Cosmos DB account.
    - Modify or delete data, including databases and collections.
    - Change account configurations.
    - Potentially use the compromised account to further attack other systems or data.

- **Vulnerability Rank:**
    Critical

- **Currently Implemented Mitigations:**
    There are no mitigations implemented within the code to prevent key exposure via modified scripts.

- **Missing Mitigations:**
    - **Strong Warning in Documentation:**  Include a prominent security warning in the README.md against providing the authorization key as a command-line argument and stress verifying script integrity.
    - **Alternative Input Methods (Consideration for Future Versions):** Explore alternative input methods for the authorization key less prone to direct exposure, such as environment variables or secure configuration files.

- **Preconditions:**
    1. An attacker creates a modified version of the `cosmos_tls_scanner.py` script to exfiltrate the authorization key.
    2. Social engineering is successful in tricking a user into executing the modified script.
    3. The user provides their valid Azure Cosmos DB endpoint and authorization key as command-line arguments to the modified script.

- **Source Code Analysis:**
    1. **`_get_parser()` function:** Defines `--authorization-key` as a command-line argument.
        ```python
        def _get_parser():
            parser = argparse.ArgumentParser()
            parser.add_argument(
                "--authorization-key",
                "-k",
                required=True,
                help="Master or Read-only key",
            )
            return parser
        ```
    2. **`main()` function:** Retrieves the authorization key from command-line arguments.
        ```python
        def main(args):
            args.authorization_key = args.authorization_key.strip()
            # ... rest of main function using args.authorization_key
        ```
    3. **Authentication Functions:** `args.authorization_key` is used directly in authentication functions like `_get_auth_header`.

    **Visualization:**

    ```
    User Command Line Input --> argparse (_get_parser) --> args.authorization_key (in main) --> _get_auth_header --> API Request
    ```
    A malicious script can intercept `args.authorization_key` before it is used for authentication.

- **Security Test Case:**
    1. **Prepare Malicious Script:** Modify `cosmos_tls_scanner.py` to log `args.authorization_key` to a file.
    2. **Social Engineering (Simulated):** Trick a test user into using the modified script.
    3. **Execute Malicious Script:** User runs the modified script with their Cosmos DB credentials.
    4. **Verify Key Exfiltration:** Check for the log file containing the authorization key.

#### 2. Credential Exposure to Malicious Endpoint

- **Description:**
    This vulnerability arises when a user is tricked into running the `cosmos_tls_scanner.py` script against a malicious endpoint controlled by an attacker. The script, as designed, sends HTTP requests to the specified endpoint, including the Azure Cosmos DB authorization key in the `authorization` header for authentication.

    1. An attacker sets up a malicious server mimicking an Azure Cosmos DB endpoint.
    2. The attacker uses social engineering to convince a user to use this malicious endpoint with the `cosmos_tls_scanner.py`.
    3. The user, intending to test their Cosmos DB, provides their Cosmos DB authorization key to the script.
    4. The script sends requests to the malicious endpoint, including the authorization key in headers.
    5. The attacker's server captures the requests and extracts the authorization key.
    6. The attacker can then use this key to access the user's legitimate Cosmos DB account.

- **Impact:**
    - Full compromise of the Azure Cosmos DB account.
    - Unauthorized access to all data.
    - Potential data exfiltration, modification, or deletion.
    - Loss of confidentiality, integrity, and availability.

- **Vulnerability Rank:**
    Critical

- **Currently Implemented Mitigations:**
    None. The tool lacks any mitigations against this vulnerability.

- **Missing Mitigations:**
    - **Warning Message:** Display a prominent warning about using trusted endpoints.
    - **Endpoint Validation (Limited):** Implement basic endpoint format validation, but this is not a strong security measure.

- **Preconditions:**
    - User is tricked into running the script.
    - User is socially engineered to target a malicious endpoint.
    - Attacker controls the malicious endpoint and can capture HTTP requests.

- **Source Code Analysis:**
    1. **Argument Parsing (`_get_parser()`):** Script accepts `--endpoint` and `--authorization-key` as arguments.
        ```python
        def _get_parser():
            parser = argparse.ArgumentParser()
            parser.add_argument("--endpoint", "-e", required=True, help="Endpoint")
            parser.add_argument("--authorization-key", "-k", required=True, help="Key")
            return parser
        ```
    2. **Request Construction and Authorization (`_send_request`, `_get_auth_header`):** Authorization key is used to generate headers for requests to the provided endpoint.
        ```python
        def _get_auth_header(key, ...): # Key is authorization key
            # ... creates authorization header using key ...
            return urllib.parse.quote("type=master&ver=1.0&sig={}".format(signature[:-1]))

        def _send_request(uri, ..., headers=None, ...): # uri is endpoint
            full_url = urllib.parse.urljoin(uri, ...)
            response = session.request(..., full_url, headers=headers, ...) # Headers include auth key
            return response
        ```
    3. **Execution Flow (`main()`):** `main()` uses user-provided endpoint and key to make requests.

- **Security Test Case:**
    1. **Set up a malicious endpoint:** Create a simple HTTP server that logs incoming requests.
    2. **Prepare to run scanner:** Install requirements and obtain a Cosmos DB key.
    3. **Execute against malicious endpoint:** Run `cosmos_tls_scanner.py` with the malicious endpoint and a Cosmos DB key.
        ```bash
        python3 cosmos_tls_scanner.py --endpoint http://<malicious-endpoint-ip>:8080/ --authorization-key <your_cosmos_db_key>
        ```
    4. **Verify credential capture:** Check the malicious server logs for the `authorization` header containing the Cosmos DB key.

#### 3. Credential Exposure via Command-Line Arguments (Command History)

- **Description:**
    The Cosmos TLS Scanner script requires users to provide the Azure Cosmos DB authorization key as a command-line argument. This practice leads to the exposure of sensitive credentials through command history and system logs.

    1. The user executes `cosmos_tls_scanner.py` and provides the authorization key using the `--authorization-key` parameter in the command line.
    2. The command, including the authorization key in plain text, is recorded in the command history of the user's shell (e.g., `.bash_history`, `.zsh_history`, PowerShell history).
    3. System logs may also record command executions, potentially including the authorization key.
    4. If an attacker gains unauthorized access to the user's command history files or system logs, they can retrieve the plaintext authorization key.
    5. The attacker can then use this exposed key to gain unauthorized access to the targeted Azure Cosmos DB account.

- **Impact:**
    - **High**. Exposure of the Cosmos DB authorization key can lead to unauthorized access to the Cosmos DB account.
        - **Master Key Exposure:** Full read and write access, leading to data breaches, manipulation, and service disruption.
        - **Read-only Key Exposure:** Read-only access, leading to data exfiltration and confidentiality breaches.

- **Vulnerability Rank:**
    High

- **Currently Implemented Mitigations:**
    None. The script requires the authorization key as a command-line argument, with no warnings or secure alternatives provided.

- **Missing Mitigations:**
    - **Secure Input Method:** Avoid command-line arguments for credentials. Implement secure alternatives:
        - **Environment Variables:** Read the key from environment variables.
        - **Configuration File:** Load the key from a secure configuration file.
    - **Documentation Warning:** Update documentation (README.md) to warn against command-line credentials and recommend secure alternatives.

- **Preconditions:**
    - User executes `cosmos_tls_scanner.py` with the authorization key as a command-line argument.
    - Attacker gains access to command history files or system logs on the user's system.

- **Source Code Analysis:**
    - **`_get_parser()` function:** Defines `--authorization-key` as a required command-line argument.
        ```python
        parser.add_argument(
            "--authorization-key",
            "-k",
            required=True,
            help="Master or Read-only key for account of the form khYANAIiAl12n...==",
        )
        ```
    - **`main()` function:** Retrieves `authorization-key` directly from command-line arguments (`args.authorization_key`).
    - The key is then used for authentication.

    **Visualization:**
    ```
    User Command Line --> argparse.ArgumentParser --> args.authorization_key --> _get_auth_header --> Cosmos DB
    ^
    |
    Command History/Logs
    ```
    Command history and logs can store the command line including the authorization key.

- **Security Test Case:**
    1. **Setup:** Python 3.5+, `requests`, `urllib3` installed, valid Cosmos DB endpoint and key.
    2. **Execution:** Run `cosmos_tls_scanner.py` with `--endpoint` and `--authorization-key` arguments.
        ```bash
        python3 cosmos_tls_scanner.py --endpoint <your_cosmos_db_endpoint> --authorization-key <your_cosmos_db_key>
        ```
    3. **Check Command History:** Examine shell command history files (`~/.bash_history`, `.zsh_history`, PowerShell history).
    4. **Verification:** Locate the executed command in history.
    5. **Observation:** Verify that the command history contains the `--authorization-key` and the plaintext Cosmos DB authorization key.