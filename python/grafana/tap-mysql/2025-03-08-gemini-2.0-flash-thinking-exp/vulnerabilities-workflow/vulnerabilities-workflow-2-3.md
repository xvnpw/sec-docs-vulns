- Vulnerability Name: Insecure Storage of Database Credentials
- Description: The tap-mysql project relies on a `config.json` file to store sensitive database credentials, including hostname, port, username, and password, in plaintext. If a user mismanages this `config.json` file by, for example, accidentally committing it to a public repository, storing it in an insecure location, or failing to restrict access permissions, an attacker could gain unauthorized access to the MySQL database. This is because the attacker can easily read the plaintext credentials from the exposed `config.json` file.
- Impact: Critical. Successful exploitation of this vulnerability grants an attacker full access to the MySQL database. This can lead to severe consequences, including complete data breaches, unauthorized data manipulation, data loss, and potentially further compromise of systems and data depending on the database's content and the attacker's objectives.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations: None. The project provides no built-in mechanisms to secure the database credentials stored in `config.json`. The documentation in `README.md` explicitly instructs users to create this file and store credentials in plaintext without any security warnings or recommendations for secure handling.
- Missing Mitigations:
    - Secure Credential Storage: The project should not encourage or necessitate the storage of plaintext credentials in a configuration file. Instead, it should implement or recommend secure alternatives such as:
        - Environment Variables:  Guide users to use environment variables for sensitive configurations, as these are generally not stored in version control and can be managed more securely within deployment environments.
        - Secrets Management Systems:  Integrate with or recommend the use of secrets management systems (e.g., HashiCorp Vault, AWS Secrets Manager, etc.) for retrieving database credentials.
        - Credential Encryption: If a configuration file is deemed necessary, implement encryption for the sensitive sections (specifically the password) within the `config.json` file. The tap would then need a mechanism to decrypt these credentials at runtime, ideally using a key that is not stored alongside the encrypted credentials.
    - Security Best Practices Documentation: The `README.md` and any accompanying documentation should include prominent security warnings. These warnings should:
        - Emphasize the extreme risks of storing plaintext database credentials in `config.json` and the dangers of exposing this file.
        - Strongly recommend secure credential management practices, such as using environment variables or dedicated secrets management solutions.
        - Advise against committing `config.json` files containing sensitive information to version control systems, especially public repositories.
- Preconditions:
    - The user follows the project's instructions and creates a `config.json` file to configure the tap, including storing MySQL database credentials in plaintext within this file.
    - The `config.json` file is then exposed to an attacker through insecure practices. Common scenarios include:
        - Accidental Commit to Public Repository: The user inadvertently commits the `config.json` file to a public version control repository like GitHub.
        - Insecure Server Configuration: The `config.json` file is placed in a publicly accessible directory on a web server or storage service due to misconfigured permissions.
        - Local System Compromise: An attacker gains unauthorized access to the user's local system where the `config.json` file is stored.
- Source Code Analysis:
    1. README.md Exposure: The `README.md` file, specifically the "Create the configuration file" section, provides a code example that directs users to create a `config.json` file and explicitly store database credentials in plaintext JSON format:
    ```json
    {
      "host": "localhost",
      "port": "3306",
      "user": "root",
      "password": "password"
    }
    ```
    This documentation actively encourages insecure practices by demonstrating and recommending plaintext credential storage without any security caveats.
    2. Configuration Loading in `__init__.py` and Test Files: The source code, particularly within `__init__.py` and the test files (e.g., `tests/nosetests/utils.py`), demonstrates the application's reliance on configuration parameters loaded from the `config.json` file. The code directly accesses these configurations via `args.config`, assuming the presence of plaintext credentials within this dictionary.  For example, test files use environment variables as a *testing* mechanism, implying a better security practice exists but is not promoted for general usage.
    3. `connection.py` - Direct Credential Usage: The `connection.py` file contains the `MySQLConnection` class, which is responsible for establishing connections to the MySQL database. The constructor of this class directly takes the `config` dictionary (originating from `config.json`) and uses the plaintext 'user' and 'password' values to initialize the database connection:
    ```python
    args = {
        "user": config["user"],
        "password": config["password"],
        ...
    }
    super().__init__(defer_connect=True, ssl=ssl_arg, **args)
    ```
    No encryption, secure lookup, or any form of secure credential handling is implemented within this connection logic. The application directly trusts and utilizes the plaintext credentials provided in the configuration.

- Security Test Case:
    1. Setup:
        - Threat Actor Scenario: Assume an external attacker is reviewing publicly available repositories on GitHub to find potential vulnerabilities.
        - Project Discovery: The attacker discovers a public GitHub repository for a project that utilizes `tap-mysql`.
        - Repository Cloning: The attacker clones this repository to their local machine.
        - Configuration File Inspection: The attacker examines the repository's contents and specifically looks for configuration files.  They find a `config.json` file in the repository's root directory, which is unusual for public repositories but represents a user mistake this vulnerability highlights.
        - Credential Assessment: The attacker opens `config.json` and finds plaintext MySQL database credentials, including `"user": "testuser"` and `"password": "P@$$wOrd"`.
    2. Exploit:
        - Credential Extraction: The attacker extracts the hostname, port, username, and password from the `config.json` file. Let's say these are:
            - Host: `db.example.com`
            - Port: `3306`
            - User: `testuser`
            - Password: `P@$$wOrd`
        - Database Connection Attempt: The attacker uses a MySQL client (e.g., the `mysql` command-line client, MySQL Workbench, DBeaver) from their own machine. They attempt to connect to the target MySQL database using the following command (or equivalent GUI operation):
        ```bash
        mysql -h db.example.com -P 3306 -u testuser -pP@$$wOrd
        ```
    3. Verification:
        - Successful Connection: The attacker successfully connects to the MySQL database without any authentication errors, indicating that the extracted credentials are valid.
        - Unauthorized Data Access: Once connected, the attacker executes a simple SQL query to verify access to the database, such as:
        ```sql
        SELECT * FROM some_sensitive_table LIMIT 10;
        ```
        - Data Breach Confirmation: The query returns data from the database, confirming that the attacker has gained unauthorized access and can potentially read, modify, or delete data within the MySQL database. This confirms the vulnerability.