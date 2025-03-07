- Vulnerability Name: Hardcoded Database Credentials in Configuration File
- Description:
    1. The project requires users to create a `config.json` file to store database connection details.
    2. This `config.json` file is intended to contain sensitive information, including database username and password in plain text.
    3. The scripts `convert_dataset.py`, `delete_dataset.py`, and `dataset.py` read the database credentials directly from this `config.json` file to establish a connection to the SQL database.
    4. If a user unintentionally exposes this `config.json` file (e.g., by committing it to a public version control repository, sharing it insecurely, or leaving it accessible on a publicly accessible system), an attacker can easily obtain the database credentials.
    5. With these credentials, an attacker can gain unauthorized access to the SQL database.
- Impact:
    - Unauthorized access to the SQL database.
    - Depending on the database permissions and the sensitivity of the data stored, the attacker could:
        - Read sensitive data stored in the database, leading to data breaches and privacy violations.
        - Modify or delete data, causing data corruption or loss of data integrity.
        - Potentially gain further access to the system hosting the database, depending on the database server's security configuration and network setup.
        - Disrupt the service by deleting or corrupting critical data.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The project, as designed, requires storing credentials in `config.json` and provides no built-in mechanisms to protect this file or the credentials within it.
- Missing Mitigations:
    - **Secure Credential Storage:** The project should avoid storing database credentials in plain text in a configuration file. Instead, it should use more secure methods such as:
        - **Environment Variables:**  Credentials can be stored as environment variables, which are less likely to be accidentally committed to version control. The application can then read credentials from the environment.
        - **Secrets Management Systems:** For more robust security, integrate with a secrets management system (like Azure Key Vault, HashiCorp Vault, etc.) to securely store and retrieve credentials.
        - **Configuration Encryption:**  Encrypt the `config.json` file or at least the sensitive sections containing credentials. The application would then need a decryption key, which itself needs to be managed securely.
    - **Documentation and User Warnings:** The documentation, especially the "Getting Started" section, should prominently warn users about the security risks of storing credentials in `config.json` and advise them on best practices for securing these credentials (e.g., using environment variables, restricting file access permissions, not committing the file to public repositories).
    - **`.gitignore` Configuration:**  Include `config.json` in the `.gitignore` file by default in the repository to prevent accidental commits of the configuration file containing sensitive information.
- Preconditions:
    1. The user follows the "Getting Started" instructions and creates a `config.json` file, populating it with their actual database credentials.
    2. The user unintentionally exposes the `config.json` file. Common scenarios for exposure include:
        - Accidentally committing `config.json` to a public Git repository (or a repository that becomes public later).
        - Storing `config.json` on a publicly accessible web server without proper access controls.
        - Sharing the `config.json` file via insecure channels (e.g., email, unencrypted file sharing services).
- Source Code Analysis:
    - **File: `/code/convert_dataset.py` and `/code/delete_dataset.py` and `/code/dataset.py`**
        - The function `create_sql_engine` (in `convert_dataset.py` and `delete_dataset.py`) and `init_sql_engine` (in `dataset.py`) are responsible for establishing the database connection.
        - They both start by reading the `config.json` file:
          ```python
          with open("config.json", "r") as f:
              config = json.load(f)
          ```
        - Then, they directly access the SQL credentials from the loaded `config` dictionary:
          ```python
          conn = f"""Driver={config['sql']['driver']};Server=tcp:{config['sql']['server']},1433;Database={config['sql']['database']};
          Uid={config['sql']['username']};Pwd={config['sql']['password']};Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;""" # in convert_dataset.py and delete_dataset.py
          ```
          ```python
          conn = f"""Driver={config['sql']['driver']};Server=tcp:{config['sql']['server']},1433;Database={config['sql']['database']};
          Uid={config['sql']['username']};Pwd={config['sql']['password']};Encrypt=yes;TrustServerCertificate=yes;Connection Timeout=1;""" # in dataset.py
          ```
        - The username (`Uid`) and password (`Pwd`) are directly taken from `config['sql']['username']` and `config['sql']['password']` respectively and embedded into the connection string.
        - This connection string is then used by `sqlalchemy.create_engine` to create the database engine, which is used throughout the scripts to interact with the SQL database.
        - **Visualization:**

          ```
          config.json --> JSON Loader --> config dictionary --> Extract 'sql' section --> Extract 'username', 'password', etc. --> Build Connection String --> sqlalchemy.create_engine --> Database Connection
          ```

    - **File: `/code/README.md`**
        - The "Getting Started" section instructs users to "update the provided template file `config_template.json` ... and store the file under `config.json`".
        - It lists the required information to be put in `config.json`, including `username` and `password`.
        - There is no warning or guidance about the security implications of storing these credentials in plain text in `config.json` or how to protect this file.

- Security Test Case:
    1. **Setup:**
        - Follow the instructions in `README.md` to set up the project.
        - Create a `config.json` file in the `/code/` directory and populate it with valid credentials for a test Azure SQL database. Ensure this test database contains non-sensitive data for testing purposes.
        - Initialize the conda environment as described in `README.md`.
    2. **Simulate Exposure:**
        -  For the purpose of this test, assume the attacker has gained access to the `config.json` file. This could be simulated by:
            -  Intentionally copying `config.json` to a publicly accessible location (e.g., a public GitHub repository - **do not actually commit real credentials to a public repository for real testing, use a dummy file or a private repository for safe testing**).
            -  Placing `config.json` in a publicly accessible directory of a web server.
            -  Simply making the file readable by another user on a shared system if simulating an internal attacker.
    3. **Attacker Action - Credential Extraction:**
        - As an attacker, access the exposed `config.json` file (e.g., by browsing the public repository, accessing the web server directory, or directly accessing the file if permissions allow).
        - Open the `config.json` file and read the values for `username` and `password` under the `"sql"` section. Also, note the `server` and `database` values.
    4. **Attacker Action - Unauthorized Database Access:**
        - Use the extracted credentials to attempt to connect to the SQL database. This can be done using:
            - A SQL client tool like `sqlcmd` or SQL Server Management Studio (SSMS).
            - Or by using the provided `delete_dataset.py` script. Open a terminal, navigate to the `/code/` directory, and run:
              ```bash
              python delete_dataset.py -tables
              ```
              or
              ```bash
              python delete_dataset.py -db
              ```
        - If using `delete_dataset.py`, observe the script output. If the connection is successful and the script proceeds to attempt to delete tables or the database, it confirms unauthorized access.
        - If using a SQL client, attempt to connect using the extracted server, database, username, and password. Upon successful connection, the attacker has gained unauthorized access. They can then execute SQL queries, browse tables, and potentially modify or delete data, depending on the permissions associated with the compromised user account.
    5. **Verification:**
        - Successful execution of `delete_dataset.py` or successful connection using a SQL client with the extracted credentials demonstrates that an attacker can gain unauthorized access to the database by obtaining the exposed `config.json` file. This validates the vulnerability.