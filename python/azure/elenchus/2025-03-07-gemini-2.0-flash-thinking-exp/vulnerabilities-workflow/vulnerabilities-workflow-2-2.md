- Vulnerability Name: Insecure Storage of Database Credentials in Configuration File

- Description:
    1. The project requires users to create a `config.json` file to store database connection details.
    2. The `README.md` and code explicitly instruct users to input sensitive information such as database username and password directly into this `config.json` file.
    3. The code then reads this `config.json` file in plain text to establish a connection to the SQL database.
    4. If a user insecurely stores or handles this `config.json` file (e.g., commits it to a public repository, leaves it accessible in a world-readable location, or shares it insecurely), the database credentials become exposed.
    5. An attacker who gains access to this `config.json` file can then use these credentials to access the SQL database.

- Impact:
    - **High:** Unauthorized access to the SQL database.
    - Depending on the database permissions associated with the exposed credentials, an attacker could:
        - Read sensitive data stored in the database.
        - Modify or delete data, leading to data integrity issues or data loss.
        - Execute arbitrary SQL commands, potentially leading to further system compromise, including data exfiltration, privilege escalation within the database system, or even denial of service.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None. The project currently provides no built-in mechanisms to protect the database credentials stored in `config.json`. The documentation does not warn against insecure handling of `config.json` beyond general advice to "keep the username/password somewhere safe".

- Missing Mitigations:
    - **Secure Credential Storage:** The project should not rely on storing plain text credentials in a configuration file. Missing mitigations include:
        - **Environment Variables:**  Instruct users to store database credentials as environment variables instead of in `config.json`. The code should be modified to read credentials from environment variables.
        - **Credential Vault/Secrets Management:** Recommend or integrate with secure credential management solutions (like Azure Key Vault, HashiCorp Vault, or similar) for storing and retrieving database credentials.
        - **Configuration File Encryption:** If a configuration file is still used, it should be encrypted, and a secure mechanism for decryption should be implemented (though this adds complexity and is generally less secure than environment variables or vault solutions for this type of application).
        - **Warning in Documentation:**  At a minimum, the documentation should strongly warn users about the risks of storing sensitive credentials in `config.json` and provide clear guidance on secure alternatives.

- Preconditions:
    - User must create a `config.json` file and store database credentials within it as instructed by the `README.md`.
    - The `config.json` file must be accessible to an attacker. This could happen if the user:
        - Commits `config.json` to a version control system (especially a public repository).
        - Stores `config.json` in a publicly accessible location on a server.
        - Shares `config.json` via insecure channels (e.g., email, unencrypted file sharing).
        - Has their local machine or server compromised where `config.json` is stored.

- Source Code Analysis:

    1. **Configuration Loading:**
        - Files: `convert_dataset.py`, `delete_dataset.py`, `dataset.py`, `train.py`
        - Code Snippet (from `convert_dataset.py`, similar in other files):
          ```python
          with open("config.json", "r") as f:
              config = json.load(f)
          ```
        - Analysis: All the main Python scripts start by opening and reading `config.json` using `json.load()`. This parses the JSON file into a Python dictionary named `config`.

    2. **Database Connection String Creation:**
        - Files: `convert_dataset.py`, `delete_dataset.py`, `dataset.py`
        - Code Snippet (from `convert_dataset.py`, similar in other files):
          ```python
          def create_sql_engine(config):
              conn = f"""Driver={config['sql']['driver']};Server=tcp:{config['sql']['server']},1433;Database={config['sql']['database']};
              Uid={config['sql']['username']};Pwd={config['sql']['password']};Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;"""

              params = urllib.parse.quote_plus(conn)
              conn_str = 'mssql+pyodbc:///?autocommit=true&odbc_connect={}'.format(params)
              engine = create_engine(conn_str,echo=False,fast_executemany=True, pool_size=1000, max_overflow=100)

              print('connection is ok')

              return engine
          ```
        - Visualization:
          ```
          config.json --> config (Python dictionary) -->  config['sql']['driver'], config['sql']['server'], config['sql']['database'], config['sql']['username'], config['sql']['password'] --> conn (connection string - includes credentials in plain text) --> conn_str (URL encoded connection string) --> engine (SQLAlchemy engine)
          ```
        - Analysis: The `create_sql_engine` function retrieves database connection parameters directly from the `config` dictionary, which was loaded from `config.json`. It then constructs a connection string `conn` using an f-string, embedding the username and password in plain text directly into the connection string. This connection string is then used to create a SQLAlchemy engine.  The credentials are thus used directly from the `config.json` file without any security measures.

- Security Test Case:

    1. **Setup:**
        - Assume an attacker has gained access to a `config.json` file created by a user of this project. This could be through various means (e.g., finding it in a public GitHub repository, compromised server, etc.).
        - The `config.json` file contains valid database credentials, structured as expected by the project, for a SQL Server instance.
        - The attacker has a machine with Python and `pyodbc` installed.

    2. **Steps to Exfiltrate Credentials (Demonstration):**
        - **Step 1: Obtain `config.json`:**  The attacker obtains a copy of the user's `config.json` file. Let's assume the content of `config.json` is:
          ```json
          {
              "sql": {
                  "username": "db_user",
                  "password": "P@$$wOrd",
                  "driver": "ODBC Driver 18 for SQL Server",
                  "server": "your_db_server.database.windows.net",
                  "database": "your_db"
              },
              "data": { ... },
              "model": { ... }
          }
          ```

        - **Step 2: Extract Credentials:** The attacker can use a simple Python script to read and print the credentials from the `config.json` file.
          ```python
          import json

          with open("config.json", "r") as f:
              config = json.load(f)

          username = config['sql']['username']
          password = config['sql']['password']
          server = config['sql']['server']
          database = config['sql']['database']

          print(f"Database Server: {server}")
          print(f"Database Name: {database}")
          print(f"Username: {username}")
          print(f"Password: {password}")
          ```

        - **Step 3: Execute the script:** The attacker runs this Python script in the same directory as the `config.json` file.

        - **Step 4: Observe Output:** The script will output the database credentials in plain text to the attacker's console.
          ```
          Database Server: your_db_server.database.windows.net
          Database Name: your_db
          Username: db_user
          Password: P@$$wOrd
          ```

    3. **Impact Demonstration:**
        - With these extracted credentials, the attacker can now use any SQL client or tool to connect to the database server (`your_db_server.database.windows.net`) and database (`your_db`) using the username (`db_user`) and password (`P@$$wOrd`).
        - They can then perform unauthorized actions on the database as described in the "Impact" section above.

This test case clearly demonstrates how an attacker can easily extract database credentials if they gain access to the `config.json` file, confirming the vulnerability.