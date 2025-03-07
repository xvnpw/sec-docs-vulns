* Vulnerability Name: SQL Injection via `database` field in `config.json`
* Description:
    1. The application reads database configuration parameters from a `config.json` file.
    2. The `database` field from the `config.json` file is used to construct the SQL connection string in the `create_sql_engine` function in `convert_dataset.py`, `delete_dataset.py`, and `dataset.py`.
    3. The `database` field is also used in SQL queries in `delete_dataset.py` when dropping the database using string formatting.
    4. If an attacker can modify the `config.json` file and inject malicious SQL code into the `database` field, this code will be executed when the application connects to the database or attempts to delete the database.
    5. For example, an attacker could set the `database` field in `config.json` to `mydatabase;DROP TABLE users;--`.
    6. When `delete_dataset.py` with `-db` argument is executed, the `delete_db` function will be called.
    7. Inside `delete_db`, the SQL statement `DROP DATABASE IF EXISTS [mydatabase;DROP TABLE users;--]` will be executed.
    8. This will first attempt to drop a database named `mydatabase`, and then execute `DROP TABLE users;--`, which will drop the `users` table in the connected SQL server. The `--` comments out any subsequent SQL code.
* Impact:
    Critical. An attacker can execute arbitrary SQL commands on the database server. This can lead to:
    - Data exfiltration: Accessing and stealing sensitive data from other tables in the database.
    - Data manipulation: Modifying or deleting critical data in the database.
    - Data destruction: Dropping tables or even the entire database, leading to complete data loss.
    - Privilege escalation: Potentially gaining administrative access to the database server depending on the injected commands and database permissions.
* Vulnerability Rank: Critical
* Currently Implemented Mitigations:
    None. The application directly uses the `database` value from `config.json` without any sanitization or validation.
* Missing Mitigations:
    - Input validation: Sanitize and validate the `database` field from `config.json` to ensure it only contains expected characters and does not include any SQL keywords or commands.
    - Parameterized queries: Use parameterized queries or prepared statements instead of string formatting to construct SQL queries. This prevents SQL injection by separating SQL code from user-supplied data. For database and table names, consider using an ORM or database library that provides safe methods for database schema manipulation.
    - Principle of least privilege: Ensure that the database user configured in `config.json` has only the minimum necessary privileges required for the application to function. Avoid using database administrator accounts.
* Preconditions:
    - The attacker must be able to modify the `config.json` file. This could be achieved through various means, such as:
        - Exploiting another vulnerability in the application or the system where it is deployed that allows file modification.
        - If the application is deployed in a publicly accessible environment and the `config.json` file is not properly protected.
    - The application must be executed with the modified `config.json` file, specifically running `delete_dataset.py` with `-db` flag in this example.
* Source Code Analysis:
    1. **File:** `/code/delete_dataset.py`
    2. **Function:** `delete_db(config)`
    3. **Line:** `db_name = config['sql']['database']` - Reads the `database` name from the `config.json` file.
    4. **Line:** `stmt = "DROP DATABASE IF EXISTS [%s]" % (db_name)` - Constructs the SQL DROP DATABASE statement using string formatting and the unsanitized `db_name`.
    5. **Line:** `_ = engine.execute(stmt)` - Executes the constructed SQL statement.

    ```python
    def delete_db(config):
        engine = create_sql_engine(config) # SQL engine is created with potentially malicious config
        db_name = config['sql']['database'] # db_name is read from config
        try:
            print("Dropping database")
            print("database name:", db_name)
            # drop table
            stmt = "DROP DATABASE IF EXISTS [%s]" % (db_name) # SQL statement is constructed with string formatting
            _ = engine.execute(stmt) # Malicious SQL is executed

        except Exception as e:
            print(e)
            print("failed")
        engine.dispose()
    ```

* Security Test Case:
    1. **Precondition**: Access to modify `config.json` file. Assume attacker has access to modify `config.json` locally or through some other means.
    2. **Modify `config.json`**:
        - Open `config.json` and locate the `database` field under the `sql` section.
        - Change the value of the `database` field to: `testdb;DROP TABLE users;--`. Replace `testdb` with your actual test database name if needed.
        ```json
        "sql": {
          "driver": "ODBC Driver 18 for SQL Server",
          "server": "<your_server_url>",
          "database": "testdb;DROP TABLE users;--",
          "username": "<your_username>",
          "password": "<your_password>",
          "table_prefix": "glue_"
        },
        ```
        **Note**: Ensure you have a table named `users` in the `testdb` database for testing purposes, or change `DROP TABLE users` to a less destructive command for initial testing. **Use a dedicated test database for safety.**
    3. **Execute `delete_dataset.py`**:
        - Run the script `python delete_dataset.py -db` from the command line in the `/code/` directory.
    4. **Observe the result**:
        - Check the SQL Server logs or database state to see if the `users` table has been dropped (or if the injected SQL command has been executed).
        - If the SQL Injection is successful, the `users` table should be dropped, or other injected SQL commands will be executed.
    5. **Expected outcome**: The `delete_dataset.py` script should execute the injected SQL command, demonstrating the SQL Injection vulnerability. In this case, the `users` table in the `testdb` database should be dropped.