### Vulnerability List:

* SQL Injection in Database and Table Deletion

#### Vulnerability Name:
SQL Injection in Database and Table Deletion

#### Description:
The `delete_dataset.py` script allows users to delete database tables or the entire database. The table and database names are constructed directly from the `config.json` file without proper sanitization before being used in SQL DROP statements. An attacker who can modify the `config.json` file could inject malicious SQL code into the `table_prefix` or `database` configuration values. When `delete_dataset.py` is executed with the `-tables` or `-db` flags, this injected SQL code will be executed by the application, leading to potential unauthorized database modifications or data breaches.

Steps to trigger the vulnerability:
1.  Modify the `config.json` file.
2.  In the `sql` section, change the `table_prefix` value to a malicious SQL injection payload, for example: `"glue_"; DROP TABLE glue_train; --"` or change the `database` value to `"mydatabase; DROP DATABASE mydatabase; --"`.
3.  Run the `delete_dataset.py` script with the `-tables` flag to trigger table deletion or `-db` flag to trigger database deletion: `python delete_dataset.py -tables` or `python delete_dataset.py -db`.
4.  The injected SQL code will be executed along with the intended DROP TABLE or DROP DATABASE command.

#### Impact:
- **High**: An attacker can potentially delete arbitrary tables or databases, leading to data loss and service disruption. In more severe scenarios, depending on the database permissions and injected payload, an attacker could potentially gain unauthorized access to data, modify data, or even execute system commands on the database server.

#### Vulnerability Rank:
High

#### Currently Implemented Mitigations:
None. The application directly substitutes values from the configuration file into SQL queries without any sanitization or parameterization.

#### Missing Mitigations:
- **Input Sanitization:** The application should sanitize the `table_prefix` and `database` values from the `config.json` file to remove or escape any characters that could be used for SQL injection.
- **Parameterized Queries:**  Instead of string formatting to construct SQL queries, parameterized queries should be used. This would prevent SQL injection by ensuring that user-supplied data is treated as data, not as executable code.
- **Principle of Least Privilege:** The database user configured in `config.json` should have the minimum necessary privileges required for the application to function. This would limit the impact of a successful SQL injection attack. If only table deletion is needed, database deletion rights should be revoked.

#### Preconditions:
- The attacker must have the ability to modify the `config.json` file. This could be achieved through various means depending on the deployment environment, such as exploiting a separate vulnerability that allows file modification, or if the configuration file is inadvertently exposed or writable to unauthorized users.
- The `delete_dataset.py` script must be executed after the `config.json` file has been modified.

#### Source Code Analysis:
1.  **File: `/code/delete_dataset.py`**
2.  **Function: `delete_tables(config)`**
    ```python
    def delete_tables(config):
        engine = create_sql_engine(config)
        for split in ['train', 'validation', 'test']:
            table = config['sql']['table_prefix'] + split # [POINT OF VULNERABILITY 1] Table name is constructed from config
            try:
                print("Dropping table")
                print("table name:", table)
                # drop table
                stmt = "DROP TABLE IF EXISTS %s" % (table) # [POINT OF VULNERABILITY 2] Table name is directly inserted into SQL query using string formatting
                _ = engine.execute(stmt)

            except Exception as e:
                print(e)
                print("failed")

        engine.dispose()
    ```
    - **[POINT OF VULNERABILITY 1]:** The `table` variable is constructed by concatenating `config['sql']['table_prefix']` and the `split` name. If `config['sql']['table_prefix']` is attacker-controlled and contains malicious SQL code, it will be incorporated into the table name.
    - **[POINT OF VULNERABILITY 2]:** The `table` variable, which can be attacker-controlled, is directly inserted into the SQL `DROP TABLE` statement using string formatting (`%s`). This allows the attacker to inject arbitrary SQL commands.
3.  **Function: `delete_db(config)`**
    ```python
    def delete_db(config):
        engine = create_sql_engine(config)
        db_name = config['sql']['database'] # [POINT OF VULNERABILITY 3] Database name is taken from config

        try:
            print("Dropping database")
            print("database name:", db_name)
            # drop table
            stmt = "DROP DATABASE IF EXISTS [%s]" % (db_name) # [POINT OF VULNERABILITY 4] Database name is directly inserted into SQL query using string formatting
            _ = engine.execute(stmt)

        except Exception as e:
            print(e)
            print("failed")
        engine.dispose()
    ```
    - **[POINT OF VULNERABILITY 3]:** The `db_name` variable is directly taken from `config['sql']['database']`. If this value is attacker-controlled, it can contain malicious SQL code.
    - **[POINT OF VULNERABILITY 4]:** The `db_name` variable is directly inserted into the SQL `DROP DATABASE` statement using string formatting (`[%s]`). This allows for SQL injection if `db_name` is malicious.

#### Security Test Case:
1.  **Pre-requisites:**
    - Have a running instance of the project with a SQL database configured and populated with tables (e.g., after running `convert_dataset.py`).
    - Access to modify the `config.json` file.
2.  **Steps:**
    a.  Modify the `config.json` file.
    b.  In the `sql` section, change the `table_prefix` to `"glue_"; DROP TABLE glue_train; --"`.
    c.  Run the table deletion script: `python delete_dataset.py -tables`.
    d.  **Expected Outcome:** The script should attempt to drop tables. Due to the injected SQL, it will first attempt to drop the table with prefix "glue\_" and then execute `DROP TABLE glue_train; --`. This will result in an error because `glue_train` table is dropped already or was not intended to be dropped directly this way. In a more harmful scenario, an attacker could inject more damaging SQL.
    e.  Alternatively, modify `config.json` and set `database` to `"mydatabase"; DROP DATABASE mydatabase; --"`.
    f.  Run the database deletion script: `python delete_dataset.py -db`.
    g.  **Expected Outcome:** The script should attempt to drop the database. Due to the injected SQL, it will first attempt to drop the database named "mydatabase" and then execute `DROP DATABASE mydatabase; --`. This will result in an error because `mydatabase` database is dropped already or was not intended to be dropped directly this way. In a more harmful scenario, an attacker could inject more damaging SQL.
3.  **Cleanup:** Restore the original `config.json` file. Manually verify if tables or database were unintentionally dropped and restore them if necessary from backups or by re-running dataset conversion.

---
* SQL Injection in Table Creation and Data Insertion (Table Name)

#### Vulnerability Name:
SQL Injection in Table Creation and Data Insertion (Table Name)

#### Description:
The `convert_dataset.py` script creates new SQL tables to store the dataset. The table names are constructed using the `dataset` name and `split` name from the `config.json` file. If an attacker can modify the `config.json` and inject malicious SQL code into the `dataset` configuration value, this code will be used to construct the table name and subsequently embedded in SQL `CREATE TABLE` and `INSERT INTO` queries during the `df.to_sql()` operation. This can lead to arbitrary SQL execution.

Steps to trigger the vulnerability:
1.  Modify the `config.json` file.
2.  In the `data` section, change the `dataset` value to a malicious SQL injection payload, for example: `"glue_mrpc; DROP TABLE users; --"`.
3.  Run the dataset conversion script: `python convert_dataset.py`.
4.  The script will attempt to create tables and insert data. The injected SQL code within the dataset name will be executed during table creation or data insertion, potentially leading to unauthorized database operations.

#### Impact:
- **High**: An attacker could potentially modify database schema, delete or modify data in other tables (e.g., by injecting `DROP TABLE` or `UPDATE` statements), or potentially gain unauthorized access to data depending on the injected payload and database permissions.

#### Vulnerability Rank:
High

#### Currently Implemented Mitigations:
None. The application directly uses the dataset name from the configuration file to construct table names without sanitization.

#### Missing Mitigations:
- **Input Sanitization:** Sanitize the `dataset` value from the `config.json` file to prevent SQL injection.
- **Parameterized Table Names (if supported by library):** Investigate if `pandas.to_sql` or SQLAlchemy provides mechanisms to parameterize table names, although this is less common and might require a different approach to query construction.
- **Validation of Table Names:** Implement validation to ensure table names conform to expected patterns and do not contain special characters or SQL keywords that could be exploited.

#### Preconditions:
- The attacker must be able to modify the `config.json` file.
- The `convert_dataset.py` script must be executed after the malicious modification of `config.json`.

#### Source Code Analysis:
1.  **File: `/code/convert_dataset.py`**
2.  **Main code block:**
    ```python
    ...
    for split in raw_datasets.keys():
        ...
        df = pd.DataFrame(df_dict)

        table_name = config['data']['dataset'] + split # [POINT OF VULNERABILITY 1] Table name is constructed from config
        try:
            print("creating table")
            print("table name:", table_name)
            df.to_sql(table_name, con=engine, if_exists='replace', index=False, method='multi', chunksize=100) # [POINT OF VULNERABILITY 2] Table name used in df.to_sql
        except Exception as e:
            print(e)
            print("failed")
        ...
    ```
    - **[POINT OF VULNERABILITY 1]:** The `table_name` is constructed by concatenating `config['data']['dataset']` and `split`. If `config['data']['dataset']` is attacker-controlled, it can contain SQL injection payloads.
    - **[POINT OF VULNERABILITY 2]:** The `table_name`, potentially containing malicious SQL, is passed to `df.to_sql()`. While `pandas.to_sql` itself parameterizes data values, the table name itself is often not parameterized and can be vulnerable if constructed from unsanitized input. The underlying SQLAlchemy and database driver's behavior regarding table name parameterization needs to be considered, but in general, constructing table names via string concatenation with user-controlled input is risky.

#### Security Test Case:
1.  **Pre-requisites:**
    - Have a running instance of the project with SQL database configured.
    - Access to modify the `config.json` file.
2.  **Steps:**
    a.  Modify the `config.json` file.
    b.  In the `data` section, change the `dataset` value to `"glue_mrpc; DROP TABLE users; --"`. Assume a table named `users` exists in the database (for demonstration purposes - in a real attack, the attacker might target other tables).
    c.  Run the dataset conversion script: `python convert_dataset.py`.
    d.  **Expected Outcome:** The script execution might fail or produce database errors due to the injected SQL. More importantly, it might successfully execute the injected `DROP TABLE users;` command before attempting to create a table with the malicious name. Check the database to see if the `users` table (or another table targeted by the injected SQL) has been dropped or modified.
3.  **Cleanup:** Restore the original `config.json` file. Verify and restore any unintentionally dropped or modified tables from backups or by re-creating them.

---
* SQL Injection in Adding Clustered Index (Table Name)

#### Vulnerability Name:
SQL Injection in Adding Clustered Index (Table Name)

#### Description:
The `convert_dataset.py` script adds a clustered index to the newly created tables. The table name for index operations is directly taken as a parameter in the `add_clustered_index` function, which is derived from the potentially attacker-controlled `config.json` and split name. If a malicious table name is constructed via `config.json` manipulation (as described in the previous vulnerability), and the `convert_dataset.py` script proceeds to execute the `add_clustered_index` function with this malicious table name, SQL injection can occur within the index-related SQL statements.

Steps to trigger the vulnerability:
1.  Modify the `config.json` file to inject malicious SQL into the `dataset` name, as described in the "SQL Injection in Table Creation and Data Insertion (Table Name)" vulnerability.
2.  Run the `convert_dataset.py` script.
3.  The script will proceed to create tables with the malicious name and then attempt to add a clustered index using the `add_clustered_index` function. The injected SQL in the table name will be executed during the index operations.

#### Impact:
- **Medium to High**: Similar to table creation SQL injection, the impact can range from database errors to potential unauthorized data access or modification, depending on the injected SQL and database permissions, but is likely less severe than direct data manipulation as it's within index operations.

#### Vulnerability Rank:
Medium

#### Currently Implemented Mitigations:
None. The table name is directly used in SQL queries without sanitization.

#### Missing Mitigations:
- **Input Sanitization:** Sanitize table names before using them in SQL queries, even for index operations.
- **Parameterized Queries:** Use parameterized queries for index operations to prevent SQL injection.
- **Table Name Validation:** Validate table names to ensure they are safe and conform to expected patterns.

#### Preconditions:
- The attacker must be able to modify the `config.json` file and successfully inject malicious SQL into the `dataset` name.
- The `convert_dataset.py` script must be executed, and it must reach the `add_clustered_index` function call after creating tables with the malicious name.

#### Source Code Analysis:
1.  **File: `/code/convert_dataset.py`**
2.  **Function: `add_clustered_index(table, engine)`**
    ```python
    def add_clustered_index(table, engine): # [POINT OF VULNERABILITY 1] Table name parameter is taken without sanitization
        print("adding clustered index")

        stmt = "DROP INDEX IF EXISTS %s_idx ON %s" % (table, table) # [POINT OF VULNERABILITY 2] Table name used in DROP INDEX
        _ = engine.execute(stmt)

        # primary index as to be NOT NULL
        stmt = "ALTER TABLE %s alter column idx bigint NOT NULL" % table # [POINT OF VULNERABILITY 3] Table name used in ALTER TABLE
        _ = engine.execute(stmt)

        # add primary key
        stmt = """ALTER TABLE %s
                ADD CONSTRAINT %s_idx PRIMARY KEY CLUSTERED (idx)""" % (table, table) # [POINT OF VULNERABILITY 4] Table name used in ADD CONSTRAINT
        _ = engine.execute(stmt)
    ```
    - **[POINT OF VULNERABILITY 1]:** The `table` parameter, which can be attacker-controlled via `config.json` and table name construction, is directly used in SQL queries.
    - **[POINT OF VULNERABILITY 2, 3, 4]:** The `table` parameter is directly inserted into `DROP INDEX`, `ALTER TABLE`, and `ADD CONSTRAINT` SQL statements using string formatting (`%s`). This allows SQL injection if the `table` name is malicious.

#### Security Test Case:
1.  **Pre-requisites:**
    - Have a running instance of the project with SQL database configured.
    - Access to modify the `config.json` file.
2.  **Steps:**
    a.  Modify the `config.json` file.
    b.  In the `data` section, change the `dataset` value to `"glue_mrpc; EXEC sp_helpdb; --"`. This payload attempts to execute the `sp_helpdb` stored procedure (SQL Server specific, adjust for other DB types if needed) during index creation.
    c.  Run the dataset conversion script: `python convert_dataset.py`.
    d.  **Expected Outcome:** The script execution might proceed with table creation (potentially with the malicious name), and when it reaches the index creation phase, the injected SQL `EXEC sp_helpdb; --` will be executed. Observe the script's output and database server logs for any signs of the `sp_helpdb` procedure being executed or errors indicating SQL injection. The exact outcome depends on database permissions and how the injected SQL interacts with the index creation statements.
3.  **Cleanup:** Restore the original `config.json` file. Verify database integrity and correct any unintended changes if any malicious SQL was successfully executed.

---
* SQL Injection in Testing Table Connection (Table Name)

#### Vulnerability Name:
SQL Injection in Testing Table Connection (Table Name)

#### Description:
The `convert_dataset.py` script includes a `test_table` function to verify the SQL connection. This function constructs a `SELECT * FROM table` query where the table name is taken as input. If an attacker can influence the table name passed to `test_table` (which, again, can originate from the `config.json` via the `dataset` name), they can inject SQL code into this query. While this function is primarily for testing, a successful injection here demonstrates a broader vulnerability pattern within the project.

Steps to trigger the vulnerability:
1.  Modify the `config.json` file to inject malicious SQL into the `dataset` name, for example: `"glue_mrpc; EXEC sp_who; --"`.
2.  Run the `convert_dataset.py` script.
3.  The script will create tables and then call `test_table` with the constructed (malicious) table name. The injected SQL will be executed as part of the `SELECT * FROM ...` query.

#### Impact:
- **Low to Medium**: The impact in the `test_table` function itself might be limited as it's a `SELECT` statement. However, successful injection here highlights the lack of input sanitization, and if similar patterns exist in other parts of the application with more sensitive queries (as shown in other vulnerabilities described), the overall risk is higher. Injected SQL in a `SELECT` context could still be used to extract data if permissions allow, or cause denial of service by executing resource-intensive procedures.

#### Vulnerability Rank:
Medium

#### Currently Implemented Mitigations:
None. The table name is used directly in the SQL query without sanitization.

#### Missing Mitigations:
- **Input Sanitization:** Sanitize table names before using them in SQL queries, including testing queries.
- **Parameterized Queries:** Even for testing queries, consider using parameterized queries where possible, or at least properly escape table names.
- **Table Name Validation:** Validate table names to ensure they are safe.

#### Preconditions:
- The attacker must be able to modify the `config.json` file and inject malicious SQL into the `dataset` name.
- The `convert_dataset.py` script must be executed and reach the `test_table` function call.

#### Source Code Analysis:
1.  **File: `/code/convert_dataset.py`**
2.  **Function: `test_table(table, engine)`**
    ```python
    def test_table(table, engine): # [POINT OF VULNERABILITY 1] Table name parameter is taken without sanitization
        print("Testing connection to SQL server.")
        stmt = "SELECT * FROM %s" % table # [POINT OF VULNERABILITY 2] Table name used in SELECT query
        res = engine.execute(stmt)
        row = res.fetchone()
        print(row)
    ```
    - **[POINT OF VULNERABILITY 1]:** The `table` parameter, potentially attacker-controlled, is used in the function.
    - **[POINT OF VULNERABILITY 2]:** The `table` parameter is directly inserted into the `SELECT * FROM` SQL statement using string formatting (`%s`). This allows SQL injection if the `table` name is malicious.

#### Security Test Case:
1.  **Pre-requisites:**
    - Have a running instance of the project with SQL database configured.
    - Access to modify the `config.json` file.
2.  **Steps:**
    a.  Modify the `config.json` file.
    b.  In the `data` section, change the `dataset` value to `"glue_mrpc; EXEC sp_who; --"`. This payload attempts to execute the `sp_who` stored procedure (SQL Server specific, adjust for other DB types if needed) during the table test.
    c.  Run the dataset conversion script: `python convert_dataset.py`.
    d.  **Expected Outcome:** The script should execute, and when it calls `test_table`, the injected SQL `EXEC sp_who; --` will be executed as part of the `SELECT * FROM ...` query. Observe the script's output and database server logs for any signs of the `sp_who` procedure being executed or errors indicating SQL injection.
3.  **Cleanup:** Restore the original `config.json` file. Monitor database activity for any unauthorized data access or modifications that might have occurred due to the injected SQL.

---
* SQL Injection in Dataset Loading (Table Name in SQLDataset)

#### Vulnerability Name:
SQL Injection in Dataset Loading (Table Name in SQLDataset)

#### Description:
The `dataset.py` script defines the `SQLDataset` class, which is used to load data from SQL tables for training. The table name is constructed in the `__init__` method of `SQLDataset` using the `dataset` name and `split` from `config.json`. If an attacker can modify `config.json` to inject malicious SQL into the `dataset` value, this malicious code will be incorporated into the table name used in subsequent SQL queries within the `SQLDataset` methods (`get_embedding_size`, `__len__`, `load_data`). This leads to SQL injection vulnerabilities in data loading operations.

Steps to trigger the vulnerability:
1.  Modify the `config.json` file.
2.  In the `data` section, change the `dataset` value to a malicious SQL injection payload, for example: `"glue_mrpc; SELECT COUNT(*) FROM users; --"`. This payload attempts to execute `SELECT COUNT(*) FROM users;` alongside the intended query.
3.  Run the `train.py` or `dataset.py` script, which will instantiate `SQLDataset` and execute queries using the malicious table name.
4.  The injected SQL code within the dataset name will be executed when `SQLDataset` methods are called, potentially leading to unauthorized data access or other database operations.

#### Impact:
- **Medium to High**: Depending on the injected SQL and the context of the queries in `SQLDataset` (e.g., `SELECT`, `COUNT`), the impact can range from information disclosure (if data is extracted via injected `SELECT` statements) to potential denial of service or data modification if more aggressive SQL injection is possible within the query context.

#### Vulnerability Rank:
High

#### Currently Implemented Mitigations:
None. The table name is constructed from configuration and used directly in queries without sanitization.

#### Missing Mitigations:
- **Input Sanitization:** Sanitize the `dataset` value from `config.json`.
- **Parameterized Queries:** Use parameterized queries in `SQLDataset` methods to prevent SQL injection.
- **Table Name Validation:** Validate table names to ensure they are safe.

#### Preconditions:
- The attacker must be able to modify the `config.json` file and inject malicious SQL into the `dataset` name.
- The `train.py` or `dataset.py` script must be executed, which uses the `SQLDataset` class.

#### Source Code Analysis:
1.  **File: `/code/dataset.py`**
2.  **`SQLDataset.__init__(self, args, split="")`**
    ```python
    class SQLDataset(IterableDataset):
        def __init__(self, args, split=""):
            with open(args.config_file, "r") as f:
                config = json.load(f)
            self.config = config

            self.table = config['data']['dataset'] + split # [POINT OF VULNERABILITY 1] Table name constructed from config
            ...
    ```
    - **[POINT OF VULNERABILITY 1]:** The `self.table` attribute is constructed using `config['data']['dataset']` and `split`. If `config['data']['dataset']` is attacker-controlled, `self.table` will contain a SQL injection payload.
3.  **`SQLDataset.get_embedding_size(self)`**
    ```python
    def get_embedding_size(self):
        if self.embedding_size == None:
            stmt = "SELECT embedding FROM %s" % self.table # [POINT OF VULNERABILITY 2] self.table used in SELECT query
            embedding_json = self.execute_sql_query(stmt, nrows='one')[0]
            embedding = json.loads(embedding_json)
            self.embedding_size = len(embedding)
        return self.embedding_size
    ```
    - **[POINT OF VULNERABILITY 2]:** `self.table` (potentially malicious) is used in the `SELECT` query via string formatting (`%s`).
4.  **`SQLDataset.__len__(self)`**
    ```python
    def __len__(self):
        if self.len == None:
            stmt = "SELECT MAX(idx) FROM %s" % self.table # [POINT OF VULNERABILITY 3] self.table used in SELECT query
            self.len = self.execute_sql_query(stmt)[0][0]

        return self.len
    ```
    - **[POINT OF VULNERABILITY 3]:** `self.table` (potentially malicious) is used in the `SELECT` query via string formatting (`%s`).
5.  **`SQLDataset.load_data(self, indices)`**
    ```python
    def load_data(self, indices):
        stmt = "SELECT * FROM %s WHERE idx IN (%s)" % (self.table, indices) # [POINT OF VULNERABILITY 4] self.table used in SELECT query
        rows = self.execute_sql_query(stmt)
        return rows
    ```
    - **[POINT OF VULNERABILITY 4]:** `self.table` (potentially malicious) is used in the `SELECT` query via string formatting (`%s`).

#### Security Test Case:
1.  **Pre-requisites:**
    - Have a running instance of the project with SQL database configured and populated with data.
    - Access to modify the `config.json` file.
2.  **Steps:**
    a.  Modify the `config.json` file.
    b.  In the `data` section, change the `dataset` value to `"glue_mrpc; SELECT user_name(); --"`. This payload attempts to execute `SELECT user_name();` to retrieve the current database user.
    c.  Run the `dataset.py` script directly: `python dataset.py --split validation`. This script instantiates `SQLDataset` and will trigger queries using the malicious table name.
    d.  **Expected Outcome:** The script should execute and when `SQLDataset` methods like `get_embedding_size`, `__len__`, or during iteration are called, the injected SQL `SELECT user_name(); --` will be executed. Observe the script's output; it might print the username returned by the injected SQL or show database errors depending on how the injected SQL interacts with the intended queries.
3.  **Cleanup:** Restore the original `config.json` file. Monitor database logs for any unauthorized data access or operations that may have resulted from the injected SQL.