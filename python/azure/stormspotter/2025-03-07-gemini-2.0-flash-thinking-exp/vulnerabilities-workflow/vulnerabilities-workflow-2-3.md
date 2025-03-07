- Vulnerability Name: Potential Neo4j Injection through Insecure Data Sanitization
- Description:
  - An attacker crafts a malicious SQLite file.
  - This SQLite file contains JSON data that is designed to be parsed by the backend.
  - Within the JSON data, specific string fields are manipulated to include malicious Neo4j Cypher code.
  - The attacker uploads this malicious SQLite file to the Stormspotter backend via the `/api/upload` endpoint.
  - The backend processes the uploaded file, reads data from the SQLite database, and parses the JSON data.
  - The backend uses the parsed data to construct Cypher queries for inserting nodes and relationships into the Neo4j database.
  - Due to insufficient sanitization in the `sanitize_string` function, the malicious Cypher code injected in the JSON data is not properly escaped.
  - When the backend executes the constructed Cypher queries, the malicious Cypher code is executed in the Neo4j database.
  - This can allow the attacker to execute arbitrary Cypher queries, potentially leading to data manipulation, data exfiltration, or even complete compromise of the Neo4j database.
- Impact:
  - Critical. Successful Neo4j injection can allow an attacker to:
    - Read sensitive data from the Neo4j database.
    - Modify or delete data in the Neo4j database.
    - Potentially gain control over the Neo4j server if vulnerabilities exist in Neo4j itself.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
  - The project implements `sanitize_string` function in `/code/backend/backend/db.py` to sanitize string inputs before inserting into Neo4j.
  - `sanitize_string` function replaces backslashes with double backslashes and removes single quotes.
- Missing Mitigations:
  - The current `sanitize_string` function is insufficient to prevent Neo4j injection.
  - Proper input validation and sanitization of all string data before constructing Cypher queries is missing.
  - Consider using parameterized queries or Neo4j drivers' built-in sanitization mechanisms to prevent injection.
  - Implement more robust input validation on the uploaded files to ensure they conform to expected schema and data types.
- Preconditions:
  - Attacker needs to be able to upload a malicious SQLite file to the Stormspotter backend.
  - The Neo4j database must be connected and accessible to the backend.
- Source Code Analysis:
  - `/code/backend/backend/db.py`:
    - `sanitize_string(self, input_str)`: This function is intended for sanitization, but it's weak. It only replaces `\` with `\\` and removes `'`.
    - `generate_set_statement(self, asset, extra_labels=None)`: This function constructs the `SET` part of the Cypher query by iterating through asset properties and using `sanitize_string` for values.
    - `insert_asset(self, asset, label, asset_id, extra_labels=None)`: This function uses `generate_set_statement` to construct the Cypher query and executes it using `self.query`.
    - `create_relationship(...)`: Similar to `insert_asset`, it constructs Cypher query using `generate_set_statement` (for `relationship_properties`) and executes it using `self.query`.
    - `query(self, statement, requested=False)`: This function executes the raw Cypher query statement against the Neo4j database.
  - `/code/backend/backend/parser.py`:
    - `SSProcessor._parseObject(...)`: Parses JSON object and extracts fields.
    - `SSProcessor._postProcessResource(...)`: Processes resource properties.
    - Various `_parse*` functions (e.g., `_parseAADUser`, `_parseAADGroup`, `_parseDisk`): These functions parse specific resource types, create dictionaries of data, and call `self.neo.insert_asset` and `self.neo.create_relationship` to insert data into Neo4j.
- Security Test Case:
  1. Setup a Stormspotter instance (using docker-compose is recommended as per README).
  2. Create a malicious SQLite file. This file should contain a JSON object that, when parsed by the backend and inserted into Neo4j, will execute a malicious Cypher query. For example, modify a User object's 'displayName' to include a Cypher injection payload.
     - Example malicious JSON within SQLite:
       ```json
       {
         "objectId": "malicious-user",
         "objectType": "User",
         "displayName": "MaliciousUser', password: 'pwned'})//",
         "mail": "malicious@example.com"
       }
       ```
  3. Upload this malicious SQLite file to the `/api/upload` endpoint using a tool like `curl` or Postman.
     - Example `curl` command:
       ```bash
       curl -X POST -H "Content-Type": multipart/form-data" -F "upload=@malicious.sqlite" http://localhost:9090/api/upload -H "x-neo4j-user: neo4j" -H "x-neo4j-pass: password"
       ```
  4. Check the Neo4j database (using Neo4j Browser at http://localhost:7474, credentials neo4j/password).
  5. Verify if the malicious Cypher code was executed. For example, in the example payload, check if a property `password: 'pwned'` is unexpectedly set on the "MaliciousUser" node, or if other unexpected changes in the database occur, indicating successful injection.
  6. Observe backend logs for any errors or unusual activities during processing.