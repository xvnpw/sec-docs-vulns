## Combined Vulnerability Report

This report summarizes identified high and critical vulnerabilities in the Stormspotter application.

### 1. Stored Cross-Site Scripting (XSS) via Backend API Data Injection

- **Description:**
    1. An attacker crafts a malicious JSON payload containing JavaScript code.
    2. The attacker uploads this malicious JSON file to the Stormspotter backend through the `/api/upload` endpoint.
    3. The backend processes the uploaded file and stores the malicious payload into the Neo4j database without proper sanitization.
    4. When a user accesses the Stormspotter frontend and views the attack graph, the frontend fetches data from the Neo4j database.
    5. The frontend renders the malicious payload from the database in the user's browser without proper output encoding or sanitization.
    6. The attacker's JavaScript code is executed in the user's browser, potentially leading to session hijacking, data theft, or other malicious actions.

- **Impact:**
    - Successful exploitation of this vulnerability allows an attacker to execute arbitrary JavaScript code in the context of a Stormspotter user's browser.
    - This can lead to:
        - **Account Compromise:** An attacker could steal session cookies or local storage tokens, gaining unauthorized access to the user's Stormspotter account and potentially the Azure environment visualized within Stormspotter if the user has saved Azure credentials in the browser.
        - **Data Theft:**  An attacker could steal sensitive information displayed in the Stormspotter UI, such as Azure resource configurations, relationships, and potentially credentials if exposed in the graph.
        - **Redirection to Malicious Sites:** The attacker could redirect the user to a malicious website, potentially leading to further phishing or malware attacks.
        - **Defacement:** The attacker could modify the displayed attack graph or UI elements, causing confusion or misinformation.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - **Partial Input Sanitization in Backend:** The `backend/backend/db.py` file contains a `sanitize_string` function.
    ```python
    def sanitize_string(self, input_str):
        """ clean objects that come in as type string """
        if input_str:
            return input_str.replace("\\", "\\\\").replace("'", "")
        return input_str
    ```
    This function is used in `generate_set_statement` to sanitize string inputs before constructing Cypher queries. However, this sanitization is insufficient to prevent XSS as it only escapes backslashes and single quotes, and does not perform HTML entity encoding or any other XSS-specific sanitization. This mitigation is located in `backend/backend/db.py`.

- **Missing Mitigations:**
    - **Backend Input Sanitization:** Implement proper input sanitization in the backend before storing data in the Neo4j database. This should include HTML entity encoding or using a robust HTML sanitization library to neutralize potentially malicious HTML or JavaScript code within user-provided data. Sanitize data in `backend/backend/parser.py` before calling `neo.insert_asset`.
    - **Frontend Output Encoding:** Implement output encoding in the frontend when displaying data fetched from the Neo4j database. This will ensure that any potentially malicious code stored in the database is rendered as plain text in the browser, preventing execution. This should be implemented in the Vue.js frontend components responsible for displaying graph data.

- **Preconditions:**
    - The attacker needs to be able to upload a JSON file to the Stormspotter backend via the `/api/upload` endpoint.
    - The Stormspotter frontend must render data from the Neo4j database without proper output encoding.
    - A user must access the frontend and view the attack graph containing the attacker's injected malicious data.

- **Source Code Analysis:**
    1. **Backend API Endpoint (`backend/backend/main.py`):**
        - The `/api/upload` endpoint in `backend/backend/main.py` is responsible for handling file uploads.
        - It calls the `process` function of the `SSProcessor` class in `backend/backend/parser.py` to handle the uploaded file.
        ```python
        @app.post("/api/upload")
        async def process_upload(
            task: BackgroundTasks,
            x_neo4j_user: str = Header("neo4j"),
            x_neo4j_pass: str = Header("password"),
            upload: UploadFile = File(...),
        ):
            upload.file.rollover()
            task.add_task(
                sshandler.process,
                upload.file._file,
                upload.filename,
                x_neo4j_user,
                x_neo4j_pass,
            )
            return {"status": "Upload Success"}
        ```

    2. **Data Processing in Backend (`backend/backend/parser.py`):**
        - The `SSProcessor.process` function in `backend/backend/parser.py` handles the uploaded file, extracts data, and calls functions to parse different types of Azure resources.
        - The parsing functions (e.g., `_parseAADUser`, `_parseKeyVault`, `_parseGeneric`, etc.) extract relevant fields from the JSON data and store them in dictionaries.
        - The `_postProcessResource` function performs some basic property parsing but does not include any XSS sanitization.
        - The extracted and processed data is then passed to the `Neo4j` class for database insertion.
        ```python
        async def _parseObject(self, data: dict, fields: List[str], label: str) -> dict:
            parsed = {f.split("@")[0]: data.get(f) for f in fields}
            parsed["raw"] = orjson.dumps(data).decode()
            parsed["type"] = label
            # ... (rest of the parsing logic) ...
            return parsed

        async def _postProcessResource(self, resource: dict) -> dict:
            resource_attrs = {
                k: await self._parseProperty(v) for k, v in resource.items() if k != "raw"
            }
            resource_attrs["raw"] = resource["raw"]
            # ... (rest of the processing logic) ...
            return {**resource_attrs, **resource_props}

        async def _parseGeneric(self, generic: dict, rgroup: str):
            parsed = await self._parseObject(generic, generic.keys(), GENERIC_NODE_LABEL)
            post_generic = await self._postProcessResource(parsed)

            self.neo.insert_asset(post_generic, GENERIC_NODE_LABEL, post_generic["id"]) # Data inserted into Neo4j
            # ... (rest of the function) ...
        ```

    3. **Database Insertion (`backend/backend/db.py`):**
        - The `Neo4j.insert_asset` function in `backend/backend/db.py` constructs a Cypher query using `base_import_cypher` and `generate_set_statement` to insert data into the Neo4j database.
        - The `generate_set_statement` function calls `sanitize_string` for each value.
        - As analyzed earlier, `sanitize_string` provides insufficient sanitization for XSS prevention.
        ```python
        base_import_cypher = """MERGE (obj:{label}{{id:'{id}'}}) SET {set_statement}"""

        def generate_set_statement(self, asset, extra_labels=None):
            """ parses resource for type and creates appropriate index via id"""
            def f(x):
                return (
                    f"'{self.sanitize_string(x)}'" if (isinstance(x, str) or not x) else x
                )

            set_statements_parts = [
                f"obj.{key} = {f(value)}" for key, value in asset.items() if not key == "id"
            ]
            # ... (rest of the function) ...
            return ", ".join(set_statements_parts)

        def insert_asset(self, asset, label, asset_id, extra_labels=None):
            """ inserts asset into graph """
            set_statement = self.generate_set_statement(asset, extra_labels)
            statement = self.base_import_cypher.format(
                label=label, id=asset_id.lower(), set_statement=set_statement
            )
            try:
                self.query(statement) # Cypher query execution
            except ConnectionResetError as e:
                # ... (error handling) ...
        ```
        - **Visualization:**
          ```mermaid
          graph LR
              A[Frontend UI] --> B(Neo4j Database)
              C[Backend API (/api/upload)] --> D(SSProcessor.process in parser.py)
              D --> E(Neo4j.insert_asset in db.py)
              E --> B
              F[Attacker] --> C

              style A fill:#f9f,stroke:#333,stroke-width:2px
              style B fill:#ccf,stroke:#333,stroke-width:2px
              style C fill:#ccf,stroke:#333,stroke-width:2px
              style D fill:#ccf,stroke:#333,stroke-width:2px
              style E fill:#ccf,stroke:#333,stroke-width:2px
              style F fill:#f9f,stroke:#333,stroke-width:2px

              F -- Malicious JSON Upload --> C
              B -- Data for Attack Graph --> A
          ```

    4. **Frontend Rendering (Conceptual):**
        - Based on the description, the frontend is built with Vue.js. If Vue.js templates are used to render data from Neo4j without proper output encoding (e.g., using `v-html` without sanitization or not using `{{ }}` for escaping), the stored XSS vulnerability will be exploitable.

- **Security Test Case:**
    1. **Prepare Malicious JSON Payload (e.g., `malicious.json`):**
        ```json
        [
          {
            "resource": "users",
            "value": [
              {
                "objectId": "user-xss-id",
                "displayName": "<img src=x onerror=alert('XSS-Stormspotter')>",
                "mail": "test@example.com"
              }
            ]
          }
        ]
        ```

    2. **Prepare `malicious.zip`:**
        - Create a zip archive containing `malicious.json` (e.g., `malicious.zip`).

    3. **Upload `malicious.zip` to Stormspotter Backend:**
        - Use `curl` or a similar tool to upload `malicious.zip` to the `/api/upload` endpoint. Replace `[STORMSPOTTER_URL]` with the actual URL of the Stormspotter instance. Replace `neo4j` and `password` with actual Neo4j credentials if changed.
        ```bash
        curl -X POST \
          -H "Content-Type: multipart/form-data" \
          -H "x-neo4j-user: neo4j" \
          -H "x-neo4j-pass: password" \
          -F "upload=@malicious.zip" \
          "[STORMSPOTTER_URL]/api/upload"
        ```

    4. **Access Stormspotter Frontend:**
        - Open a web browser and navigate to the Stormspotter frontend URL (e.g., `http://localhost:9091`).
        - Log in to the Stormspotter UI.

    5. **View Attack Graph and Trigger XSS:**
        - Navigate to the "Database View" or the section where user data (or generic Azure resource data) is displayed in the attack graph.
        - Look for the injected user object (or resource) with `objectId: user-xss-id`.
        - If the frontend is vulnerable, an alert box with "XSS-Stormspotter" should pop up when the malicious `displayName` is rendered in the UI, demonstrating successful XSS execution.

---

### 2. Cypher Injection via Malicious Stormcollector Output File

- **Description:**
    1. An attacker crafts a malicious Stormcollector output file (zip archive containing SQLite database files) where the JSON data embedded within the SQLite database contains specially crafted string values.
    2. A user with access to the Stormspotter frontend uploads this malicious file to the Stormspotter backend through the frontend's upload functionality or directly to the `/api/upload` endpoint.
    3. The backend receives the file, extracts the zip archive (if it is a zip file), and processes the SQLite database files within.
    4. The `SSProcessor` in the backend parses the data from the SQLite database, row by row, converting the JSON strings back into Python dictionaries.
    5. During the parsing process, the `SSProcessor` calls the `Neo4j` class to insert nodes and relationships into the Neo4j database.
    6. The `Neo4j` class uses the `sanitize_string` function to attempt sanitization of string values before constructing Cypher queries. However, this sanitization is insufficient to prevent Cypher injection.
    7. A malicious string value within the uploaded JSON data can bypass the inadequate sanitization and inject arbitrary Cypher code into the queries executed by the `Neo4j` class against the Neo4j database.
    8. This successful Cypher injection can lead to unauthorized actions such as data manipulation, deletion, or extraction from the Neo4j database, potentially compromising the integrity and confidentiality of the attack graph data and the Stormspotter application itself.

- **Impact:**
    An attacker can execute arbitrary Cypher queries against the Neo4j database. This can lead to:
        - **Data Breach:** Extraction of sensitive information from the attack graph.
        - **Data Manipulation:** Modification or deletion of nodes and relationships in the attack graph, leading to incorrect visualizations and analysis within Stormspotter.
        - **Service Disruption:** Potential corruption of the database or denial of service if malicious Cypher queries cause errors or resource exhaustion.
        - **Potential for further exploitation:** Depending on Neo4j configurations and permissions, successful Cypher injection could potentially be leveraged for more significant system compromise.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - The project includes a `sanitize_string` function in `/code/backend/backend/db.py`.
    - This function is used in `Neo4j.generate_set_statement` to sanitize string inputs before they are used in Cypher queries within `Neo4j.insert_asset` and `Neo4j.create_relationship`.
    - The `sanitize_string` function performs basic sanitization by replacing backslashes (`\`) with double backslashes (`\\`) and single quotes (`'`) with empty strings.

- **Missing Mitigations:**
    - **Insufficient Sanitization:** The current `sanitize_string` function is not robust enough to prevent Cypher injection. Removing single quotes and escaping backslashes is a basic attempt, but it may not cover all injection vectors or bypass more sophisticated injection techniques. More comprehensive input sanitization or parameterized queries should be used.
    - **Lack of Parameterized Queries:** The code uses string formatting to construct Cypher queries in `backend/backend/db.py`. This is inherently vulnerable to injection attacks. Parameterized queries should be implemented to separate data from the Cypher query structure, preventing malicious data from being interpreted as code.
    - **Input Validation:** The backend should implement more rigorous input validation on the uploaded Stormcollector output files. This includes:
        - **File Format Validation:** Strictly enforce the expected file format (SQLite databases within ZIP archives) and reject any files that do not conform. While JSON conversion is mentioned in README for other purposes, Stormspotter parser should strictly parse SQLite format.
        - **Data Schema Validation:** Validate the schema and data types within the SQLite databases to ensure they match the expected Stormcollector output format. Reject files with unexpected schemas or data types.
        - **Content Sanitization:** Even with format and schema validation, further sanitization of string content is necessary to prevent injection.  A more robust sanitization function should be implemented or ideally, parameterized queries should be used.

- **Preconditions:**
    1. The attacker must be able to craft a valid Stormcollector output file (zip archive with SQLite database files) containing malicious JSON payloads.
    2. A user with valid access to the Stormspotter frontend must upload this crafted file through the "Stormcollector Upload" functionality in the Database View tab or directly to the `/api/upload` endpoint.
    3. The Stormspotter backend must be running and correctly configured to connect to a Neo4j database instance.

- **Source Code Analysis:**
    - `/code/backend/backend/db.py`:
        - `sanitize_string(self, input_str)`: This function attempts to sanitize string inputs by replacing backslashes and single quotes.
        - `generate_set_statement(self, asset, extra_labels=None)`: This method generates the `SET` clause for Cypher queries. It calls `sanitize_string` on each value in the `asset` dictionary.
        - `insert_asset(self, asset, label, asset_id, extra_labels=None)`: This method constructs a Cypher `MERGE` query using `base_import_cypher` and the `set_statement` generated by `generate_set_statement`. The `asset_id` and `label` are directly formatted into the query string without sanitization beyond lowercasing the `asset_id`.
        - `create_relationship(self, from_id, from_label, to_id, to_label, relationship_type, ...)`: This method constructs a Cypher `MERGE` query using `base_merge_cypher`.  `from_id`, `from_label`, `to_id`, `to_label`, and `relationship_type` are directly formatted into the query string without sufficient sanitization.
        - `query(self, statement, requested=False)`: This function executes the raw Cypher query statement against the Neo4j database.
    - `/code/backend/backend/parser.py`:
        - `SSProcessor.process(self, upload: SpooledTemporaryFile, filename: str, neo_user: str, neo_pass: str)`: This method handles the uploaded file. It checks for zip files, extracts them, and processes SQLite files using `process_sqlite`.
        - `SSProcessor.process_sqlite(self, sql_file: Path)`: This method reads results from the SQLite database and processes each row using `_process_json`.
        - `SSProcessor._process_json(self, json)`: This method parses JSON data and calls specific parsing methods based on the `objectType` or `type` field in the JSON. These parsing methods then call `Neo4j.insert_asset` and `Neo4j.create_relationship` to insert data into the Neo4j database.
        - Parsing methods (`_parseAADUser`, `_parseDisk`, etc.): These methods extract data from the parsed JSON and pass it to the `Neo4j` class for database insertion. They do not perform robust input validation or sanitization beyond the limited `_parseProperty` function, which focuses on data type handling rather than security sanitization.

- **Security Test Case:**
    1. Prepare a malicious Stormcollector output file. This involves:
        a. Create a directory structure mimicking a Stormcollector output zip, including an SQLite database file (e.g., `results_test/tenant.sqlite`).
        b. Inside the SQLite database, create a `results` table with a `result` column of type JSON.
        c. Insert a malicious JSON payload into the `results` table. This JSON payload should contain a crafted string value within a field that will be used in a Cypher query. For example, create a JSON for a Tenant object and set the `display_name` to: `"malicious_name') DETACH DELETE n --"`. The goal is to inject Cypher code that will be executed when this data is processed.
        d. Zip the `results_test` directory to create `malicious_upload.zip`.
    2. Start the Stormspotter application, including the frontend and backend, and ensure they are connected to a Neo4j database.
    3. Access the Stormspotter frontend through a web browser and log in.
    4. Navigate to the "Database View" tab, find the "Stormcollector Upload" section, and use the file uploader to upload the `malicious_upload.zip` file.
    5. After uploading, monitor the Stormspotter backend logs for any errors or unusual activity. Also, monitor the Neo4j database logs if possible.
    6. Examine the Neo4j database content using the Neo4j browser or Cypher queries to check for the impact of the injected code. For example, if the injected code was intended to delete all nodes (`DETACH DELETE n`), verify if the database is now empty or contains unexpected changes.
    7. If the Cypher injection is successful, you should observe the intended malicious behavior in the Neo4j database (e.g., data deletion, modification, or errors indicating Cypher parsing issues due to injection). If nodes are deleted or modified unexpectedly, or if Neo4j logs show errors related to unexpected Cypher syntax, the vulnerability is confirmed.