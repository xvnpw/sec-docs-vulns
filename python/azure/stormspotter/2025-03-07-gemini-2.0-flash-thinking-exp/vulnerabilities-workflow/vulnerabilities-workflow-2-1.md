- Vulnerability Name: Stored Cross-Site Scripting (XSS) via Backend API Data Injection

- Description:
  1. An attacker crafts a malicious JSON payload containing JavaScript code.
  2. The attacker uploads this malicious JSON file to the Stormspotter backend through the `/api/upload` endpoint.
  3. The backend processes the uploaded file and stores the malicious payload into the Neo4j database without proper sanitization.
  4. When a user accesses the Stormspotter frontend and views the attack graph, the frontend fetches data from the Neo4j database.
  5. The frontend renders the malicious payload from the database in the user's browser without proper output encoding or sanitization.
  6. The attacker's JavaScript code is executed in the user's browser, potentially leading to session hijacking, data theft, or other malicious actions.

- Impact:
  - Successful exploitation of this vulnerability allows an attacker to execute arbitrary JavaScript code in the context of a Stormspotter user's browser.
  - This can lead to:
    - **Account Compromise:** An attacker could steal session cookies or local storage tokens, gaining unauthorized access to the user's Stormspotter account and potentially the Azure environment visualized within Stormspotter if the user has saved Azure credentials in the browser.
    - **Data Theft:**  An attacker could steal sensitive information displayed in the Stormspotter UI, such as Azure resource configurations, relationships, and potentially credentials if exposed in the graph.
    - **Redirection to Malicious Sites:** The attacker could redirect the user to a malicious website, potentially leading to further phishing or malware attacks.
    - **Defacement:** The attacker could modify the displayed attack graph or UI elements, causing confusion or misinformation.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
  - **Partial Input Sanitization in Backend:** The `backend/backend/db.py` file contains a `sanitize_string` function.
    ```python
    def sanitize_string(self, input_str):
        """ clean objects that come in as type string """
        if input_str:
            return input_str.replace("\\", "\\\\").replace("'", "")
        return input_str
    ```
    This function is used in `generate_set_statement` to sanitize string inputs before constructing Cypher queries. However, this sanitization is insufficient to prevent XSS as it only escapes backslashes and single quotes, and does not perform HTML entity encoding or any other XSS-specific sanitization. This mitigation is located in `backend/backend/db.py`.

- Missing Mitigations:
  - **Backend Input Sanitization:** Implement proper input sanitization in the backend before storing data in the Neo4j database. This should include HTML entity encoding or using a robust HTML sanitization library to neutralize potentially malicious HTML or JavaScript code within user-provided data. Sanitize data in `backend/backend/parser.py` before calling `neo.insert_asset`.
  - **Frontend Output Encoding:** Implement output encoding in the frontend when displaying data fetched from the Neo4j database. This will ensure that any potentially malicious code stored in the database is rendered as plain text in the browser, preventing execution. This should be implemented in the Vue.js frontend components responsible for displaying graph data.

- Preconditions:
  - The attacker needs to be able to upload a JSON file to the Stormspotter backend via the `/api/upload` endpoint.
  - The Stormspotter frontend must render data from the Neo4j database without proper output encoding.
  - A user must access the frontend and view the attack graph containing the attacker's injected malicious data.

- Source Code Analysis:
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

- Security Test Case:
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

This vulnerability allows for stored XSS due to insufficient sanitization in the backend and potentially missing output encoding in the frontend. Addressing both backend sanitization and frontend output encoding is crucial to mitigate this risk effectively.