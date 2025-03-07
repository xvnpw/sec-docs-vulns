- Vulnerability Name: Malicious SQL Injection via Config File

- Description:
    1. An attacker crafts a malicious `config.yml` file. This file specifies query titles that correspond to malicious SQL files created by the attacker and placed in the designated `queries_folder`.
    2. The attacker tricks a victim into using this malicious `config.yml` file with the `adm` tool. This could be achieved through social engineering, phishing, or by compromising a system where the victim stores their configuration files.
    3. The victim executes the `adm` tool, providing the path to the attacker's malicious `config.yml` file using the `-c` option.
    4. The `adm` tool parses the `config.yml` file and, based on the `queries_setup` section, identifies the query titles to be deployed or run.
    5. For each query title, the tool retrieves the corresponding SQL query from the files within the `queries_folder`. The tool uses the query title to locate the SQL file (e.g., `query_title.sql`).
    6. The tool reads the content of these SQL files without any sanitization or validation.
    7. If the command is `deploy` or `run`, the tool sends the unsanitized SQL query content to the Ads Data Hub API to deploy or execute.
    8. As the attacker controls the content of the SQL files, they can inject arbitrary SQL commands. These commands are then executed within the victim's Ads Data Hub environment.

- Impact:
    - **Unauthorized Data Access:** The attacker can execute SQL queries to access sensitive data within the victim's Ads Data Hub environment that they are not authorized to view. This could include customer data, advertising performance metrics, and other proprietary information.
    - **Data Manipulation:** The attacker can modify or delete data within the victim's Ads Data Hub environment. This could lead to data corruption, inaccurate reporting, and business disruption.
    - **Privilege Escalation:** In some scenarios, depending on the Ads Data Hub setup and permissions, the attacker might be able to leverage SQL injection to gain higher privileges or access resources beyond the intended scope of the tool.
    - **Reputation Damage:** If the vulnerability is exploited, it can lead to a breach of data and trust, causing significant reputational damage to the victim's organization.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - None. The code directly reads and uses SQL query files without any validation or sanitization of their content.

- Missing Mitigations:
    - **Input Validation and Sanitization:** The most critical missing mitigation is input validation and sanitization of the SQL queries read from files. Before deploying or running any query, the tool should:
        - Parse the SQL query to identify its structure and components.
        - Validate that the query conforms to an expected safe pattern or a whitelist of allowed SQL operations.
        - Sanitize the query to remove or escape any potentially malicious SQL code injected by an attacker.
    - **Principle of Least Privilege:** While not a direct code mitigation, adhering to the principle of least privilege for the service account used by the `adm` tool can limit the potential impact of a successful SQL injection attack. The service account should only have the necessary permissions required for deploying and running legitimate queries, and not broader administrative access.
    - **User Education and Documentation:**  Documentation should explicitly warn users about the risks of using configuration files and SQL query files from untrusted sources. Users should be advised to only use files from trusted origins and to carefully review the content of `config.yml` and SQL files before using the `adm` tool.

- Preconditions:
    1. **Attacker-Controlled `config.yml`:** The attacker must be able to provide or trick the victim into using a malicious `config.yml` file. This could involve:
        - Social engineering to convince the victim to download and use a malicious config file.
        - Compromising a system or storage location where the victim keeps their configuration files and replacing a legitimate `config.yml` with a malicious one.
    2. **Attacker-Controlled SQL Files:** The malicious `config.yml` must reference query titles for which the attacker has created malicious SQL files within the designated `queries_folder` (or the folder specified via `-q` option).
    3. **Victim Executes `adm` Tool:** The victim must execute the `adm` tool using the `-c` option and providing the path to the malicious `config.yml` file.
    4. **ADH API Access:** The victim must have properly configured the `adm` tool with credentials and developer key to access the Ads Data Hub API.

- Source Code Analysis:
    1. **`adh_deployment_manager/cli/adm.py`**:
        - The `main` function in `adm.py` parses command-line arguments, including `-c` for the config path and `-q` for the queries path.
        - It initializes a `Deployment` object using the provided config path, queries path, credentials, and developer key.
        - It then creates a `CommandsFactory` and executes commands based on user input.
        ```python
        config = os.path.join(os.getcwd(), args.config_path)
        deployment = Deployment(config=config,
                                developer_key=DEVELOPER_KEY,
                                credentials=credentials,
                                queries_folder=os.path.join(os.getcwd(),
                                                            args.queries_path))
        ```
    2. **`adh_deployment_manager/deployment.py`**:
        - The `Deployment` class initializes a `Config` object to parse the `config.yml` file.
        - The `_get_queries` method is responsible for retrieving `AdhQuery` objects.
        - Inside `_get_queries`, if `is_buildable` is True, it reads SQL file content using `get_file_content`.
        ```python
        def _get_queries(self, is_buildable=False):
            for query in self.config.queries:
                query_for_run = self.config.queries[query]
                if is_buildable:
                    adh_query = AdhQuery(
                        query,
                        get_file_content(
                            f"{self.queries_folder}/{query}{self.query_file_extention}"
                        ), # <--- SQL content is read here without sanitization
                        query_for_run.get("parameters"),
                        query_for_run.get("filtered_row_summary"))
                else:
                    adh_query = AdhQuery(query)
                # ...
        ```
    3. **`adh_deployment_manager/utils.py`**:
        - The `get_file_content` function simply reads the content of the file specified by `relative_path` without any processing or sanitization.
        ```python
        def get_file_content(relative_path: str, working_directory: str = None) -> str:
            # ...
            with open(os.path.join(working_directory, relative_path),
                      "r") as sql_query: # <--- Opens and reads the SQL file
                query_lines = sql_query.readlines()
                query_txt = "".join(line for line in query_lines
                                    if not line.startswith("#"))
                return query_txt.strip() # <--- Returns the raw SQL content
        ```
    4. **`adh_deployment_manager/commands/deploy.py` and `adh_deployment_manager/commands/run.py`**:
        - The `Deployer.execute` and `Runner.execute` methods call `self.deployment._get_queries(is_buildable=True)` to get query information.
        - They then use `analysis_query.deploy()` or `analysis_query._run()` to deploy or run the queries.
    5. **`adh_deployment_manager/query.py`**:
        - The `AnalysisQuery` class's `deploy` and `_run` methods send the `queryText` (which is the unsanitized content from the SQL file) to the ADH API.
        ```python
        class AnalysisQuery(AdhQuery):
            # ...
            def _create(self):
                # ...
                query_body_create = {
                    "title": self.title,
                    "queryText": self.text, # <--- Unsanitized SQL text is used here
                }
                # ...
                return (self.adh_service.customers().analysisQueries().create(
                    parent=self.customer_id, body=self.query_body_create))

            def _run(self,
                     start_date,
                     end_date,
                     output_table_name,
                     parameters=None,
                     **kwargs):
                # ...
                queryExecuteBody: Dict[str, Any] = {
                    "spec": {
                        "adsDataCustomerId": self.ads_data_from,
                        "startDate": utils.get_date(start_date),
                        "endDate": utils.get_date(end_date)
                    },
                    "destTable": output_table_name
                }
                queryExecuteBody["spec"]["parameterValues"] = \
                    Parameters.prepare_parameters(parameters, **kwargs)

                op = (self.adh_service.customers().analysisQueries().start(
                    name=self.name, body=queryExecuteBody)) # <--- Unsanitized SQL text is executed by ADH API
                return op
        ```
    **Visualization:**

    ```mermaid
    graph LR
        A[adm.py (CLI Input: config_path, queries_path)] --> B(Deployment Object Creation);
        B --> C[Config.py (Parse config.yml)];
        B --> D[Deployment._get_queries(is_buildable=True)];
        D --> E[utils.get_file_content (Read SQL file)];
        E --> F[AdhQuery Object (Unsanitized SQL Text)];
        F --> G[AnalysisQuery Object];
        G -- deploy() / run() --> H[ADH API (Malicious SQL Execution)];
    ```

- Security Test Case:
    1. **Setup:**
        - Create a directory named `malicious_project`.
        - Inside `malicious_project`, create a directory named `sql`.
        - Inside `malicious_project`, create a file named `config.yml`.
        - Inside `malicious_project/sql`, create a file named `malicious_query.sql`.
        - Ensure you have the `adm` tool installed and configured with valid ADH credentials and developer key (for a test ADH environment if possible).

    2. **Malicious SQL Query (`malicious_project/sql/malicious_query.sql`):**
        ```sql
        -- Malicious SQL query to exfiltrate data (example - replace with actual malicious intent)
        SELECT
          'ATTACK_DETECTED',
          user_id, -- Example: Exfiltrate user IDs
          COUNT(*)
        FROM
          adh.google_ads_impressions -- Example: Target a specific table
        GROUP BY 1, 2
        ```
        *Note:* Replace the example SQL with queries that demonstrate actual data exfiltration, manipulation, or other malicious actions you want to test within the constraints of your test ADH environment and ethical boundaries. Be extremely cautious and ensure you are only testing in a safe, isolated environment and have proper authorization.*

    3. **Malicious `config.yml` (`malicious_project/config.yml`):**
        ```yaml
        customer_ids:
          - <YOUR_ADH_CUSTOMER_ID> # Replace with your ADH customer ID
        bq_project: <YOUR_BQ_PROJECT> # Replace with your BQ project
        bq_dataset: <YOUR_BQ_DATASET> # Replace with your BQ dataset
        queries_setup:
          - queries:
              - malicious_query # Query title matching the malicious SQL file name
        ```
        *Replace placeholders like `<YOUR_ADH_CUSTOMER_ID>`, `<YOUR_BQ_PROJECT>`, and `<YOUR_BQ_DATASET>` with your actual test environment details.*

    4. **Execution:**
        - Open a terminal and navigate to the `malicious_project` directory.
        - Set the `ADH_DEVELOPER_KEY` and `ADH_SECRET_FILE` environment variables to your test ADH API credentials.
        - Execute the `adm` tool to deploy the malicious query:
          ```bash
          adm -c config.yml -q sql deploy
          ```
        - Or, execute the `adm` tool to run the malicious query directly (if applicable and properly configured in `config.yml` with `date_range_setup`):
          ```bash
          adm -c config.yml -q sql run
          ```

    5. **Verification:**
        - **Check ADH UI:** Log in to your Ads Data Hub UI and verify if the query named "malicious_query" (or the title specified in your `config.yml`) has been deployed. Inspect the query text to confirm it contains the malicious SQL code you injected.
        - **Check BQ Output (if query was run):** If you ran the query, check your specified BigQuery dataset for a table named "malicious_query" (or as configured). Examine the table data to see if the malicious SQL actions were executed (e.g., if data was exfiltrated as intended by your malicious query - in the example, check for rows with 'ATTACK_DETECTED').
        - **ADH API Logs:** Examine the Ads Data Hub API logs (if available in your test environment) for any signs of unusual or unauthorized query executions originating from the `adm` tool.

    6. **Expected Result:**
        - The malicious query, as defined in `malicious_query.sql`, should be successfully deployed to your Ads Data Hub project.
        - If you ran the query, the malicious SQL code should be executed within your ADH environment, potentially leading to the actions defined in your malicious query (data exfiltration, manipulation, etc. - depending on your specific malicious SQL payload and ADH permissions).
        - This confirms that the `adm` tool is vulnerable to SQL injection via malicious configuration and SQL files because it processes and executes attacker-controlled SQL code without proper sanitization.

This vulnerability allows a remote attacker to execute arbitrary SQL queries within the victim's Ads Data Hub environment by tricking them into using a malicious configuration file. It is a critical vulnerability due to the potential for significant data breaches and manipulation.