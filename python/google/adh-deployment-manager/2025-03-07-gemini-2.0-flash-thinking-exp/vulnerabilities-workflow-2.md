### Vulnerability List:

* Vulnerability Name: Configuration Manipulation for Data Exfiltration (BigQuery Project and Dataset)
* Description:
    An attacker with write access to the `config.yml` file can modify the `bq_project` and `bq_dataset` parameters. These parameters define the BigQuery project and dataset where the query results from Ads Data Hub will be stored. By changing these values, an attacker can redirect the output of ADH queries to a BigQuery project and dataset under their control. This allows the attacker to exfiltrate potentially sensitive data from the organization's ADH environment to an external location.

    Steps to trigger the vulnerability:
    1. An attacker gains unauthorized write access to the `config.yml` file. This could be achieved through various methods such as exploiting system vulnerabilities, social engineering, or insider access.
    2. The attacker modifies the `config.yml` file.
    3. Within the `config.yml`, the attacker changes the values of `bq_project` and `bq_dataset` to point to a BigQuery project and dataset under their control.
    4. The victim user executes the `adm` tool (e.g., using `adm run` or `adm deploy`) with the manipulated `config.yml` file.
    5. The `adh-deployment-manager` library reads the configuration from the modified `config.yml` file, including the attacker-controlled `bq_project` and `bq_dataset`.
    6. When the queries are executed, the results are written to the BigQuery project and dataset specified in the manipulated configuration, which is controlled by the attacker.
    7. The attacker can then access and exfiltrate the sensitive data from their BigQuery project.

* Impact:
    - Data Exfiltration: Sensitive data processed by ADH queries is written to an attacker-controlled BigQuery project, allowing the attacker to access and steal this data.
    - Data Exposure:  Data intended to be stored within the organization's controlled BigQuery environment can be exposed to external parties if the attacker-controlled project is outside the organization's security perimeter.
    - Unauthorized Access to Data (Indirect): While not direct access to ADH data, this allows attackers to gain access to the *results* of ADH queries, which can still contain sensitive information.
    - Compliance Violations: Exfiltration of user data can lead to serious violations of data privacy regulations and compliance standards.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - None: The provided code does not implement any specific mitigations against configuration manipulation. The documentation mentions access setup and authentication to ADH API, but no input validation or access control for the `config.yml` file is present in the code.

* Missing Mitigations:
    - Input Validation and Sanitization: Implement validation in the `Config` class (`adh_deployment_manager/config.py`) to check if `bq_project` and `bq_dataset` values conform to expected formats (e.g., project ID and dataset ID patterns).
    - Project/Dataset Whitelisting: Ideally, the application should only allow writing to a predefined list of authorized BigQuery projects and datasets. This list could be hardcoded or configured in a more secure manner, separate from the user-editable `config.yml`.
    - Access Control for `config.yml`: Implement operating system level access controls to restrict write access to the `config.yml` file only to authorized users or processes. This is an operational security measure but crucial to prevent unauthorized modification.
    - Configuration Change Monitoring and Logging: Implement logging of any changes made to the `config.yml` file. Monitoring these logs for unexpected modifications can help detect and respond to potential attacks.
    - Configuration Integrity Checks: Consider implementing mechanisms to verify the integrity of the `config.yml` file, such as using checksums or digital signatures, to detect unauthorized modifications.
    - Auditing: Log the BigQuery project and dataset being used for each execution to facilitate auditing and detection of suspicious activity.
    - Principle of Least Privilege (for Service Account): Ensure the service account used by the deployment manager has write access only to the intended BigQuery project and dataset, limiting the impact if the configuration is manipulated. However, this doesn't prevent exfiltration if the attacker *can* control a valid project.

* Preconditions:
    - Attacker Write Access to `config.yml`: The attacker must have write permissions to the `config.yml` file on the system where `adh-deployment-manager` is deployed.
    - Execution of `adm` Tool: A legitimate user must execute the `adm` tool (or use the library programmatically) after the `config.yml` file has been maliciously modified.
    - Attacker BigQuery Project: The attacker needs to have a BigQuery project and dataset under their control where they can receive the exfiltrated data.
    - Service Account Permissions: The service account used by the deployment manager must have permissions to write data to *both* the legitimate BigQuery dataset *and* the attacker's specified BigQuery dataset.

* Source Code Analysis:
    1. **`adh_deployment_manager/config.py` - Config class:**
        - The `Config` class is responsible for parsing the `config.yml` file.
        - In the `__init__` method, the `bq_project` and `bq_dataset` attributes are directly populated from the configuration file using `self.config.get("bq_project")` and `self.config.get("bq_dataset")`.
        - **Vulnerable Code Snippet:**
          ```python
          class Config:
              def __init__(self, path, working_directory=None):
                  # ...
                  self.bq_project = self.config.get("bq_project")
                  self.bq_dataset = self.config.get("bq_dataset")
                  # ...
          ```
        - **No Input Validation:** There is no input validation or sanitization performed on the values retrieved for `bq_project` and `bq_dataset`. The code directly trusts the values provided in the `config.yml` file.
    2. **`adh_deployment_manager/commands/run.py` - Runner.execute method:**
        - The `Runner.execute` method uses the `bq_project` and `bq_dataset` attributes from the `Config` object to construct the destination table path for the BigQuery output.
        - **Vulnerable Code Snippet:**
          ```python
          class Runner(AbsCommand):
              # ...
              def execute(self, deploy=False, update=False, **kwargs):
                  # ...
                  if not self.config.bq_project or not self.config.bq_dataset:
                      # ...
                  # ...
                  job = analysis_query._run(
                      query_for_run.get("start_date"),
                      query_for_run.get("end_date"),
                      f"{self.config.bq_project}.{self.config.bq_dataset}.{table_name}", # VULNERABLE LINE
                      query_for_run.get("parameters"), **kwargs)
                  # ...
          ```
        - **Direct Use of Configuration Values:** The code directly embeds `self.config.bq_project` and `self.config.bq_dataset` into the BigQuery destination table path without any checks to ensure they are valid or safe. This allows an attacker to control where the query results are written by manipulating the `config.yml` file.

    - **Visualization:**

    ```mermaid
    graph LR
        subgraph Configuration Loading
            ConfigYML[/config.yml/] --> ConfigClass(Config Class in config.py)
            ConfigClass -- Reads bq_project, bq_dataset --> RunnerClass(Runner Class in commands/run.py)
        end

        subgraph Query Execution
            RunnerClass -- Constructs BQ output path --> AnalysisQueryClass(AnalysisQuery Class in query.py)
            AnalysisQueryClass -- Uses BQ output path in API calls --> ADH_API[(Ads Data Hub API)]
            ADH_API -- Writes query results to --> AttackerBQ[(Attacker's BigQuery Project/Dataset)]
        end

        style ConfigYML fill:#f9f,stroke:#333,stroke-width:2px
        style ADH_API fill:#ccf,stroke:#333,stroke-width:2px
        style AttackerBQ fill:#faa,stroke:#333,stroke-width:2px
        LinkStyle 0,1,2,3,4 stroke:#f66,stroke-width:2px,color:#f00;
    ```

* Security Test Case:
    1. **Setup:**
        - Deploy `adh-deployment-manager` in a test environment where you can modify the `config.yml` file.
        - Have a legitimate Google Cloud Project and BigQuery dataset where the tool is intended to write data (let's call it `legitimate-project:legitimate-dataset`).
        - Create a separate Google Cloud Project and BigQuery dataset under your control to simulate the attacker's environment (let's call it `attacker-project:attacker-dataset`). Ensure you have credentials to access `attacker-project:attacker-dataset`.
        - Configure `adh-deployment-manager` to use `legitimate-project:legitimate-dataset` in the original `config.yml`.
    2. **Malicious Configuration Modification:**
        - As an attacker, gain access to the `config.yml` file in the deployed environment.
        - Modify the `config.yml` file by changing the `bq_project` and `bq_dataset` values to your attacker-controlled project and dataset:
          ```yaml
          # ... other configurations ...
          bq_project: attacker-project
          bq_dataset: attacker-dataset
          # ... other configurations ...
          ```
        - Save the modified `config.yml` file.
    3. **Execute `adm run` command:**
        - As a legitimate user (or trigger the tool through its intended workflow), execute the `adm run` command (or any command that triggers query execution and data writing) using the modified `config.yml`:
          ```bash
          adm -c path/to/modified/config.yml run
          ```
    4. **Verify Data Exfiltration:**
        - After the `adm run` command completes successfully, check the BigQuery dataset in your attacker-controlled project (`attacker-project:attacker-dataset`).
        - Verify that the output tables generated by `adh-deployment-manager` and the corresponding query results are present in `attacker-project:attacker-dataset`, instead of the intended `legitimate-project:legitimate-dataset`.
    5. **Confirmation of Vulnerability:**
        - If the output tables and data are found in `attacker-project:attacker-dataset`, it confirms that the configuration manipulation vulnerability is exploitable, and an attacker can successfully redirect data output to their controlled environment.

---

* Vulnerability Name: Malicious SQL Injection via Config File
* Description:
    An attacker crafts a malicious `config.yml` file. This file specifies query titles that correspond to malicious SQL files created by the attacker and placed in the designated `queries_folder`. The attacker tricks a victim into using this malicious `config.yml` file with the `adm` tool. When the victim executes the `adm` tool, providing the path to the attacker's malicious `config.yml` file, the tool parses the `config.yml` file and retrieves the corresponding SQL queries from the files within the `queries_folder`. The tool reads the content of these SQL files without any sanitization or validation. If the command is `deploy` or `run`, the tool sends the unsanitized SQL query content to the Ads Data Hub API to deploy or execute. As the attacker controls the content of the SQL files, they can inject arbitrary SQL commands, which are then executed within the victim's Ads Data Hub environment.

* Impact:
    - **Unauthorized Data Access:** The attacker can execute SQL queries to access sensitive data within the victim's Ads Data Hub environment that they are not authorized to view. This could include customer data, advertising performance metrics, and other proprietary information.
    - **Data Manipulation:** The attacker can modify or delete data within the victim's Ads Data Hub environment. This could lead to data corruption, inaccurate reporting, and business disruption.
    - **Privilege Escalation:** In some scenarios, depending on the Ads Data Hub setup and permissions, the attacker might be able to leverage SQL injection to gain higher privileges or access resources beyond the intended scope of the tool.
    - **Reputation Damage:** If the vulnerability is exploited, it can lead to a breach of data and trust, causing significant reputational damage to the victim's organization.

* Vulnerability Rank: Critical

* Currently Implemented Mitigations:
    - None. The code directly reads and uses SQL query files without any validation or sanitization of their content.

* Missing Mitigations:
    - **Input Validation and Sanitization:** The most critical missing mitigation is input validation and sanitization of the SQL queries read from files. Before deploying or running any query, the tool should:
        - Parse the SQL query to identify its structure and components.
        - Validate that the query conforms to an expected safe pattern or a whitelist of allowed SQL operations.
        - Sanitize the query to remove or escape any potentially malicious SQL code injected by an attacker.
    - **Principle of Least Privilege:** While not a direct code mitigation, adhering to the principle of least privilege for the service account used by the `adm` tool can limit the potential impact of a successful SQL injection attack. The service account should only have the necessary permissions required for deploying and running legitimate queries, and not broader administrative access.
    - **User Education and Documentation:**  Documentation should explicitly warn users about the risks of using configuration files and SQL query files from untrusted sources. Users should be advised to only use files from trusted origins and to carefully review the content of `config.yml` and SQL files before using the `adm` tool.

* Preconditions:
    1. **Attacker-Controlled `config.yml`:** The attacker must be able to provide or trick the victim into using a malicious `config.yml` file.
    2. **Attacker-Controlled SQL Files:** The malicious `config.yml` must reference query titles for which the attacker has created malicious SQL files within the designated `queries_folder` (or the folder specified via `-q` option).
    3. **Victim Executes `adm` Tool:** The victim must execute the `adm` tool using the `-c` option and providing the path to the malicious `config.yml` file.
    4. **ADH API Access:** The victim must have properly configured the `adm` tool with credentials and developer key to access the Ads Data Hub API.

* Source Code Analysis:
    1. **`adh_deployment_manager/cli/adm.py`**:
        - The `main` function in `adm.py` parses command-line arguments, including `-c` for the config path and `-q` for the queries path and initializes a `Deployment` object.
    2. **`adh_deployment_manager/deployment.py`**:
        - The `Deployment` class initializes a `Config` object and the `_get_queries` method retrieves `AdhQuery` objects.
        - Inside `_get_queries`, if `is_buildable` is True, it reads SQL file content using `get_file_content`.
    3. **`adh_deployment_manager/utils.py`**:
        - The `get_file_content` function simply reads the content of the file specified by `relative_path` without any processing or sanitization.
    4. **`adh_deployment_manager/commands/deploy.py` and `adh_deployment_manager/commands/run.py`**:
        - The `Deployer.execute` and `Runner.execute` methods call `self.deployment._get_queries(is_buildable=True)` to get query information and then use `analysis_query.deploy()` or `analysis_query._run()` to deploy or run the queries.
    5. **`adh_deployment_manager/query.py`**:
        - The `AnalysisQuery` class's `deploy` and `_run` methods send the `queryText` (which is the unsanitized content from the SQL file) to the ADH API.

    - **Visualization:**

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

* Security Test Case:
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
    4. **Execution:**
        - Open a terminal and navigate to the `malicious_project` directory.
        - Set the `ADH_DEVELOPER_KEY` and `ADH_SECRET_FILE` environment variables to your test ADH API credentials.
        - Execute the `adm` tool to deploy the malicious query:
          ```bash
          adm -c config.yml -q sql deploy
          ```
    5. **Verification:**
        - **Check ADH UI:** Log in to your Ads Data Hub UI and verify if the query named "malicious_query" (or the title specified in your `config.yml`) has been deployed. Inspect the query text to confirm it contains the malicious SQL code you injected.
        - **Check BQ Output (if query was run):** If you ran the query, check your specified BigQuery dataset for a table named "malicious_query" (or as configured). Examine the table data to see if the malicious SQL actions were executed.
        - **ADH API Logs:** Examine the Ads Data Hub API logs (if available in your test environment) for any signs of unusual or unauthorized query executions originating from the `adm` tool.
    6. **Expected Result:**
        - The malicious query should be successfully deployed and potentially executed, confirming the SQL injection vulnerability.

---

* Vulnerability Name: Configuration Injection - Customer IDs and Ads Data From Manipulation
* Description:
    An attacker who gains write access to the `config.yml` file can modify the `customer_ids` and `ads_data_from` parameters. These parameters are used to specify the Google Ads Data Hub (ADH) customer IDs for which queries are deployed and from which ads data is accessed. By altering these values, an attacker can potentially gain unauthorized access to data belonging to different ADH customers or manipulate queries to run against unintended customer data.

    Steps to trigger the vulnerability:
    1. An attacker gains unauthorized write access to the `config.yml` file within the deployment project.
    2. The attacker modifies the `customer_ids` list or the `ads_data_from` list in the `config.yml` file to include ADH customer IDs that they are not authorized to access.
    3. The attacker executes any command that utilizes the configuration file, such as `adm run` or `adm deploy`.
    4. The application, using the modified `config.yml`, will then use the attacker-specified customer IDs in subsequent API calls to ADH.
    5. If the attacker's account has sufficient permissions within the Ads Data Hub project associated with the modified customer IDs (or if there are misconfigurations in ADH permissions), the attacker may successfully deploy or run queries against these unauthorized customer IDs, potentially exfiltrating or manipulating sensitive data.

* Impact:
    - **Unauthorized Data Access:** An attacker could gain access to sensitive data from Google Ads Data Hub belonging to customer IDs that they are not authorized to access.
    - **Data Manipulation:** An attacker could potentially manipulate or corrupt data within the Ads Data Hub environment by running queries with modified customer ID configurations.
    - **Compliance Violation:** Accessing and manipulating data of unauthorized customers can lead to serious compliance violations and legal repercussions.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - None. The application currently reads and uses the `customer_ids` and `ads_data_from` values from the `config.yml` file without any validation or authorization checks.

* Missing Mitigations:
    - Input Validation: Implement validation for `customer_ids` and `ads_data_from` in `config.py` to ensure they conform to expected formats (e.g., numeric values) and potentially check against an allowed list or authorized customer IDs.
    - Authorization Checks:  Ideally, the application should incorporate an authorization mechanism to verify that the user or service account running the deployment has the necessary permissions to access and process data for the specified `customer_ids` and `ads_data_from`. This could involve integrating with an identity and access management (IAM) system.
    - Principle of Least Privilege: Recommend and document that users should grant the service account running the deployment manager only the minimum necessary permissions in Google Ads Data Hub and related Google Cloud projects.
    - Configuration File Protection:  Document and emphasize the importance of securing the `config.yml` file and restricting write access to authorized personnel only.

* Preconditions:
    - An attacker must gain write access to the `config.yml` file.
    - The attacker needs to have some level of access to the Google Cloud project and ADH API to execute the `adm` tool and trigger API calls.
    - The targeted Ads Data Hub environment must not have overly restrictive access controls that would prevent the attacker's actions even with modified configurations.

* Source Code Analysis:
    1. **`adh_deployment_manager/config.py`:**
        - The `Config` class in `config.py` reads the `config.yml` file and directly accesses the `customer_id` and `ads_data_from` values from the loaded YAML data without any validation.
    2. **`adh_deployment_manager/deployment.py`:**
        - The `Deployment` class initializes the `Config` object, making the potentially attacker-modified `customer_ids` and `ads_data_from` accessible throughout the application.
    3. **`adh_deployment_manager/query.py`:**
        - The `AnalysisQuery` class uses the `customer_id` and `ads_data_from` values (originating from `config.yml`) when making API calls to ADH.

    - **Visualization:**

    ```mermaid
    graph LR
        subgraph Configuration Loading
            ConfigYML[/config.yml/] --> ConfigClass(Config Class in config.py)
            ConfigClass -- Reads customer_ids, ads_data_from --> DeploymentClass(Deployment Class in deployment.py)
        end

        subgraph Query Execution
            DeploymentClass -- Passes customer_ids, ads_data_from --> AnalysisQueryClass(AnalysisQuery Class in query.py)
            AnalysisQueryClass -- Uses customer_ids, ads_data_from in API calls --> ADH_API[(Ads Data Hub API)]
        end

        style ConfigYML fill:#f9f,stroke:#333,stroke-width:2px
        style ADH_API fill:#ccf,stroke:#333,stroke-width:2px
        LinkStyle 0,1,2,3,4,5 stroke:#f66,stroke-width:2px,color:#f00;
    ```

* Security Test Case:
    1. **Pre-requisites:**
        - Set up a test environment with the ADH Deployment Manager library installed and configured to connect to a test Ads Data Hub environment.
        - Have access to two distinct ADH customer IDs: `CUSTOMER_ID_A` (authorized) and `CUSTOMER_ID_B` (unauthorized).
        - Create a simple SQL query (e.g., `SELECT 1;`) named `test_query.sql` in the `sql` folder.
        - Create a `config.yml` file that initially includes `CUSTOMER_ID_A` in the `customer_ids` list and is configured to deploy and run `test_query.sql`.
    2. **Initial Deployment and Run (Baseline):**
        - Run `adm deploy -c config.yml -q sql deploy` and then `adm run -c config.yml run`.
        - Verify that the query runs successfully for `CUSTOMER_ID_A` and the output is as expected in the designated BigQuery dataset.
    3. **Modify `config.yml` to Unauthorized Customer ID:**
        - Edit the `config.yml` file.
        - Replace `CUSTOMER_ID_A` in the `customer_ids` list with `CUSTOMER_ID_B`.
        - Save the modified `config.yml`.
    4. **Attempt to Deploy and Run with Modified Config:**
        - Run `adm deploy -c config.yml -q sql deploy` and then `adm run -c config.yml run` again, using the *modified* `config.yml`.
    5. **Verification:**
        - **Successful Exploitation:** If the commands execute successfully *without any errors related to authorization for `CUSTOMER_ID_B`*, and if you can observe actions being performed in ADH context of `CUSTOMER_ID_B`, then the vulnerability is confirmed.

---

* Vulnerability Name: Hardcoded Developer Key in Sample Configuration
* Description: The sample configuration file (`/code/tests/sample_config.yml`) contains a hardcoded developer key (`developer_key: A`). If a user were to use this sample configuration directly or if it were inadvertently exposed, the hardcoded developer key could be compromised, potentially leading to unauthorized access to the Ads Data Hub API.
* Impact: Exposure of a developer key, potentially leading to unauthorized access to the Ads Data Hub API.
* Vulnerability Rank: Medium
* Currently Implemented Mitigations: None.
* Missing Mitigations:
    *   Remove the hardcoded developer key from the sample configuration file.
    *   Add a warning comment in the sample configuration file.
    *   Advise against hardcoding developer keys in documentation.
* Preconditions:
    *   User uses the sample configuration file directly.
    *   Sample configuration file is accidentally exposed.
* Source Code Analysis:
    1.  Inspect `/code/tests/sample_config.yml` and observe `developer_key: A`.
* Security Test Case:
    1.  **Manual Inspection:** Open `/code/tests/sample_config.yml` and verify `developer_key: A`.
    2.  **Conclude Vulnerability:** Hardcoded developer key in sample configuration.

---

* Vulnerability Name: Service Account Key File Path Exposure via Configuration File
* Description: Users might store the path to their sensitive service account key file within the `config.yml` file or similar configuration files. If these configuration files are not properly secured, the path to the service account key file could be exposed to unauthorized parties, potentially leading to unauthorized access to the Ads Data Hub API.
* Impact: Exposure of the service account key file path, potentially leading to unauthorized access to the Ads Data Hub API.
* Vulnerability Rank: Medium
* Currently Implemented Mitigations: `adm.py` script reads secret file path from environment variable.
* Missing Mitigations:
    *   Strongly discourage storing paths to sensitive credential files in configuration files.
    *   Advise users to manage service account key files and OAuth 2.0 credentials securely in documentation.
    *   Recommend using environment variables or secure secret management solutions.
    *   Add a security warning to the documentation.
* Preconditions:
    *   User stores service account key file path in `config.yml`.
    *   Configuration file is exposed to an attacker.
* Source Code Analysis:
    1.  Examine `/code/cli/adm.py`: Script uses `os.environ['ADH_SECRET_FILE']`.
    2.  Review `README.md`: Documentation emphasizes `config.yml` usage.
    3.  Infer User Behavior: Users might extend `config.yml` to store secret file path.
    4.  Identify Risk: Exposure of secret file path if `config.yml` is exposed.
* Security Test Case:
    1.  **Code Review `adm.py`:** Confirm script retrieves credential file path from `ADH_SECRET_FILE`.
    2.  **Documentation Review `README.md`:** Note emphasis on `config.yml` for configuration.
    3.  **Scenario Creation (Hypothetical User Error):** Imagine user adding `adh_secret_file_path` to `config.yml`.
    4.  **Simulate Exposure:** Assume `config.yml` is committed to a public repository.
    5.  **Conclude Vulnerability:** Potential exposure of service account key file path due to user misconfiguration and documentation practices.