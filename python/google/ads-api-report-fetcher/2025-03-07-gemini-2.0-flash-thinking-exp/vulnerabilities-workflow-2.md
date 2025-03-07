## Vulnerability Report

The following vulnerabilities were identified in the application.

### 1. GAQL Injection via Macros/Templates
- **Vulnerability Name:** GAQL Injection via Macros/Templates
- **Description:**
  1. An attacker crafts a malicious payload designed for GAQL injection. This payload could be a string containing malicious GAQL clauses or functions.
  2. The attacker injects this malicious payload into a macro or template parameter when running `gaarf`. This could be achieved through command-line arguments like `--macro.<macro_name>=<payload>` or `--template.<template_name>=<payload>`, or by modifying configuration files (`.gaarfrc`, `gaarf.yaml`, `google-ads.yaml`) if those are under attacker's control in some scenarios (less likely for external attacker but possible in compromised environments).
  3. When `gaarf` processes the query, it substitutes the macro or template placeholders with the attacker-controlled payload *without sufficient sanitization*.
  4. The resulting string, now containing the injected GAQL code, is used as a query against the Google Ads API.
  5. The Google Ads API executes the crafted GAQL query, potentially allowing the attacker to bypass intended restrictions and access sensitive data beyond the scope of the original report. For example, the attacker could modify the `WHERE` clause to broaden the data selection or add `SELECT` fields to extract additional sensitive information.
- **Impact:**
  An attacker can successfully perform a GAQL injection attack, gaining unauthorized access to sensitive Google Ads data. This could include:
  1. **Data Breach:** Extraction of confidential marketing data, customer information, or competitive insights.
  2. **Reputation Damage:** Leakage of sensitive data can severely damage the reputation and trust of the organization using `gaarf`.
  3. **Financial Loss:**  Unauthorized access to advertising performance data or budget information could lead to financial misinterpretations or manipulations.
  4. **Compliance Violations:** Data breaches can lead to violations of data privacy regulations (e.g., GDPR, CCPA) and associated penalties.
- **Vulnerability rank:** High
- **Currently implemented mitigations:**
  No explicit mitigations are mentioned in the provided project files. The tool's design relies on string substitution for macros and templates, which, without sanitization, inherently leads to this vulnerability.
- **Missing mitigations:**
  1. **Input Sanitization:** Implement robust sanitization and validation of all user-provided inputs used in macros and templates. This should involve escaping or removing potentially harmful GAQL syntax from user-supplied values.
  2. **Parameterized Queries:**  Ideally, the macro and template functionality should be redesigned to use parameterized queries instead of string substitution. Parameterized queries prevent injection attacks by separating the query structure from user-supplied data, ensuring that user input is treated as data, not executable code. However, GAQL might not fully support parameterization in the same way as SQL. Explore if the Google Ads API offers any safer mechanisms for dynamic query construction.
  3. **Principle of Least Privilege:** Ensure that the Google Ads API credentials used by `gaarf` have the minimum necessary permissions. Restrict API access to only the data and operations genuinely required for report fetching. This limits the potential damage even if a GAQL injection is successful.
  4. **Documentation and Warnings:** Clearly document the risks of GAQL injection, especially when using macros and templates with external or untrusted input sources. Warn users about the importance of carefully constructing queries and sanitizing inputs.
- **Preconditions:**
  1. The attacker must have the ability to influence the input parameters of `gaarf`, specifically macro or template values. This is typically possible through command-line arguments or configuration files.
  2. The `gaarf` tool must be configured to use macros or templates in its queries.
  3. The Google Ads account being queried must contain sensitive data that the attacker is interested in accessing.
- **Source code analysis:**
  (Due to the absence of provided source code, a precise line-by-line analysis is not possible. However, based on the documentation and feature description, we can infer the vulnerable points.)

  1. **Query Parsing and Substitution:** The `gaarf` tool likely has a module responsible for parsing query files (e.g., SQL files) and identifying macro and template placeholders (e.g., `{macro_name}`, `{% template_logic %}`).
  2. **Macro and Template Processing:**  The tool then processes macros and templates. For macros, this probably involves simple string replacement of placeholders with values provided via command-line arguments or config files. For templates (Jinja/Nunjucks), the template engine likely renders the query string based on provided template parameters.
  3. **Lack of Sanitization:** The vulnerability arises if the code *directly substitutes* user-provided macro or template values into the GAQL query string *without any sanitization or validation*. This means if a user provides a malicious string as a macro value, that string is inserted verbatim into the GAQL query.
  4. **GAQL Execution:** Finally, `gaarf` uses the constructed GAQL query and the Google Ads API client to fetch the report. Because the malicious payload is now part of the GAQL query, the Google Ads API executes it as intended, leading to the injection vulnerability.

  **Visualization (Conceptual):**

  ```
  User Input (Malicious Payload) --> Macro/Template Parameter --> Gaarf Tool (String Substitution - No Sanitization) --> Crafted GAQL Query (Malicious Code Injected) --> Google Ads API --> Data Breach
  ```

- **Security test case:**
  1. **Setup:** Assume you have a running instance of `gaarf` (Python or Node.js version) and access to a Google Ads account for testing. Prepare a simple GAQL query file (e.g., `test_query.sql`) that uses a macro, for example:

     ```sql
     SELECT
         campaign.name
     FROM campaign
     WHERE campaign.status = "{campaign_status}"
     LIMIT 10
     ```

  2. **Normal Execution (Baseline):** Run `gaarf` with a normal macro value to establish a baseline and ensure the tool works as expected. For example:

     ```bash
     gaarf test_query.sql --account=<YOUR_ADS_ACCOUNT_ID> --output=console --macro.campaign_status=ENABLED
     ```
     Verify that the command executes successfully and returns campaign names for enabled campaigns.

  3. **Injection Attempt - Modifying WHERE Clause:**  Craft a malicious payload to inject additional conditions into the `WHERE` clause, attempting to bypass the intended filter and extract more data. For example, try to inject `OR customer.id != <YOUR_ADS_ACCOUNT_ID>` to potentially access data outside your account (if possible in your test environment and permissions):

     ```bash
     gaarf test_query.sql --account=<YOUR_ADS_ACCOUNT_ID> --output=console --macro.campaign_status='ENABLED" OR customer.id != <YOUR_ADS_ACCOUNT_ID> OR campaign.status = "'
     ```
     *Note:* The payload is designed to close the existing `WHERE` clause condition (`campaign.status = "ENABLED"`) by adding a quote (`"`) and then inject `OR customer.id != <YOUR_ADS_ACCOUNT_ID> OR campaign.status = "`. This is a simplified example; more sophisticated payloads might be needed depending on the parsing logic.*

  4. **Analyze Results:**
     - **Vulnerable:** If the command executes *without errors* and returns data that *should not* be accessible based on the original query (e.g., data from a different `customer.id` if that's possible in your testing context, or campaigns with statuses other than `ENABLED` due to bypassed filtering), then the GAQL injection is successful.
     - **Not Vulnerable (Mitigated):** If the command fails with a GAQL error, or if it executes but only returns data consistent with the *intended* query (campaigns with `ENABLED` status from *your* account), then the tool might have some implicit or explicit sanitization, or the injection attempt was not effective. However, further testing with different payloads would be needed to confirm robust mitigation.

  5. **Further Test Cases:** Explore other injection payloads to test different injection points and potential impacts:
     - Injecting `SELECT` fields to extract sensitive columns not originally in the query.
     - Injecting malicious functions or operators (if GAQL supports them and if the tool's macro substitution occurs at a vulnerable point).
     - Testing different output formats and writers to see if the vulnerability behavior changes.

  **Expected Outcome of Successful Test Case:**
  The security test case should demonstrate that by manipulating macro or template inputs, an attacker can alter the generated GAQL query and potentially extract data beyond the intended scope, proving the existence of a GAQL injection vulnerability.

### 2. Configuration File Injection leading to Data Redirection
- **Vulnerability Name:** Configuration File Injection leading to Data Redirection
- **Description:**
  - An attacker can craft a malicious `google-ads.yaml` configuration file designed to redirect Google Ads reports to an attacker-controlled destination.
  - The attacker then needs to convince a user to utilize this malicious configuration file when running the `gaarf` tool. This could be achieved through social engineering, phishing, or by compromising a system where the user might execute `gaarf`.
  - When the user executes `gaarf` and points it to the malicious `google-ads.yaml` file (either by placing it in a default search location or explicitly specifying it using the `--ads-config` option), the tool parses this file to obtain configuration parameters.
  - The attacker's malicious `google-ads.yaml` is crafted to modify output configurations, such as the BigQuery dataset (`bq.dataset`), Google Sheet URL (`sheet.spreadsheet-url`), or CSV output path (`csv.output-path`), to point to locations controlled by the attacker.
  - Consequently, when `gaarf` fetches reports from the Google Ads API, instead of saving them to the user's intended and secure destination, the reports are redirected to the attacker-specified location, granting the attacker unauthorized access to sensitive Google Ads data.
- **Impact:**
  - **Step 1:** An attacker prepares a malicious `google-ads.yaml` file. This file contains legitimate Google Ads API credentials to avoid immediate errors, but modifies the output settings. For example, in a BigQuery output scenario, the `bq.dataset` parameter is changed to point to a dataset controlled by the attacker.
  - **Step 2:** The attacker distributes this malicious `google-ads.yaml` file to potential victims, perhaps through a phishing email or by hosting it on a website and instructing users to download and use it with `gaarf`.
  - **Step 3:** A user, unknowingly using the malicious configuration, executes `gaarf` to fetch Google Ads reports. They might use a command like `gaarf <queries> --ads-config=/path/to/malicious/google-ads.yaml --account=<user_account_id> --output=bq`.
  - **Step 4:** `gaarf` reads the configuration from the provided `google-ads.yaml` file, which includes the attacker's BigQuery dataset information.
  - **Step 5:** `gaarf` successfully fetches the Google Ads reports using the user's credentials (correctly configured or unintentionally leaked in the malicious config).
  - **Step 6:** Instead of writing the reports to the user's intended BigQuery dataset, `gaarf` writes the reports to the attacker-controlled BigQuery dataset as specified in the malicious configuration.
  - **Step 7:** The attacker gains unauthorized access to the user's Google Ads reports, which may contain sensitive business data, campaign performance metrics, and customer information. The user remains unaware of the data redirection unless they meticulously verify the output destination.
- **Vulnerability Rank:** High
- **Currently implemented mitigations:**
  - None. The current project does not implement any specific mitigations against malicious configuration files. The documentation lacks warnings about using configuration files from untrusted sources or best practices for secure configuration management.
- **Missing mitigations:**
  - **Input Validation and Sanitization:** Implement strict validation for configuration parameters, especially for output paths (e.g., `csv.output-path`, `json.output-path`) and URLs (e.g., `sheet.spreadsheet-url`). Sanitize these paths to prevent path traversal attacks or redirection to unintended external locations. For BigQuery and other cloud outputs, validate the project and dataset against an expected or user-confirmed list.
  - **Secure Configuration Loading Practices:** Restrict the locations from which `gaarf` automatically loads configuration files. Avoid default loading from the current directory, or implement a warning mechanism when a configuration file is loaded from a non-standard or potentially untrusted location. Consider recommending or enforcing loading configuration from a secure, user-defined location only.
  - **User Warnings and Documentation:** Add clear warnings in the documentation and potentially in the CLI output about the risks of using `google-ads.yaml` files from untrusted sources. Advise users to only use configuration files they have created and to verify the contents of any `google-ads.yaml` file before using it with `gaarf`.
  - **Principle of Least Privilege:**  Document and emphasize the principle of least privilege regarding the permissions granted to the Google Ads API credentials used in the `google-ads.yaml` file. Users should be advised to grant only the necessary permissions to the API credentials to limit the potential damage if the configuration file is compromised.
- **Preconditions:**
  - The user must have downloaded and installed the `gaarf` tool.
  - The attacker must successfully trick the user into using a malicious `google-ads.yaml` file. This could involve social engineering, phishing attacks, or compromising a system where the user might execute `gaarf`.
  - The user must execute `gaarf` with the malicious configuration file, either by placing it in a default location where `gaarf` searches or by explicitly specifying its path using the `--ads-config` option.
- **Source code analysis:**
  - **Configuration Loading:** The `gaarf` tool, in both Python and Node.js versions, is designed to load its configuration from a `google-ads.yaml` file. The code likely uses YAML parsing libraries (like `PyYAML` in Python or `js-yaml` in Node.js) to read and process this file.  The tool searches for `google-ads.yaml` in default locations (like the current working directory) and allows users to specify a custom path using the `--ads-config` command-line argument.
  - **Parameter Extraction:** After loading the YAML file, the tool extracts various configuration parameters, including Google Ads API credentials (developer token, client ID, client secret, refresh token) and output configurations (BigQuery dataset, CSV output path, Google Sheet URL, etc.).
  - **Vulnerable Code Points:** The vulnerability arises because the tool directly uses the output configurations from the `google-ads.yaml` file without sufficient validation or sanitization. Specifically:
    - **Output Paths and URLs:**  The code does not validate or sanitize the `csv.output-path`, `json.output-path`, and `sheet.spreadsheet-url` parameters. This allows an attacker to insert arbitrary paths or URLs into the configuration file.
    - **BigQuery Dataset:** While BigQuery datasets are project-scoped, the `bq.dataset` and `bq.project` parameters are also read directly from the configuration file without validation against expected or user-confirmed values.
  - **Absence of Security Checks:** There is no evidence in the provided files (and based on common patterns for similar tools) that `gaarf` implements any checks to validate the integrity or source of the `google-ads.yaml` file. The tool trusts the configuration file at face value and proceeds to use the parameters it contains.
  - **Conceptual Code Flow:**
    ```
    # Pseudocode - Conceptual representation of vulnerable code flow
    config = load_config_from_yaml(config_path) # Loads google-ads.yaml using YAML parser
    output_type = config.get("output")
    output_destination = config.get(output_type) # e.g., config.get("bq") for BigQuery output

    if output_type == "bq":
        bq_dataset = output_destination.get("dataset") # Attacker controlled value
        bq_project = output_destination.get("project") # Attacker controlled value
        # ... No validation of bq_dataset or bq_project ...
        bq_writer = BigQueryWriter(project=bq_project, dataset=bq_dataset, ...)
        gaarf.execute_and_write(writer=bq_writer, ...)

    elif output_type == "csv":
        csv_output_path = output_destination.get("output-path") # Attacker controlled value
        # ... No validation of csv_output_path ...
        csv_writer = CsvWriter(destination_folder=csv_output_path, ...)
        gaarf.execute_and_write(writer=csv_writer, ...)

    # ... similar flow for other output types (json, sheet, etc.) ...
    ```

- **Security test case:**
  - **Step 1: Prepare Attacker Resources:**
    - Set up a Google Cloud project and create a BigQuery dataset controlled by the attacker (e.g., `attacker-project:attacker_dataset`).
  - **Step 2: Create Malicious `google-ads.yaml`:**
    - Create a file named `malicious-google-ads.yaml` with the following content (adjust with valid but non-sensitive Google Ads API credentials if necessary for testing, otherwise placeholder values can be used, as the vulnerability is about data redirection not credential theft in this scenario):
      ```yaml
      developer_token: YOUR_DEVELOPER_TOKEN # Or a placeholder value
      client_id: YOUR_CLIENT_ID # Or a placeholder value
      client_secret: YOUR_CLIENT_SECRET # Or a placeholder value
      refresh_token: YOUR_REFRESH_TOKEN # Or a placeholder value
      login_customer_id: YOUR_LOGIN_CUSTOMER_ID # Or a placeholder value
      output: bq
      bq:
        project: attacker-project  # Attacker's Google Cloud Project ID
        dataset: attacker_dataset  # Attacker's BigQuery Dataset ID
        location: US
      ```
  - **Step 3: Prepare a Test Query:**
    - Create a simple GAQL query file (e.g., `test_query.sql`) for testing purposes:
      ```sql
      SELECT campaign.id FROM campaign LIMIT 1
      ```
  - **Step 4: Execute `gaarf` with Malicious Configuration:**
    - Run the `gaarf` tool, specifying the malicious configuration file and a valid Google Ads account to fetch data from:
      ```bash
      gaarf test_query.sql --ads-config=malicious-google-ads.yaml --account=YOUR_GOOGLE_ADS_ACCOUNT --output=bq
      ```
      *(Replace `YOUR_GOOGLE_ADS_ACCOUNT` with a valid Google Ads Customer ID)*
  - **Step 5: Verify Data Redirection:**
    - **Attacker Side:** Check the attacker-controlled BigQuery dataset (`attacker-project:attacker_dataset`). Verify that a new table (named based on `test_query.sql`) has been created and contains the Google Ads report data.
    - **User Side:** Check the user's intended BigQuery dataset (if any was implicitly or explicitly intended). Verify that the report data is **not** present in the user's intended location.
  - **Step 6: Expected Result:**
    - The test should successfully demonstrate that the Google Ads report data is written to the attacker-controlled BigQuery dataset, proving the data redirection vulnerability. The user is misled into sending their data to an unintended destination due to the malicious configuration file.

### 3. GAQL Injection via `customer-ids-query` and `customer-ids-query-file` Options
- **Vulnerability Name:** GAQL Injection via `customer-ids-query` and `customer-ids-query-file` Options
- **Description:**
    1. An attacker crafts a malicious GAQL query designed to extract sensitive data or manipulate data access beyond their authorized scope.
    2. The attacker uses the `--customer-ids-query` or `--customer-ids-query-file` options of `gaarf` to supply this malicious GAQL query. These options are intended to filter customer IDs but can be abused if not properly validated.
    3. `gaarf` executes the attacker-provided GAQL query against the Google Ads API.
    4. If the application fails to properly sanitize or validate the input GAQL query, the attacker's malicious query is executed verbatim.
    5. The attacker potentially gains access to sensitive data from multiple accounts or performs unauthorized actions, depending on the crafted query.
- **Impact:**
    - High: Unauthorized access to sensitive Google Ads data across multiple accounts managed by the MCC account. Data exfiltration, potential data manipulation depending on the API capabilities exposed and the crafted query.
- **Vulnerability Rank:** High
- **Currently implemented mitigations:**
    - None: Based on the provided project files, there is no explicit input validation or sanitization mentioned for the `--customer-ids-query` and `--customer-ids-query-file` options. The documentation describes the intended usage but doesn't mention security considerations for malicious queries.
- **Missing mitigations:**
    - Input validation and sanitization for GAQL queries provided via `--customer-ids-query` and `--customer-ids-query-file` options. Implement parsing and validation of the provided GAQL query to ensure it only selects `customer.id` and includes necessary `WHERE` clauses for filtering, preventing arbitrary GAQL execution.
    - Principle of least privilege: Limit the permissions of the service account used by `gaarf` to the bare minimum required for its intended functionality. This can reduce the impact of a successful GAQL injection attack.
- **Preconditions:**
    - The attacker needs to be able to run the `gaarf` tool with access to the command-line interface and the ability to specify command-line arguments, including `--customer-ids-query` or `--customer-ids-query-file`.
    - The attacker needs to know or guess a valid MCC account ID to use with the `--account` option.
- **Source code analysis:**
    1. **File: /code/README.md**: The documentation describes the `--customer-ids-query` and `--customer-ids-query-file` options, explaining their intended functionality to filter accounts. It lacks any security warnings or input validation details.
    2. **File: /code/gcp/README.md**: The documentation for Cloud Workflow parameters also mentions `customer_ids_query` as a parameter for the workflow, indicating that this parameter is passed down to the `gaarf` tool running in the cloud function.
    3. **File: /code/gcp/workflow/workflow.yaml & workflow-ads.yaml**: These workflow definitions show how the `customer_ids_query` parameter is passed to the `gaarf` cloud function.
    4. **File: /code/gcp/functions/gaarf/main.js**:  *(Assuming similar logic in Python version)* The cloud function likely takes the `customer_ids_query` as input and passes it to the core `gaarf` library for execution without validation, as no validation logic is apparent in the provided documentation or setup scripts.
    5. **File: /code/js/README.md & py/README.md**:  These README files describe the command-line options, including `--customer-ids-query` and `--customer-ids-query-file`, again without mentioning any input validation or security considerations.

    **Visualization:**

    ```
    User Input (Malicious GAQL Query via --customer-ids-query/file) --> gaarf CLI --> gaarf Core Library --> Google Ads API (Executes Malicious Query) --> Sensitive Data Leak
    ```

- **Security test case:**
    1. **Setup:** Have a running instance of `gaarf` (either Node.js or Python version). Ensure you have Google Ads API credentials configured for a test MCC account.
    2. **Craft Malicious Query (malicious_query.sql):** Create a file `malicious_query.sql` with the following content:
        ```sql
        SELECT
            customer.id,
            customer.descriptive_name,
            customer.currency_code,
            customer.time_zone
        FROM customer
        LIMIT 10
        ```
        This query attempts to extract customer details beyond just IDs.
    3. **Execute gaarf with malicious query file:** Run `gaarf` command, providing a regular ads query file (e.g., a simple campaign query) and the malicious customer IDs query file:
        ```bash
        gaarf examples/campaign_query.sql --account=YOUR_MCC_ID --output=console --customer-ids-query-file=malicious_query.sql
        ```
        Replace `YOUR_MCC_ID` with a valid MCC account ID and `examples/campaign_query.sql` with a valid, simple query file for gaarf to process.
    4. **Observe Output:** Examine the console output. If the vulnerability exists, you will see output containing not only customer IDs but also `customer.descriptive_name`, `customer.currency_code`, and `customer.time_zone` for multiple accounts, demonstrating unauthorized data access.
    5. **Expected Result (Vulnerable):** The output will include sensitive customer data (descriptive name, currency, timezone) beyond just customer IDs, confirming GAQL injection.
    6. **Expected Result (Mitigated):** If mitigations are in place, `gaarf` should either reject the malicious query with an error (due to validation) or only return customer IDs, ignoring the extra fields in the malicious query.